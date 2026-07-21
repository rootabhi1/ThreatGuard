"""ThreatGuard — FastAPI app with RBAC.

Architecture (POC):
  - SQLite via db/__init__.py
  - JWT access tokens + opaque refresh tokens (auth/auth.py)
  - Role-based permission checks via @require_permission decorators
  - Resource-access checks via ensure_can_access_threat_model
  - Hierarchy: Release → Feature → ThreatModel → Threats (with per-threat status)

Run locally:
  export INITIAL_ADMIN_EMAIL=admin@example.com
  export INITIAL_ADMIN_PASSWORD=changeme123
  export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
  python app.py
  # Open http://127.0.0.1:8000
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File, Form
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

import json
import secrets as _secrets
import logging as _logging
import uuid as _uuid
from contextvars import ContextVar as _ContextVar
from datetime import timedelta as _td
from starlette.middleware.base import BaseHTTPMiddleware

# Initialize DB before anything else imports from it
from db import init_db, db_conn, audit
init_db()

from db import domain
from auth import (
    register_user, login as auth_login, get_user_by_id, list_users,
    update_user_role, deactivate_user,
    consume_refresh_token, create_access_token, revoke_all_refresh_tokens,
    get_current_user, require_permission, require_role,
    ensure_can_access_threat_model, can_access_feature, get_role_permissions,
)
from db import settings as app_settings
from threat_engine import analyze_system, METHODOLOGIES, render_dfd_svg, auto_layout_for_frontend
from threat_engine.llm import llm_available as _llm_available, provider as _llm_provider
from threat_engine.report import to_markdown, to_pdf
from threat_engine.html_report import to_html



# ===========================================================================
# Security middleware — headers, rate limiting, request ID, JSON logging
# ===========================================================================
_request_id_var: _ContextVar[str] = _ContextVar("request_id", default="")

class _JsonFormatter(_logging.Formatter):
    def format(self, record):
        import time as _t
        return json.dumps({"ts": _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime()),
                           "level": record.levelname, "msg": record.getMessage(),
                           "request_id": _request_id_var.get("")})

_handler = _logging.StreamHandler()
_handler.setFormatter(_JsonFormatter())
_logging.basicConfig(handlers=[_handler], level=_logging.INFO, force=True)
logger = _logging.getLogger("atm")

_rate_store: dict = {}
def _rate_limit(key: str, limit: int, window: int) -> bool:
    if os.getenv("RATE_LIMIT_ENABLED", "1").lower() in ("0", "false", "no", "off"):
        return True
    import time as _t2; now = _t2.time()
    _rate_store[key] = [t for t in _rate_store.get(key, []) if now - t < window]
    if len(_rate_store[key]) >= limit: return False
    _rate_store[key].append(now); return True

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    LIMITS = {"/api/auth/login": (10, 60), "/api/auth/register": (5, 60)}
    async def dispatch(self, request, call_next):
        path = request.url.path
        if path in self.LIMITS:
            limit, window = self.LIMITS[path]
            ip = request.client.host if request.client else "unknown"
            if not _rate_limit(f"rl:{path}:{ip}", limit, window):
                return Response(content='{"detail":"Too many requests"}', status_code=429, media_type="application/json")
        return await call_next(request)

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        import time as _t3
        rid = request.headers.get("X-Request-ID", _uuid.uuid4().hex[:8])
        _request_id_var.set(rid)
        t0 = _t3.monotonic()
        response = await call_next(request)
        ms = int((_t3.monotonic() - t0) * 1000)
        logger.info(f"{request.method} {request.url.path} → {response.status_code} ({ms}ms)")
        response.headers["X-Request-ID"] = rid
        return response

app = FastAPI(title="ThreatGuard", version="2.1")

app.add_middleware(RequestIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
# CORS: browsers reject (and it is unsafe to send) wildcard origins together
# with credentials. Only enable credentials when explicit origins are configured;
# a bare "*" default falls back to no-credentials, which is the safe public-API mode.
# Auth uses Bearer tokens in the Authorization header, so credentialed CORS is
# not required for normal operation.
_cors_env = os.getenv("CORS_ORIGINS", "*").strip()
if _cors_env and _cors_env != "*":
    _cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
    _cors_allow_credentials = True
else:
    _cors_origins = ["*"]
    _cors_allow_credentials = False
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=_cors_allow_credentials,
)

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# ===========================================================================
# AUTH ENDPOINTS — public
# ===========================================================================
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.post("/api/auth/register")
async def auth_register(req: RegisterRequest, request: Request):
    """Self-registration creates a User-role account — except on a brand-new
    deployment with no admin yet, where the very first registrant becomes the
    admin so the instance is never a dead end (no INITIAL_ADMIN env required).
    After that, only an admin can create Management/Admin accounts."""
    first_admin = not any(usr.get("role") == "admin" for usr in list_users())
    try:
        u = register_user(req.email, req.password, req.full_name,
                          role="admin" if first_admin else "user")
    except ValueError as e:
        raise HTTPException(400, str(e))
    access, refresh, _ = auth_login(
        req.email, req.password,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", ""),
    )
    return {
        "user": u,
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "permissions": list(get_role_permissions(u["role"])),
    }


@app.post("/api/auth/login")
async def auth_login_endpoint(req: LoginRequest, request: Request):
    try:
        access, refresh, user = auth_login(
            req.email, req.password,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", ""),
        )
    except ValueError as e:
        raise HTTPException(401, str(e))
    return {
        "user": user,
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "permissions": list(get_role_permissions(user["role"])),
    }


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/api/auth/refresh")
async def auth_refresh(req: RefreshRequest):
    uid = consume_refresh_token(req.refresh_token)
    if not uid:
        raise HTTPException(401, "Invalid or expired refresh token")
    user = get_user_by_id(uid)
    if not user or not user["is_active"]:
        raise HTTPException(401, "User unavailable")
    new_access = create_access_token(uid, user["email"], user["role"])
    from auth.auth import create_refresh_token
    new_refresh = create_refresh_token(uid)
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
    }


@app.post("/api/auth/logout")
async def auth_logout(user: dict = Depends(get_current_user)):
    revoke_all_refresh_tokens(user["id"])
    audit(user["id"], user["email"], "user.logout", "grant",
          ip_address=user.get("_ip"), user_agent=user.get("_user_agent"))
    return {"ok": True}


@app.get("/api/auth/me")
async def auth_me(user: dict = Depends(get_current_user)):
    return {
        "user": {k: v for k, v in user.items() if not k.startswith("_")},
        "permissions": list(get_role_permissions(user["role"])),
    }


# ===========================================================================
# USER MANAGEMENT — admin only
# ===========================================================================
class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str
    role: str = Field(pattern="^(user|management|admin)$")
    feature_ids: list[int] = []


@app.post("/api/users")
async def admin_create_user(
    req: CreateUserRequest,
    actor: dict = Depends(require_permission("user.create")),
):
    try:
        u = register_user(req.email, req.password, req.full_name, role=req.role)
    except ValueError as e:
        raise HTTPException(400, str(e))
    for fid in req.feature_ids:
        domain.grant_feature_access(u["id"], fid, granted_by=actor["id"])
    audit(actor["id"], actor["email"], "user.create", "grant", "user", u["id"],
          ip_address=actor.get("_ip"),
          detail=f"role={req.role} feature_ids={req.feature_ids}")
    return u


@app.get("/api/users")
async def admin_list_users(actor: dict = Depends(require_permission("user.read.all"))):
    return list_users()


class UpdateUserRoleRequest(BaseModel):
    role: str = Field(pattern="^(user|management|admin)$")


@app.put("/api/users/{uid}/role")
async def admin_update_user_role(
    uid: int,
    req: UpdateUserRoleRequest,
    actor: dict = Depends(require_permission("user.update.all")),
):
    if uid == actor["id"]:
        raise HTTPException(400, "Cannot change your own role")
    if not get_user_by_id(uid):
        raise HTTPException(404, "User not found")
    try:
        update_user_role(uid, req.role, by_user_id=actor["id"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    return get_user_by_id(uid)


@app.delete("/api/users/{uid}")
async def admin_deactivate_user(
    uid: int,
    actor: dict = Depends(require_permission("user.delete.all")),
):
    if uid == actor["id"]:
        raise HTTPException(400, "Cannot deactivate yourself")
    if not get_user_by_id(uid):
        raise HTTPException(404, "User not found")
    deactivate_user(uid, by_user_id=actor["id"])
    return {"ok": True, "deactivated": uid}


class GrantFeatureAccessRequest(BaseModel):
    feature_ids: list[int]


@app.put("/api/users/{uid}/feature-access")
async def admin_set_user_feature_access(
    uid: int,
    req: GrantFeatureAccessRequest,
    actor: dict = Depends(require_permission("user.feature_access.grant")),
):
    if not get_user_by_id(uid):
        raise HTTPException(404, "User not found")
    current = {f["id"] for f in domain.list_user_feature_access(uid)}
    target = set(req.feature_ids)
    for fid in target - current:
        domain.grant_feature_access(uid, fid, granted_by=actor["id"])
    for fid in current - target:
        domain.revoke_feature_access(uid, fid)
    audit(actor["id"], actor["email"], "user.feature_access.grant", "grant",
          "user", uid, ip_address=actor.get("_ip"),
          detail=f"granted={sorted(target - current)} revoked={sorted(current - target)}")
    return {"feature_ids": sorted(target)}


@app.get("/api/users/{uid}/feature-access")
async def admin_list_user_feature_access(
    uid: int,
    actor: dict = Depends(require_permission("user.read.all")),
):
    return [{"feature_id": f["id"], "feature_name": f["name"]}
            for f in domain.list_user_feature_access(uid)]


# ===========================================================================
# RELEASES (admin manages)
# ===========================================================================
class ReleaseCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    target_date: str | None = None
    status: str = Field(default="planned",
                        pattern="^(planned|in_progress|released|cancelled)$")


@app.post("/api/releases")
async def create_release(
    req: ReleaseCreateRequest,
    actor: dict = Depends(require_permission("release.create")),
):
    return domain.create_release(
        req.name, req.description, req.target_date,
        created_by=actor["id"], status=req.status
    )


@app.get("/api/releases")
async def list_releases(actor: dict = Depends(require_permission("release.read.all"))):
    return domain.list_releases()


@app.put("/api/releases/{rid}")
async def update_release(
    rid: int,
    req: ReleaseCreateRequest,
    actor: dict = Depends(require_permission("release.update.all")),
):
    rel = domain.update_release(rid, **req.model_dump())
    if not rel:
        raise HTTPException(404)
    return rel


@app.delete("/api/releases/{rid}")
async def delete_release(
    rid: int,
    actor: dict = Depends(require_permission("release.delete.all")),
):
    domain.delete_release(rid)
    return {"ok": True}


# ===========================================================================
# FEATURES
# ===========================================================================
class FeatureCreateRequest(BaseModel):
    release_id: int
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    status: str = Field(default="draft",
                        pattern="^(draft|in_review|in_sprint|released|cancelled)$")
    target_date: str | None = None   # ISO YYYY-MM-DD


@app.post("/api/features")
async def create_feature(
    req: FeatureCreateRequest,
    actor: dict = Depends(require_permission("feature.create")),
):
    try:
        return domain.create_feature(
            req.release_id, req.name, req.description,
            created_by=actor["id"], status=req.status,
            target_date=req.target_date,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/features")
async def list_features(
    release_id: int | None = None,
    user: dict = Depends(get_current_user),
):
    """Filter by role:
       - admin/management: see all features
       - user: see ones they created or were granted access to
    """
    return domain.list_features(
        release_id=release_id,
        visible_to_user_id=user["id"],
        visible_to_role=user["role"],
    )


@app.get("/api/features/{fid}")
async def get_feature(fid: int, user: dict = Depends(get_current_user)):
    f = domain.get_feature(fid)
    if not f:
        raise HTTPException(404)
    if not can_access_feature(user, f, "read"):
        audit(user["id"], user["email"], "feature.read", "deny", "feature", fid,
              ip_address=user.get("_ip"))
        raise HTTPException(404)
    return f


@app.put("/api/features/{fid}")
async def update_feature(
    fid: int,
    req: FeatureCreateRequest,
    actor: dict = Depends(require_permission("feature.update.all")),
):
    f = domain.update_feature(fid, **req.model_dump(exclude={"release_id"}))
    if not f:
        raise HTTPException(404)
    return f


@app.delete("/api/features/{fid}")
async def delete_feature(
    fid: int,
    actor: dict = Depends(require_permission("feature.delete.all")),
):
    domain.delete_feature(fid)
    return {"ok": True}


# ===========================================================================
# THREAT MODELS
# ===========================================================================
class ThreatModelCreateRequest(BaseModel):
    feature_id: int
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    system: dict
    methodologies: list[str] = ["stride"]


@app.post("/api/threat-models")
async def create_threat_model(
    req: ThreatModelCreateRequest,
    actor: dict = Depends(require_permission("threat_model.create")),
):
    feature = domain.get_feature(req.feature_id)
    if not feature:
        raise HTTPException(400, "Feature not found")
    if not can_access_feature(actor, feature, "read"):
        raise HTTPException(403, "No access to this feature")
    try:
        return domain.create_threat_model(
            req.feature_id, owner_id=actor["id"],
            name=req.name, description=req.description,
            system=req.system, methodologies=req.methodologies,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/threat-models")
async def list_threat_models(
    feature_id: int | None = None,
    user: dict = Depends(get_current_user),
):
    return domain.list_threat_models(
        visible_to_user_id=user["id"],
        visible_to_role=user["role"],
        feature_id=feature_id,
    )


@app.get("/api/threat-models/{tid}")
async def get_threat_model(tid: int, user: dict = Depends(get_current_user)):
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "read")
    tm["threat_statuses"] = domain.list_threat_statuses(tid)
    return tm


class ThreatModelUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    system: dict | None = None
    methodologies: list[str] | None = None
    feature_id: int | None = None


@app.put("/api/threat-models/{tid}")
async def update_threat_model(
    tid: int,
    req: ThreatModelUpdateRequest,
    user: dict = Depends(get_current_user),
):
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "update")
    fields = {k: v for k, v in req.model_dump().items() if v is not None}
    return domain.update_threat_model(tid, **fields)


@app.delete("/api/threat-models/{tid}")
async def delete_threat_model(tid: int, user: dict = Depends(get_current_user)):
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "delete")
    domain.delete_threat_model(tid)
    return {"ok": True}


class AnalyzeRequest(BaseModel):
    methodologies: list[str] = ["stride"]
    use_llm: bool = False


@app.post("/api/threat-models/{tid}/analyze")
async def analyze_threat_model(
    tid: int,
    req: AnalyzeRequest,
    user: dict = Depends(get_current_user),
):
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "update")
    result = analyze_system(tm["system"], req.methodologies, use_llm=req.use_llm)
    domain.update_threat_model(tid, methodologies=req.methodologies, analysis=result)
    audit(user["id"], user["email"], "threat_model.analyze", "grant",
          "threat_model", tid, ip_address=user.get("_ip"),
          detail=f"methodologies={req.methodologies} findings={result['summary'].get('findings', result['summary']['total'])} standard_checks={result['summary'].get('standard_checks', 0)}")
    return result


class ThreatStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|in_progress|mitigated|accepted_risk|false_positive)$")
    notes: str | None = None


@app.put("/api/threat-models/{tid}/threats/{threat_id}/status")
async def update_threat_status(
    tid: int,
    threat_id: str,
    req: ThreatStatusUpdate,
    user: dict = Depends(get_current_user),
):
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    # Status updates require WRITE access — only owner (user) or admin.
    # Management can READ but not change anything.
    ensure_can_access_threat_model(user, tm, "update")
    return domain.set_threat_status(
        tid, threat_id, req.status, req.notes, updated_by=user["id"]
    )


@app.get("/api/threat-models/{tid}/threats/{threat_id}/history")
async def threat_status_history(
    tid: int,
    threat_id: str,
    user: dict = Depends(get_current_user),
):
    """Full status-change history for a single threat. Read-access only."""
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "read")
    return domain.get_threat_status_history(tid, threat_id)


# ===========================================================================
# REPORTS
# ===========================================================================
@app.get("/api/threat-models/{tid}/report/{fmt}")
async def threat_model_report(
    tid: int,
    fmt: str,
    user: dict = Depends(get_current_user),
):
    if fmt not in ("markdown", "html", "pdf", "csv", "executive"):
        raise HTTPException(400, "Format must be markdown, html, pdf, csv, or executive")
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "read")
    if not tm.get("analysis"):
        raise HTTPException(400, "Run analysis before generating a report")
    analysis = tm["analysis"]
    fname = f"threat_model_{tid}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    if fmt == "executive":
        from threat_engine.executive_report import generate_executive_report
        return Response(generate_executive_report(analysis), media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="executive_{fname}.html"'})
    if fmt == "markdown":
        return Response(to_markdown(analysis), media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.md"'})
    if fmt == "html":
        return Response(to_html(analysis), media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.html"'})
    if fmt == "csv":
        threats = analysis.get("threats", [])
        system_name = (analysis.get("system", {}) or {}).get("name", "System")
        return Response(_risk_register_csv(threats, system_name), media_type="text/csv",
                        headers={"Content-Disposition": _content_disposition(f"risk_register_{system_name.replace(' ', '_')}.csv")})
    return Response(to_pdf(analysis), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.pdf"'})


# Ad-hoc analysis (no DB write) — kept for the canvas UI when not yet saved
class AdhocAnalyzeRequest(BaseModel):
    system: dict
    methodologies: list[str] = ["stride"]
    use_llm: bool = False


@app.post("/api/analyze")
async def analyze_adhoc(
    req: AdhocAnalyzeRequest,
    user: dict = Depends(require_permission("threat_model.create")),
):
    return analyze_system(req.system, req.methodologies, use_llm=req.use_llm)


def _content_disposition(filename: str) -> str:
    """Build an RFC 6266 Content-Disposition value with an ASCII-safe ``filename``
    and a UTF-8 ``filename*`` (RFC 5987), so a system name containing non-latin-1
    characters cannot break the latin-1 HTTP header. The original Unicode name is
    preserved, percent-encoded, in ``filename*``."""
    import unicodedata
    from urllib.parse import quote
    ascii_name = unicodedata.normalize("NFKD", filename).encode("ascii", "ignore").decode("ascii")
    ascii_name = ascii_name.replace('"', "").replace("\\", "").strip() or "risk_register.csv"
    return "attachment; filename=\"{}\"; filename*=UTF-8''{}".format(ascii_name, quote(filename, safe=""))


def _risk_register_csv(threats: list, system_name: str = "System") -> bytes:
    """Build a CSV risk register from a list of threats. Shared by the
    /api/report/csv route and the {fmt}=csv path."""
    import csv as _csv
    import io as _io
    buf = _io.StringIO(); writer = _csv.writer(buf)
    # "Tier" distinguishes grounded findings from generic "standard checks" so the
    # register carries every row but the reader can filter/sort by which are proven.
    writer.writerow(["ID", "Title", "Tier", "Severity", "Methodology", "Component", "Category", "DREAD", "DREAD Tier",
                     "Cross-boundary", "ATT&CK ID", "ATT&CK Tactic", "SOC2", "ISO27001", "PCI-DSS", "Description"])
    # Findings first, then standard checks — a natural risk-register ordering.
    ordered = sorted(threats, key=lambda t: 0 if t.get("tier", "baseline") == "evidenced" else 1)
    for i, t in enumerate(ordered):
        atk = t.get("attack") or {}; comp = t.get("compliance") or {}; dread = t.get("dread") or {}
        tier = "Finding" if t.get("tier", "baseline") == "evidenced" else "Standard check"
        dread_score = f'{dread.get("total")}/50' if dread.get("total") is not None else ""
        writer.writerow([t.get("id", f"T{i+1:03d}"), t.get("title", ""), tier, t.get("severity", ""), (t.get("methodology", "") or "").upper(),
                         t.get("component_name", ""), t.get("category", ""), dread_score, dread.get("tier", ""),
                         "Yes" if t.get("cross_boundary") else "No", atk.get("id", ""), atk.get("tactic", ""),
                         " ".join(comp.get("soc2", [])), " ".join(comp.get("iso27001", [])), " ".join(comp.get("pci_dss", [])),
                         t.get("description", "")])
    return buf.getvalue().encode()


@app.post("/api/report/{fmt}")
async def adhoc_report(
    fmt: str,
    analysis: dict,
    user: dict = Depends(get_current_user),
    pdf: bool = False,
):
    if fmt not in ("markdown", "html", "pdf", "csv", "executive"):
        raise HTTPException(400, "Format must be markdown, html, pdf, csv, or executive")
    fname = f"threat_model_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    if fmt == "markdown":
        return Response(to_markdown(analysis), media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.md"'})
    if fmt == "html":
        return Response(to_html(analysis), media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.html"'})
    if fmt == "csv":
        threats = analysis.get("threats", [])
        system_name = (analysis.get("system", {}) or {}).get("name", "System")
        return Response(_risk_register_csv(threats, system_name), media_type="text/csv",
                        headers={"Content-Disposition": _content_disposition(f"risk_register_{system_name.replace(' ', '_')}.csv")})
    if fmt == "executive":
        # Business-level summary. Uses the configured LLM for narrative when a key
        # is set, else a deterministic template — so it works offline too. Returns
        # HTML by default; ?pdf=true renders a PDF when WeasyPrint is installed.
        from threat_engine.executive_report import generate_executive_report, html_to_pdf
        html = generate_executive_report(analysis)
        if pdf:
            pdf_bytes = html_to_pdf(html)
            if pdf_bytes is None:
                raise HTTPException(501, "PDF rendering requires the optional WeasyPrint package; request the HTML instead.")
            return Response(pdf_bytes, media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="executive_{fname}.pdf"'})
        return Response(html, media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="executive_{fname}.html"'})
    return Response(to_pdf(analysis), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.pdf"'})


# ===========================================================================
# MANAGEMENT VIEW + AUDIT LOG
# ===========================================================================
@app.get("/api/management/overview")
async def management_overview(
    actor: dict = Depends(require_permission("view.management")),
):
    return domain.management_overview()


@app.get("/api/management/threats")
async def management_threats(
    actor: dict = Depends(require_permission("view.management")),
):
    """Compact, flattened list of every threat across all models. Powers the
    management OWASP drill-down, remediation focus, and portfolio CSV export.
    Deliberately omits heavy fields (description, mitigations) to stay small."""
    features = {f["id"]: f for f in domain.list_features()}
    out: list[dict] = []
    for tm in domain.list_threat_models():
        full = domain.get_threat_model(tm["id"])
        analysis = (full or {}).get("analysis")
        if not analysis:
            continue
        statuses = domain.list_threat_statuses(tm["id"]) or {}
        fname = (features.get(tm.get("feature_id")) or {}).get("name", "")
        for t in (analysis.get("threats") or []):
            st = statuses.get(t.get("id")) or {}
            out.append({
                "tm_id": tm["id"],
                "tm_name": tm.get("name", ""),
                "feature": fname,
                "id": t.get("id"),
                "title": t.get("title", ""),
                "severity": t.get("severity", ""),
                "category": t.get("category", ""),
                "tier": t.get("tier", "baseline"),
                "owasp": domain._extract_owasp_label(t.get("references") or []),
                "cwe": (t.get("cwe") or {}).get("id", ""),
                "status": st.get("status", "open"),
                "updated_at": st.get("updated_at"),
            })
    return out


@app.get("/api/audit-log")
async def admin_audit_log(
    limit: int = 200,
    actor: dict = Depends(require_permission("audit.read")),
):
    limit = min(max(limit, 1), 1000)
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ===========================================================================
# UTILITY (used by canvas UI)
# ===========================================================================
@app.get("/api/methodologies")
async def list_methodologies(user: dict = Depends(get_current_user)):
    return {k: {"name": m["name"], "kind": m.get("kind", "methodology"),
                "categories": list(m["categories"].keys())}
            for k, m in METHODOLOGIES.items()}


@app.post("/api/extract-from-text")
async def extract_from_text(payload: dict, user: dict = Depends(get_current_user)):
    from threat_engine.analyzer import extract_components_from_text
    from threat_engine.trust_boundaries import infer_trust_boundaries

    text = (payload or {}).get("text", "")
    use_llm = bool((payload or {}).get("use_llm", False))

    result = extract_components_from_text(text)

    # If LLM mode requested AND key configured, replace heuristic boundaries
    # with LLM-inferred ones (falls back to heuristic on any failure).
    if use_llm:
        better = infer_trust_boundaries(
            {"components": result["components"], "data_flows": result["data_flows"]},
            source_text=text,
            use_llm=True,
        )
        if better:
            result["trust_boundaries"] = better
            result["boundary_inference_mode"] = "llm"
        else:
            result["boundary_inference_mode"] = "heuristic"
    else:
        result["boundary_inference_mode"] = "heuristic"

    return result


@app.post("/api/extract-structured")
async def extract_structured(payload: dict, user: dict = Depends(get_current_user)):
    """Parse a structured system description ('Name : type' / 'A -> B') into a
    system model. Deterministic and exact — returns 400 with a line-referenced
    message on any parse error so the UI can guide the user."""
    from threat_engine.analyzer import parse_structured_system
    text = (payload or {}).get("text", "")
    try:
        result = parse_structured_system(text)
    except ValueError as e:
        raise HTTPException(400, str(e))
    result["boundary_inference_mode"] = "heuristic"
    return result


# --- Diagram upload → system model --------------------------------------
# Accepted image types and a sane upload ceiling for architecture diagrams.
_DIAGRAM_TYPES = {"image/png": "image/png", "image/jpeg": "image/jpeg",
                  "image/jpg": "image/jpeg", "image/webp": "image/webp"}
_DIAGRAM_MAX_BYTES = 10 * 1024 * 1024  # 10 MB


async def _read_diagram(file: UploadFile) -> tuple[bytes, str]:
    """Validate an uploaded diagram and return (bytes, media_type)."""
    media_type = _DIAGRAM_TYPES.get((file.content_type or "").lower())
    if not media_type:
        raise HTTPException(415, "Upload a PNG, JPEG, or WebP image of the architecture diagram.")
    data = await file.read()
    if not data:
        raise HTTPException(400, "The uploaded file is empty.")
    if len(data) > _DIAGRAM_MAX_BYTES:
        raise HTTPException(413, "Diagram is too large (max 10 MB).")
    return data, media_type


@app.post("/api/extract-from-diagram")
async def extract_from_diagram_endpoint(
    file: UploadFile = File(...),
    description: str = Form(""),
    user: dict = Depends(get_current_user),
):
    """Extract a system model (components, flows, trust boundaries) from an
    uploaded architecture diagram using a vision-capable AI provider. Requires
    an AI provider to be configured (Admin → Settings)."""
    from threat_engine.diagram_extractor import extract_from_diagram
    if not _llm_available():
        raise HTTPException(400, "Diagram analysis needs a vision-capable AI provider. Configure one in Admin → Settings, or describe your system in text instead.")

    data, media_type = await _read_diagram(file)
    result = extract_from_diagram(data, media_type, description or "")
    audit(user["id"], user["email"], "diagram.extract", "grant",
          ip_address=user.get("_ip"),
          detail=f"method={result.get('extraction_method')} "
                 f"components={len(result.get('components', []))}")
    return result


@app.post("/api/threat-models/from-diagram")
async def create_threat_model_from_diagram(
    file: UploadFile = File(...),
    feature_id: int = Form(...),
    name: str = Form(""),
    description: str = Form(""),
    methodologies: str = Form("stride,linddun,pasta"),
    analyze: bool = Form(True),
    actor: dict = Depends(require_permission("threat_model.create")),
):
    """One-shot: upload an architecture diagram and get a persisted threat model
    back. Extracts the system model from the image, creates the threat model
    under the given feature, and (by default) runs the analysis immediately."""
    from threat_engine.diagram_extractor import extract_from_diagram
    if not _llm_available():
        raise HTTPException(400, "Diagram analysis needs a vision-capable AI provider. Configure one in Admin → Settings, or describe your system in text instead.")

    feature = domain.get_feature(feature_id)
    if not feature:
        raise HTTPException(400, "Feature not found")
    if not can_access_feature(actor, feature, "read"):
        raise HTTPException(403, "No access to this feature")

    data, media_type = await _read_diagram(file)
    system = extract_from_diagram(data, media_type, description or "")

    mkeys = [m.strip().lower() for m in methodologies.split(",") if m.strip()] or ["stride", "linddun", "pasta"]
    tm_name = name.strip() or (file.filename or "Diagram").rsplit(".", 1)[0]

    try:
        tm = domain.create_threat_model(
            feature_id, owner_id=actor["id"], name=tm_name,
            description=description or "Created from uploaded architecture diagram",
            system=system, methodologies=mkeys,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    result = None
    if analyze:
        # analyze_system normalizes the model and reports any repairs in model_issues
        # (dangling vision references → visible placeholder nodes, etc.), so nothing
        # the extractor produced is dropped silently.
        result = analyze_system(tm["system"], mkeys, use_llm=False)
        domain.update_threat_model(tm["id"], methodologies=mkeys, analysis=result)

    audit(actor["id"], actor["email"], "threat_model.create_from_diagram", "grant",
          "threat_model", tm["id"], ip_address=actor.get("_ip"),
          detail=f"extraction={system.get('extraction_method')} "
                 f"findings={result['summary'].get('findings', result['summary']['total']) if result else 0}")

    return {
        "threat_model": domain.get_threat_model(tm["id"]),
        "extraction_method": system.get("extraction_method"),
        "analysis": result,
    }


@app.post("/api/infer-trust-boundaries")
async def infer_trust_boundaries_endpoint(
    payload: dict,
    user: dict = Depends(get_current_user),
):
    """Re-infer trust boundaries on an existing system.
    Body: { system: {...}, source_text?: str, use_llm?: bool }
    """
    from threat_engine.trust_boundaries import infer_trust_boundaries

    system = (payload or {}).get("system") or {}
    source_text = (payload or {}).get("source_text", "")
    use_llm = bool((payload or {}).get("use_llm", False))

    boundaries = infer_trust_boundaries(system, source_text=source_text, use_llm=use_llm)
    return {
        "trust_boundaries": boundaries,
        "mode": "llm" if (use_llm and _llm_available()) else "heuristic",
    }


@app.post("/api/auto-layout")
async def auto_layout(payload: dict, user: dict = Depends(get_current_user)):
    return auto_layout_for_frontend(payload)


@app.post("/api/dfd-svg")
async def dfd_svg(payload: dict, user: dict = Depends(get_current_user)):
    svg = render_dfd_svg(
        payload.get("system", {}),
        animated=payload.get("animated", True),
        positions=payload.get("layout"),
    )
    return Response(svg, media_type="image/svg+xml")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": app.version,
        "llm_configured": _llm_available(),
        "llm_provider": _llm_provider(),
        "jira_configured": __import__("jira_client").is_configured(),
        "methodologies": list(METHODOLOGIES.keys()),
    }


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    # Minimal transparent 1x1 SVG — silences favicon 404s in logs
    svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>'
    return Response(svg, media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    """Public landing page — login form. JS redirects logged-in users to their role page."""
    return templates.TemplateResponse(request, "login.html", {})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {})


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    """Admin console. Page itself is public HTML — JS calls /api/auth/me to verify
    role and redirects unauthenticated/wrong-role users. The actual data calls
    enforce server-side role checks."""
    return templates.TemplateResponse(request, "admin.html", {})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Developer dashboard — list of threat models the user can see."""
    return templates.TemplateResponse(request, "dashboard.html", {})


@app.get("/management", response_class=HTMLResponse)
async def management_page(request: Request):
    """Management overview — feature × severity rollup."""
    return templates.TemplateResponse(request, "management.html", {})


@app.get("/canvas", include_in_schema=False)
async def canvas_page():
    """Retired legacy canvas UI. Its features (templates, risk matrix, attack
    paths, CSV export) now live in the authenticated dashboard, so old links
    redirect there instead of serving the unauthenticated, non-persistent page."""
    return RedirectResponse(url="/dashboard", status_code=307)


# ===========================================================================
# Health checks (D3)
# ===========================================================================
@app.get("/healthz", include_in_schema=False)
async def healthz(): return {"status": "ok", "version": "2.1"}

@app.get("/readyz", include_in_schema=False)
async def readyz():
    try:
        with db_conn() as c: c.execute("SELECT 1")
        return {"status": "ready", "db": "ok"}
    except Exception as e: raise HTTPException(503, f"DB not ready: {e}")


# ===========================================================================
# Custom threat rules CRUD (E5)
# ===========================================================================
class CustomRuleIn(BaseModel):
    name: str; title: str; severity: str = "Medium"; category: str = "Custom"
    description: str = ""; applies_to: list[str] = []; mitigations: list[str] = []; tags: list[str] = []

@app.post("/api/custom-rules")
async def create_rule(body: CustomRuleIn, user: dict = Depends(get_current_user)):
    return domain.create_custom_rule(user["id"], body.dict())

@app.get("/api/custom-rules")
async def list_rules(user: dict = Depends(get_current_user)):
    return domain.list_custom_rules(user["id"])

@app.put("/api/custom-rules/{rule_id}")
async def update_rule(rule_id: int, body: dict, user: dict = Depends(get_current_user)):
    r = domain.update_custom_rule(rule_id, user["id"], body)
    if not r: raise HTTPException(404, "Rule not found")
    return r

@app.delete("/api/custom-rules/{rule_id}")
async def delete_rule(rule_id: int, user: dict = Depends(get_current_user)):
    domain.delete_custom_rule(rule_id, user["id"]); return {"deleted": True}


# ===========================================================================
# Bulk threat status (U2)
# ===========================================================================
class BulkStatusItem(BaseModel):
    threat_id: str; status: str; owner: str | None = None; due_date: str | None = None

class BulkStatusRequest(BaseModel):
    threat_model_id: int; updates: list[BulkStatusItem]

@app.post("/api/threat-status/bulk")
async def bulk_update_status(req: BulkStatusRequest, user: dict = Depends(get_current_user)):
    tm = domain.get_threat_model(req.threat_model_id)
    if not tm: raise HTTPException(404, "Not found")
    ensure_can_access_threat_model(user, tm, "update")
    results = []
    for item in req.updates:
        try: results.append(domain.upsert_threat_status(req.threat_model_id, item.threat_id, item.status, updated_by=user["id"], owner=item.owner, due_date=item.due_date))
        except Exception as e: results.append({"threat_id": item.threat_id, "error": str(e)})
    return {"updated": len(results), "results": results}


class SingleStatusRequest(BaseModel):
    threat_model_id: int
    threat_id: str
    status: str
    owner: str | None = None
    due_date: str | None = None

@app.post("/api/threat-status")
async def update_single_status(req: SingleStatusRequest, user: dict = Depends(get_current_user)):
    """Set one threat's remediation status. Non-bulk counterpart to
    /api/threat-status/bulk (both write through domain.upsert_threat_status)."""
    tm = domain.get_threat_model(req.threat_model_id)
    if not tm: raise HTTPException(404, "Not found")
    ensure_can_access_threat_model(user, tm, "update")
    try:
        return domain.upsert_threat_status(req.threat_model_id, req.threat_id, req.status,
                                           updated_by=user["id"], owner=req.owner, due_date=req.due_date)
    except Exception as e:
        raise HTTPException(400, str(e))


# ===========================================================================
# ADMIN — Integration settings (LLM provider, Jira). Encrypted at rest,
# admin-only. Secrets are never returned to the client in the clear.
# ===========================================================================
class LlmSettingsUpdate(BaseModel):
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None

class JiraSettingsUpdate(BaseModel):
    base_url: str | None = None
    email: str | None = None
    api_token: str | None = None
    project_key: str | None = None
    default_issue_type: str | None = None


@app.get("/api/admin/settings/{namespace}")
async def get_admin_settings(namespace: str, actor: dict = Depends(require_role("admin"))):
    if namespace not in ("llm", "jira"):
        raise HTTPException(404, "Unknown settings namespace")
    return app_settings.get_settings_masked(namespace)


@app.put("/api/admin/settings/llm")
async def set_llm_settings(req: LlmSettingsUpdate, actor: dict = Depends(require_role("admin"))):
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if updates.get("provider") and updates["provider"] not in ("anthropic", "openai"):
        raise HTTPException(400, "provider must be 'anthropic' or 'openai'")
    result = app_settings.set_settings("llm", updates, updated_by=actor["id"])
    audit(actor["id"], actor["email"], "settings.llm.update", "grant", "settings", None,
          ip_address=actor.get("_ip"), detail=f"fields={sorted(updates.keys())}")
    return result


@app.put("/api/admin/settings/jira")
async def set_jira_settings(req: JiraSettingsUpdate, actor: dict = Depends(require_role("admin"))):
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if updates.get("base_url"):
        import jira_client
        err = jira_client.validate_base_url(updates["base_url"].rstrip("/"))
        if err:
            raise HTTPException(400, err)
        updates["base_url"] = updates["base_url"].rstrip("/")
    result = app_settings.set_settings("jira", updates, updated_by=actor["id"])
    audit(actor["id"], actor["email"], "settings.jira.update", "grant", "settings", None,
          ip_address=actor.get("_ip"), detail=f"fields={sorted(updates.keys())}")
    return result


@app.post("/api/admin/settings/llm/test")
async def test_llm_settings(actor: dict = Depends(require_role("admin"))):
    """Live 1-token probe so the admin sees the real result — success, or the
    actual provider error — instead of guessing."""
    from threat_engine.llm import complete_text, llm_available, provider as _p, text_model as _m, last_error
    if not llm_available():
        return {"ok": False, "error": "No API key configured."}
    out = complete_text("Reply with the single word: OK", max_tokens=5)
    if out:
        return {"ok": True, "provider": _p(), "model": _m(), "sample": out.strip()[:40]}
    return {"ok": False, "error": last_error() or "No response from the provider."}


@app.post("/api/admin/settings/jira/test")
async def test_jira_settings(actor: dict = Depends(require_role("admin"))):
    import jira_client
    return jira_client.test_connection()


# ===========================================================================
# Create a Jira ticket from a threat
# ===========================================================================
class CreateTicketRequest(BaseModel):
    threat_model_id: int
    threat_id: str


@app.post("/api/create-ticket")
async def create_ticket(req: CreateTicketRequest, user: dict = Depends(get_current_user)):
    """Create a Jira issue from a single threat. Requires write access to the
    threat model and a configured Jira integration."""
    import jira_client
    tm = domain.get_threat_model(req.threat_model_id)
    if not tm:
        raise HTTPException(404, "Threat model not found")
    ensure_can_access_threat_model(user, tm, "update")
    if not jira_client.is_configured():
        raise HTTPException(400, "Jira is not configured. Ask an admin to set it up in Admin → Settings.")
    analysis = tm.get("analysis") or {}
    threat = next((t for t in analysis.get("threats", []) if t.get("id") == req.threat_id), None)
    if not threat:
        raise HTTPException(404, "Threat not found in this model")
    system_name = (analysis.get("system", {}) or {}).get("name", tm.get("name", ""))
    result = jira_client.create_issue_from_threat(threat, system_name=system_name)
    if not result.get("ok"):
        raise HTTPException(502, result.get("error", "Jira ticket creation failed"))
    audit(user["id"], user["email"], "jira.ticket.create", "grant", "threat_model", req.threat_model_id,
          ip_address=user.get("_ip"), detail=f"threat={req.threat_id} issue={result.get('key')}")
    return result


# ===========================================================================
# Share link (U3)
# ===========================================================================
@app.post("/api/share/{threat_model_id}")
async def create_share_link(threat_model_id: int, request: Request, user: dict = Depends(get_current_user)):
    tm = domain.get_threat_model(threat_model_id)
    if not tm: raise HTTPException(404, "Not found")
    ensure_can_access_threat_model(user, tm, "read")
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    token = _secrets.token_urlsafe(24)
    from datetime import datetime as _dtnow
    try:
        expires_days = int(body.get("expires_days", 7))
    except (TypeError, ValueError):
        expires_days = 7
    expires_days = max(1, min(expires_days, 365))
    expires_at = (_dtnow.utcnow() + _td(days=expires_days)).isoformat()
    with domain.db_conn(write=True) as c:
        try: c.execute("CREATE TABLE IF NOT EXISTS share_tokens (token TEXT PRIMARY KEY, threat_model_id INTEGER NOT NULL, created_by INTEGER NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))")
        except Exception: pass
        c.execute("INSERT OR REPLACE INTO share_tokens (token, threat_model_id, created_by, expires_at) VALUES (?,?,?,?)", (token, threat_model_id, user["id"], expires_at))
    return {"url": f"{str(request.base_url).rstrip('/')}/share/{token}", "expires_at": expires_at, "token": token}

@app.get("/share/{token}", include_in_schema=False)
async def view_shared_report(token: str):
    from threat_engine.html_report import to_html
    from datetime import datetime as _dtnow2
    with domain.db_conn() as c:
        row = c.execute("SELECT * FROM share_tokens WHERE token=?", (token,)).fetchone()
    if not row: raise HTTPException(404, "Share link not found")
    row = dict(row)
    if _dtnow2.utcnow().isoformat() > row["expires_at"]: raise HTTPException(410, "Share link expired")
    tm = domain.get_threat_model(row["threat_model_id"])
    if not tm: raise HTTPException(404, "Not found")
    if not tm.get("analysis"):
        return HTMLResponse(content="<h1>Threat model has no analysis yet</h1>", status_code=200)
    return HTMLResponse(content=to_html(tm["analysis"]))


# ===========================================================================
# Release diff (P1)
# ===========================================================================
@app.get("/api/releases/{id1}/diff/{id2}")
async def diff_releases(id1: int, id2: int, user: dict = Depends(get_current_user)):
    tm1 = domain.get_threat_model(id1); tm2 = domain.get_threat_model(id2)
    if not tm1 or not tm2: raise HTTPException(404, "One or both threat models not found")
    ensure_can_access_threat_model(user, tm1, "read"); ensure_can_access_threat_model(user, tm2, "read")
    def _key(t): return (t.get("title","").lower().strip(), t.get("component_name","").lower().strip())
    def _threats(tm): ar = tm.get("analysis") or {}; return ar.get("threats", []) if isinstance(ar, dict) else []
    def _components(tm):
        sysd = tm.get("system") or (tm.get("analysis") or {}).get("system") or {}
        return {c.get("name", "") for c in (sysd.get("components") or [])}
    t1_map = {_key(t): t for t in _threats(tm1)}; t2_map = {_key(t): t for t in _threats(tm2)}
    c1 = _components(tm1); c2 = _components(tm2)
    common_threats = [k for k in t1_map if k in t2_map]
    common_components = c1 & c2
    # Overlap tells the UI whether these two models even describe the same system.
    # Compare is meant for one system across versions; two unrelated systems share
    # nothing, so the "diff" would be every threat new + every threat resolved —
    # meaningless. Surface that instead of pretending it's a real comparison.
    overlap = {
        "common_threats": len(common_threats),
        "common_components": len(common_components),
        "model_1_threats": len(t1_map), "model_2_threats": len(t2_map),
        "model_1_components": len(c1), "model_2_components": len(c2),
        "same_feature": (tm1.get("feature_id") is not None and tm1.get("feature_id") == tm2.get("feature_id")),
        "unrelated": len(common_threats) == 0 and len(common_components) == 0,
    }
    return {"model_1": {"id": id1, "name": tm1.get("name")}, "model_2": {"id": id2, "name": tm2.get("name")},
            "new_threats": [t for k, t in t2_map.items() if k not in t1_map],
            "resolved_threats": [t for k, t in t1_map.items() if k not in t2_map],
            "changed_severity": [{"threat": t2_map[k], "old": t1_map[k].get("severity"), "new": t2_map[k].get("severity")} for k in t1_map if k in t2_map and t1_map[k].get("severity") != t2_map[k].get("severity")],
            "new_components": list(c2-c1), "removed_components": list(c1-c2),
            "overlap": overlap,
            "summary": {"new": sum(1 for k in t2_map if k not in t1_map), "resolved": sum(1 for k in t1_map if k not in t2_map)}}


# ===========================================================================
# AI code fix (P2)
# ===========================================================================
class FixRequest(BaseModel):
    threat: dict; system_name: str = "System"; tech_stack: str = ""

@app.post("/api/threat/fix")
async def generate_fix(req: FixRequest, user: dict = Depends(get_current_user)):
    from threat_engine.llm import complete_text, llm_available, strip_fences, last_error
    if not llm_available():
        raise HTTPException(400, "AI fix generation needs an LLM. An admin can configure one in Admin → Settings → AI provider (or set ANTHROPIC_API_KEY / OPENAI_API_KEY).")
    try:
        t = req.threat
        prompt = f"You are a senior security engineer. Generate a concrete code fix for this threat.\nSystem: {req.system_name}\nTech stack: {req.tech_stack or 'not specified'}\nThreat: {t.get('title','')} ({t.get('severity','')})\nCWE: {(t.get('cwe') or {}).get('id','')}\nDescription: {t.get('description','')}\nMitigations: {', '.join(t.get('mitigations') or [])}\n\nReturn ONLY valid JSON with keys: language, explanation, before, after, diff_summary"
        text = complete_text(prompt, max_tokens=1200)
        if not text:
            # Surface the real provider error (e.g. billing, rate limit) instead of a generic message.
            raise HTTPException(502, f"AI fix failed: {last_error() or 'the model returned no response'}")
        return json.loads(strip_fences(text))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Fix generation failed: {e}")


# ===========================================================================
# CSV export
# ===========================================================================
@app.post("/api/report/csv")
async def report_csv(request: Request, user: dict = Depends(get_current_user)):
    body = await request.json()
    threats = body.get("threats", []); system_name = body.get("system", {}).get("name", "System")
    return Response(content=_risk_register_csv(threats, system_name), media_type="text/csv",
                    headers={"Content-Disposition": _content_disposition(f"risk_register_{system_name.replace(' ', '_')}.csv")})


# ===========================================================================
# Templates
# ===========================================================================
@app.get("/api/templates")
async def get_templates(user: dict = Depends(get_current_user)):
    tpl = BASE_DIR / "static" / "templates.json"
    return json.loads(tpl.read_text()) if tpl.exists() else []


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "127.0.0.1")
    print(f"\n  ThreatGuard v2.0 running on {host}:{port}")
    print(f"  LLM: {_llm_provider()} ({'available' if _llm_available() else 'not configured — rules-only'})")
    print(f"  JWT_SECRET:      {'set' if os.getenv('JWT_SECRET') else 'NOT SET (sessions reset on restart)'}")
    print(f"  Initial admin:   {'configured' if os.getenv('INITIAL_ADMIN_EMAIL') else 'not configured'}\n")
    uvicorn.run("app:app", host=host, port=port, reload=False)
