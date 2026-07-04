"""Threat Modeler — FastAPI app with RBAC.

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
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

import json
import re
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
    get_current_user, require_permission,
    ensure_can_access_threat_model, can_access_feature, get_role_permissions,
)
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

app = FastAPI(title="Threat Modeler", version="2.1")

app.add_middleware(RequestIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
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
    """Self-registration creates a User-role account.
    To create Management or Admin accounts, an Admin uses POST /api/users."""
    try:
        u = register_user(req.email, req.password, req.full_name, role="user")
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
          detail=f"methodologies={req.methodologies} threats={result['summary']['total']}")
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
    if fmt not in ("markdown", "html", "pdf"):
        raise HTTPException(400, "Format must be markdown, html, or pdf")
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "read")
    if not tm.get("analysis"):
        raise HTTPException(400, "Run analysis before generating a report")
    analysis = tm["analysis"]
    fname = f"threat_model_{tid}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    if fmt == "markdown":
        return Response(to_markdown(analysis), media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.md"'})
    if fmt == "html":
        return Response(to_html(analysis), media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.html"'})
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


def _risk_register_csv(threats: list, system_name: str = "System") -> bytes:
    """Build a CSV risk register from a list of threats. Shared by the
    /api/report/csv route and the {fmt}=csv path."""
    import csv as _csv, io as _io
    buf = _io.StringIO(); writer = _csv.writer(buf)
    writer.writerow(["ID", "Title", "Severity", "Methodology", "Component", "Category", "CVSS3.1",
                     "Cross-boundary", "ATT&CK ID", "ATT&CK Tactic", "SOC2", "ISO27001", "PCI-DSS", "Description"])
    for i, t in enumerate(threats):
        atk = t.get("attack") or {}; comp = t.get("compliance") or {}
        writer.writerow([t.get("id", f"T{i+1:03d}"), t.get("title", ""), t.get("severity", ""), (t.get("methodology", "") or "").upper(),
                         t.get("component_name", ""), t.get("category", ""), (t.get("cvss31", {}) or {}).get("score", ""),
                         "Yes" if t.get("cross_boundary") else "No", atk.get("id", ""), atk.get("tactic", ""),
                         " ".join(comp.get("soc2", [])), " ".join(comp.get("iso27001", [])), " ".join(comp.get("pci_dss", [])),
                         t.get("description", "")])
    return buf.getvalue().encode()


@app.post("/api/report/{fmt}")
async def adhoc_report(
    fmt: str,
    analysis: dict,
    user: dict = Depends(get_current_user),
):
    if fmt not in ("markdown", "html", "pdf", "csv"):
        raise HTTPException(400)
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
                        headers={"Content-Disposition": f'attachment; filename="risk_register_{system_name.replace(" ", "_")}.csv"'})
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
    return {k: {"name": m["name"], "categories": list(m["categories"].keys())}
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
    uploaded architecture diagram. Uses Claude vision when ANTHROPIC_API_KEY is
    set, otherwise returns an editable starter model."""
    from threat_engine.diagram_extractor import extract_from_diagram

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
    methodologies: str = Form("stride,owasp"),
    analyze: bool = Form(True),
    actor: dict = Depends(require_permission("threat_model.create")),
):
    """One-shot: upload an architecture diagram and get a persisted threat model
    back. Extracts the system model from the image, creates the threat model
    under the given feature, and (by default) runs the analysis immediately."""
    from threat_engine.diagram_extractor import extract_from_diagram

    feature = domain.get_feature(feature_id)
    if not feature:
        raise HTTPException(400, "Feature not found")
    if not can_access_feature(actor, feature, "read"):
        raise HTTPException(403, "No access to this feature")

    data, media_type = await _read_diagram(file)
    system = extract_from_diagram(data, media_type, description or "")

    mkeys = [m.strip().lower() for m in methodologies.split(",") if m.strip()] or ["stride", "owasp"]
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
        result = analyze_system(tm["system"], mkeys, use_llm=False)
        domain.update_threat_model(tm["id"], methodologies=mkeys, analysis=result)

    audit(actor["id"], actor["email"], "threat_model.create_from_diagram", "grant",
          "threat_model", tm["id"], ip_address=actor.get("_ip"),
          detail=f"extraction={system.get('extraction_method')} "
                 f"threats={result['summary']['total'] if result else 0}")

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


@app.get("/canvas", response_class=HTMLResponse)
async def canvas_page(request: Request):
    """Legacy canvas UI — the threat-modeling interface from before Stage 1.
    Still has the old API calls hard-coded; will need rewiring in a follow-up."""
    methodologies_ctx = {
        k: {
            "name": m["name"],
            "description": m.get("description", ""),
            "categories": list(m["categories"].keys()),
        }
        for k, m in METHODOLOGIES.items()
    }
    return templates.TemplateResponse(
        request, "index.html",
        {
            "methodologies": methodologies_ctx,
            "llm_available": _llm_available(),
            "llm_provider": _llm_provider(),
        }
    )


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


# ===========================================================================
# Share link (U3)
# ===========================================================================
@app.post("/api/share/{threat_model_id}")
async def create_share_link(threat_model_id: int, request: Request, user: dict = Depends(get_current_user)):
    tm = domain.get_threat_model(threat_model_id)
    if not tm: raise HTTPException(404, "Not found")
    ensure_can_access_threat_model(user, tm, "read")
    body = await request.json()
    token = _secrets.token_urlsafe(24)
    from datetime import datetime as _dtnow
    expires_at = (_dtnow.utcnow() + _td(days=int(body.get("expires_days", 7)))).isoformat()
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
    def _threats(tm): ar = tm.get("analysis_result") or {}; return ar.get("threats", []) if isinstance(ar, dict) else []
    t1_map = {_key(t): t for t in _threats(tm1)}; t2_map = {_key(t): t for t in _threats(tm2)}
    c1 = {c.get("name","") for c in (tm1.get("components") or [])}; c2 = {c.get("name","") for c in (tm2.get("components") or [])}
    return {"model_1": {"id": id1, "name": tm1.get("name")}, "model_2": {"id": id2, "name": tm2.get("name")},
            "new_threats": [t for k, t in t2_map.items() if k not in t1_map],
            "resolved_threats": [t for k, t in t1_map.items() if k not in t2_map],
            "changed_severity": [{"threat": t2_map[k], "old": t1_map[k].get("severity"), "new": t2_map[k].get("severity")} for k in t1_map if k in t2_map and t1_map[k].get("severity") != t2_map[k].get("severity")],
            "new_components": list(c2-c1), "removed_components": list(c1-c2),
            "summary": {"new": sum(1 for k in t2_map if k not in t1_map), "resolved": sum(1 for k in t1_map if k not in t2_map)}}


# ===========================================================================
# AI code fix (P2)
# ===========================================================================
class FixRequest(BaseModel):
    threat: dict; system_name: str = "System"; tech_stack: str = ""

@app.post("/api/threat/fix")
async def generate_fix(req: FixRequest, user: dict = Depends(get_current_user)):
    from threat_engine.llm import complete_text, llm_available, strip_fences
    if not llm_available():
        raise HTTPException(400, "Configure an LLM provider (set ANTHROPIC_API_KEY or OPENAI_API_KEY) to enable AI fix generation")
    try:
        t = req.threat
        prompt = f"You are a senior security engineer. Generate a concrete code fix for this threat.\nSystem: {req.system_name}\nTech stack: {req.tech_stack or 'not specified'}\nThreat: {t.get('title','')} ({t.get('severity','')})\nCWE: {(t.get('cwe') or {}).get('id','')}\nDescription: {t.get('description','')}\nMitigations: {', '.join(t.get('mitigations') or [])}\n\nReturn ONLY valid JSON with keys: language, explanation, before, after, diff_summary"
        text = complete_text(prompt, max_tokens=1200)
        if not text:
            raise HTTPException(502, "LLM returned no response")
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
                    headers={"Content-Disposition": f'attachment; filename="risk_register_{system_name.replace(" ","_")}.csv"'})


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
    print(f"\n  Threat Modeler v2.0 running on {host}:{port}")
    print(f"  LLM: {_llm_provider()} ({'available' if _llm_available() else 'not configured — rules-only'})")
    print(f"  JWT_SECRET:      {'set' if os.getenv('JWT_SECRET') else 'NOT SET (sessions reset on restart)'}")
    print(f"  Initial admin:   {'configured' if os.getenv('INITIAL_ADMIN_EMAIL') else 'not configured'}\n")
    uvicorn.run("app:app", host=host, port=port, reload=False)
