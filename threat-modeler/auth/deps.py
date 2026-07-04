"""FastAPI dependencies for auth/authz.

Usage:
    @app.get("/api/threat_models")
    async def list_tms(user: dict = Depends(require_permission("threat_model.read.own"))):
        ...

    @app.get("/api/threat_models/{tm_id}")
    async def get_tm(tm_id: int, user: dict = Depends(get_current_user)):
        tm = get_threat_model(tm_id)
        if not tm:
            raise HTTPException(404)
        ensure_can_access(user, tm, "read")   # 404 if not permitted
        return tm
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt as pyjwt

from auth.auth import decode_access_token, get_user_by_id
from auth.permissions import role_has_permission
from db import db_conn, audit


# Bearer token scheme (auto_error=False so we can return our own 401)
_bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Core dependency: extract + validate the current user
# ---------------------------------------------------------------------------
async def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    """Validates JWT, fetches fresh user from DB, returns user dict.

    Why we re-fetch: the JWT contains the role at the time of issue. If an
    admin promotes someone, the new role takes effect on next request, not next
    login. (At enterprise scale we'd cache this in Redis with short TTL.)
    """
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = creds.credentials
    try:
        payload = decode_access_token(token)
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except pyjwt.PyJWTError:
        raise HTTPException(401, "Invalid token")

    uid = int(payload["sub"])
    user = get_user_by_id(uid)
    if not user:
        raise HTTPException(401, "User not found")
    if not user["is_active"]:
        raise HTTPException(403, "Account is inactive")

    # Stash request metadata on the user dict for downstream auditing
    user["_ip"] = request.client.host if request.client else None
    user["_user_agent"] = request.headers.get("user-agent", "")

    return user


# ---------------------------------------------------------------------------
# Decorators / dependency factories
# ---------------------------------------------------------------------------
def require_permission(permission: str):
    """Returns a FastAPI dependency that ensures the current user has `permission`.
    Audits both grant and deny."""
    async def _dep(user: dict = Depends(get_current_user)) -> dict:
        if not role_has_permission(user["role"], permission):
            audit(user["id"], user["email"], permission, "deny",
                  ip_address=user.get("_ip"), user_agent=user.get("_user_agent"),
                  detail=f"role={user['role']}")
            # 403 here is fine — they have a valid identity, just not authorized
            # We DO NOT 404 here because the action itself isn't a resource.
            # Resource-level checks (where 404 hides existence) live in
            # ensure_can_access below.
            raise HTTPException(403, f"Forbidden: missing permission {permission}")
        return user
    return _dep


def require_role(*roles: str):
    """Same shape as require_permission but for raw roles. Use sparingly —
    permissions are the primary check."""
    async def _dep(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            audit(user["id"], user["email"], f"role_check:{','.join(roles)}", "deny",
                  ip_address=user.get("_ip"), detail=f"role={user['role']}")
            raise HTTPException(403, "Forbidden")
        return user
    return _dep


# ---------------------------------------------------------------------------
# Resource-access checks (ownership + admin-granted feature access)
# ---------------------------------------------------------------------------
def can_access_threat_model(user: dict, tm_row: dict, action: str) -> bool:
    """Can this user perform `action` on this threat model?

    Rules (strict ownership model, read-only management):
      - Admin: always yes.
      - Management: read-only — they can READ all threat models and generate
        reports, but cannot update anything (including threat statuses).
      - User: yes ONLY if they own the TM. Feature grants give create rights,
        not visibility into other users' TMs.
    """
    role = user["role"]
    if role == "admin":
        return True

    if role == "management":
        # Management is strictly read-only. Status updates belong to the owner.
        return action == "read"

    # User: strict ownership only — they must own the TM
    return tm_row["owner_id"] == user["id"]


def ensure_can_access_threat_model(user: dict, tm_row: dict, action: str):
    """Raises 404 if not permitted. The 404-not-403 pattern hides existence."""
    if tm_row is None:
        raise HTTPException(404)
    if not can_access_threat_model(user, tm_row, action):
        audit(user["id"], user["email"], f"threat_model.{action}", "deny",
              "threat_model", tm_row["id"],
              ip_address=user.get("_ip"), user_agent=user.get("_user_agent"),
              detail=f"role={user['role']} owner={tm_row['owner_id']}")
        raise HTTPException(404)
    audit(user["id"], user["email"], f"threat_model.{action}", "grant",
          "threat_model", tm_row["id"],
          ip_address=user.get("_ip"), user_agent=user.get("_user_agent"))


def can_access_feature(user: dict, feature_row: dict, action: str) -> bool:
    role = user["role"]
    if role == "admin":
        return True
    if role == "management":
        return action == "read"
    # User: must have explicit grant or be the creator
    if feature_row["created_by"] == user["id"]:
        return True
    with db_conn() as c:
        granted = c.execute(
            "SELECT 1 FROM user_feature_access WHERE user_id=? AND feature_id=?",
            (user["id"], feature_row["id"])
        ).fetchone()
    return action == "read" and granted is not None
