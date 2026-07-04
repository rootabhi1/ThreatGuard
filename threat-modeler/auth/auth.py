"""Authentication primitives: password hashing, JWT issuance/verification,
login flow, refresh-token management.

Tokens:
  - Access token: JWT, 15 minutes, contains {sub, role, email, iat, exp}.
  - Refresh token: opaque random string, 7 days, hashed in DB so revocation works.

Auth events are written to the audit log.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from db import db_conn, audit, _now


# ---------------------------------------------------------------------------
# Configuration — read once
# ---------------------------------------------------------------------------
# JWT secret. In production this MUST come from an environment variable. For
# POC we generate a random one if missing, but warn loudly.
_JWT_SECRET = os.getenv("JWT_SECRET")
if not _JWT_SECRET:
    _JWT_SECRET = secrets.token_urlsafe(48)
    print("[auth] WARNING: JWT_SECRET not set in env, generated a random one. "
          "All sessions will be invalidated on restart. Set JWT_SECRET for stability.")

_JWT_ALGORITHM = "HS256"
_ACCESS_TOKEN_TTL = timedelta(minutes=15)
_REFRESH_TOKEN_TTL = timedelta(days=7)

# Account lockout policy
_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_DURATION = timedelta(minutes=15)


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if len(password) > 128:
        raise ValueError("Password must be at most 128 characters")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
def create_access_token(user_id: int, email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + _ACCESS_TOKEN_TTL).timestamp()),
        "jti": secrets.token_hex(8),
        "type": "access",
    }
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Verify and decode. Raises jwt.PyJWTError on invalid/expired."""
    payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Wrong token type")
    return payload


# ---------------------------------------------------------------------------
# Refresh tokens — opaque, hashed in DB
# ---------------------------------------------------------------------------
def _hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_refresh_token(user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    expires = datetime.now(timezone.utc) + _REFRESH_TOKEN_TTL
    with db_conn(write=True) as c:
        c.execute(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, _hash_refresh_token(token), expires.isoformat(), _now())
        )
    return token


def consume_refresh_token(token: str) -> int | None:
    """Returns user_id if the refresh token is valid and not revoked. Rotates
    the token (revokes old, caller should issue new). None if invalid."""
    h = _hash_refresh_token(token)
    with db_conn(write=True) as c:
        row = c.execute(
            "SELECT id, user_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash=?",
            (h,)
        ).fetchone()
        if not row:
            return None
        if row["revoked_at"]:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            return None
        # Rotate — mark this one revoked
        c.execute(
            "UPDATE refresh_tokens SET revoked_at=? WHERE id=?",
            (_now(), row["id"])
        )
        return row["user_id"]


def revoke_all_refresh_tokens(user_id: int):
    with db_conn(write=True) as c:
        c.execute(
            "UPDATE refresh_tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
            (_now(), user_id)
        )


# ---------------------------------------------------------------------------
# Registration & login
# ---------------------------------------------------------------------------
def register_user(email: str, password: str, full_name: str, role: str = "user") -> dict:
    """Register a new user. Returns user dict. Raises ValueError on bad input."""
    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValueError("Invalid email")
    if role not in ("user", "management", "admin"):
        raise ValueError(f"Invalid role: {role}")
    pw_hash = hash_password(password)

    with db_conn(write=True) as c:
        existing = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            raise ValueError("Email already registered")
        cursor = c.execute(
            "INSERT INTO users (email, password_hash, full_name, role, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (email, pw_hash, full_name, role, _now(), _now())
        )
        uid = cursor.lastrowid

    audit(uid, email, "user.register", "grant", "user", uid)
    return get_user_by_id(uid)


def login(email: str, password: str, ip: str | None = None,
          user_agent: str | None = None) -> tuple[str, str, dict]:
    """Authenticate. Returns (access_token, refresh_token, user_dict).
    Raises ValueError with safe message on failure."""
    email = email.strip().lower()
    user = _get_user_row_by_email(email)
    if not user:
        # Run a dummy bcrypt to hide whether email exists (timing leak defence)
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12)))
        audit(None, email, "user.login", "deny", ip_address=ip, user_agent=user_agent,
              detail="email not found")
        raise ValueError("Invalid credentials")

    # Account lockout check
    if user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if locked_until > datetime.now(timezone.utc):
            audit(user["id"], email, "user.login", "deny", "user", user["id"],
                  ip_address=ip, user_agent=user_agent, detail="account locked")
            raise ValueError("Account locked. Try again later.")

    if not user["is_active"]:
        audit(user["id"], email, "user.login", "deny", "user", user["id"],
              ip_address=ip, user_agent=user_agent, detail="account inactive")
        raise ValueError("Account is inactive")

    if not verify_password(password, user["password_hash"]):
        # Increment failure counter, possibly lock
        with db_conn(write=True) as c:
            new_count = (user["failed_attempts"] or 0) + 1
            locked_until = None
            if new_count >= _MAX_FAILED_ATTEMPTS:
                locked_until = (datetime.now(timezone.utc) + _LOCKOUT_DURATION).isoformat()
            c.execute(
                "UPDATE users SET failed_attempts=?, locked_until=?, updated_at=? WHERE id=?",
                (new_count, locked_until, _now(), user["id"])
            )
        audit(user["id"], email, "user.login", "deny", "user", user["id"],
              ip_address=ip, user_agent=user_agent,
              detail=f"bad password (attempt {new_count})")
        raise ValueError("Invalid credentials")

    # Success — reset counter, issue tokens
    with db_conn(write=True) as c:
        c.execute(
            "UPDATE users SET failed_attempts=0, locked_until=NULL, updated_at=? WHERE id=?",
            (_now(), user["id"])
        )
    access = create_access_token(user["id"], user["email"], user["role"])
    refresh = create_refresh_token(user["id"])
    audit(user["id"], email, "user.login", "grant", "user", user["id"],
          ip_address=ip, user_agent=user_agent)

    return access, refresh, _user_row_to_dict(user)


# ---------------------------------------------------------------------------
# User lookups
# ---------------------------------------------------------------------------
def _user_row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "email": row["email"],
        "full_name": row["full_name"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
    }


def _get_user_row_by_email(email: str):
    with db_conn() as c:
        return c.execute("SELECT * FROM users WHERE email=?", (email.lower(),)).fetchone()


def get_user_by_id(uid: int) -> dict | None:
    with db_conn() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return _user_row_to_dict(row) if row else None


def list_users() -> list[dict]:
    with db_conn() as c:
        rows = c.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return [_user_row_to_dict(r) for r in rows]


def update_user_role(uid: int, new_role: str, by_user_id: int):
    if new_role not in ("user", "management", "admin"):
        raise ValueError(f"Invalid role: {new_role}")
    with db_conn(write=True) as c:
        c.execute(
            "UPDATE users SET role=?, updated_at=? WHERE id=?",
            (new_role, _now(), uid)
        )
    # Critical: revoke all refresh tokens so the new role takes effect on next login.
    # (Access tokens still valid for up to 15 min — see TOKEN_TTL above.)
    revoke_all_refresh_tokens(uid)
    audit(by_user_id, None, "user.role_changed", "grant", "user", uid,
          detail=f"new role={new_role}")


def deactivate_user(uid: int, by_user_id: int):
    with db_conn(write=True) as c:
        c.execute("UPDATE users SET is_active=0, updated_at=? WHERE id=?",
                  (_now(), uid))
    revoke_all_refresh_tokens(uid)
    audit(by_user_id, None, "user.deactivated", "grant", "user", uid)
