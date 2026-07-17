"""Admin-configurable integration settings with encryption at rest.

One JSON blob per namespace (e.g. "llm", "jira") in the app_settings table.
Fields named in SECRET_FIELDS are encrypted before they touch the database and
decrypted only when the server needs to use them — they are never returned to a
client in the clear (the API layer sends a masked "····last4" hint instead).

Encryption key: derived from SETTINGS_SECRET_KEY if set, otherwise from
JWT_SECRET (always present in a real deployment). Rotating that secret makes
previously stored secrets unreadable — callers treat a decrypt failure as
"not configured", so the worst case is re-entering the key, never a crash.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

from db import db_conn, _now

# Secret fields per namespace — encrypted at rest, never sent to clients in clear.
SECRET_FIELDS = {
    "llm":  {"api_key"},
    "jira": {"api_token"},
}

_ENC_PREFIX = "enc:"


def _fernet():
    """Build a Fernet from a key derived from SETTINGS_SECRET_KEY or JWT_SECRET."""
    from cryptography.fernet import Fernet
    secret = os.getenv("SETTINGS_SECRET_KEY") or os.getenv("JWT_SECRET") or "insecure-dev-key"
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def _encrypt(plain: str) -> str:
    if not plain:
        return ""
    return _ENC_PREFIX + _fernet().encrypt(plain.encode()).decode()


def _decrypt(stored: str) -> str:
    """Decrypt a stored secret. Returns "" on any failure (missing lib, rotated
    key, tampering) so a bad secret degrades to 'not configured'."""
    if not stored or not stored.startswith(_ENC_PREFIX):
        return stored or ""
    try:
        return _fernet().decrypt(stored[len(_ENC_PREFIX):].encode()).decode()
    except Exception:
        return ""


def _mask(plain: str) -> str:
    """A safe hint for the UI: shows only that a secret is set and its last 4 chars."""
    if not plain:
        return ""
    return ("·" * 6) + plain[-4:] if len(plain) >= 4 else "····"


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------
def _read_raw(namespace: str) -> dict:
    with db_conn() as c:
        row = c.execute("SELECT value FROM app_settings WHERE namespace=?", (namespace,)).fetchone()
    if not row:
        return {}
    try:
        return json.loads(row["value"] if hasattr(row, "keys") else row[0]) or {}
    except Exception:
        return {}


def get_settings_masked(namespace: str) -> dict:
    """Config for display: secret fields are replaced with a masked hint plus a
    `<field>_set` boolean, so the real secret never leaves the server."""
    raw = _read_raw(namespace)
    secrets = SECRET_FIELDS.get(namespace, set())
    out = {}
    for k, v in raw.items():
        if k in secrets:
            plain = _decrypt(v)
            out[k] = _mask(plain)
            out[f"{k}_set"] = bool(plain)
        else:
            out[k] = v
    for s in secrets:
        out.setdefault(f"{s}_set", False)
    return out


def get_secret(namespace: str, field: str) -> str:
    """Decrypted secret for server-side use (LLM/Jira calls). "" if unset."""
    return _decrypt(_read_raw(namespace).get(field, ""))


def get_value(namespace: str, field: str, default=None):
    """A non-secret config value."""
    return _read_raw(namespace).get(field, default)


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------
def set_settings(namespace: str, updates: dict, updated_by: int | None = None) -> dict:
    """Merge `updates` into the namespace. Secret fields are encrypted; a blank
    secret value leaves the existing one untouched (so submitting a form without
    re-typing the key does not wipe it). Returns the masked view."""
    raw = _read_raw(namespace)
    secrets = SECRET_FIELDS.get(namespace, set())
    for k, v in updates.items():
        if k in secrets:
            if v is None or v == "":
                continue  # keep existing secret
            raw[k] = _encrypt(str(v))
        else:
            raw[k] = v
    with db_conn(write=True) as c:
        c.execute(
            "INSERT INTO app_settings (namespace, value, updated_by, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(namespace) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
            (namespace, json.dumps(raw), updated_by, _now()),
        )
    return get_settings_masked(namespace)


def clear_secret(namespace: str, field: str, updated_by: int | None = None):
    """Explicitly remove a stored secret."""
    raw = _read_raw(namespace)
    if field in raw:
        raw.pop(field, None)
        with db_conn(write=True) as c:
            c.execute(
                "INSERT INTO app_settings (namespace, value, updated_by, updated_at) VALUES (?,?,?,?) "
                "ON CONFLICT(namespace) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                (namespace, json.dumps(raw), updated_by, _now()),
            )
