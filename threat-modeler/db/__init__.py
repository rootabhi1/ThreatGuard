"""Database layer.

Currently SQLite for POC. Designed to be swapped to PostgreSQL with minimal
changes:
  - Connection management is centralized in db_conn()
  - All queries use ? placeholders (Postgres uses %s, but we'll add a translator)
  - No SQLite-specific SQL features used (no AUTOINCREMENT, no PRAGMAs in business code)
  - Schema uses standard SQL types (TEXT, INTEGER, REAL, JSON-as-TEXT)

When migrating to Postgres:
  1. Replace `sqlite3.connect(...)` with `asyncpg.connect(...)` or psycopg
  2. Update _PLACEHOLDER from '?' to '%s'
  3. Replace `INTEGER PRIMARY KEY` with `SERIAL PRIMARY KEY`
  4. Add a connection pool
  5. Migrate existing data via the export/import scripts (which we won't write
     until you actually decide to migrate)
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

# E5: Custom threat rules table
INIT_SQL_CUSTOM_RULES = """
CREATE TABLE IF NOT EXISTS custom_threat_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    name TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'Medium',
    category TEXT NOT NULL DEFAULT 'Custom', description TEXT NOT NULL DEFAULT '',
    applies_to TEXT NOT NULL DEFAULT '[]', mitigations TEXT NOT NULL DEFAULT '[]',
    tags TEXT NOT NULL DEFAULT '[]', enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_custom_rules_user ON custom_threat_rules(user_id);
"""

# U3: Share tokens table
INIT_SQL_SHARE_TOKENS = """
CREATE TABLE IF NOT EXISTS share_tokens (
    token TEXT PRIMARY KEY, threat_model_id INTEGER NOT NULL,
    created_by INTEGER NOT NULL, expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

DB_PATH = Path(os.getenv("THREAT_MODELER_DB", "data/threat_modeler.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# SQLite has limited concurrency. We use WAL mode + a single writer lock to keep
# the POC honest. For real scale, swap to Postgres.
_write_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def db_conn(write: bool = False) -> Iterator[sqlite3.Connection]:
    """Get a connection. Pass write=True for writes — they take a process-wide
    lock so we don't get SQLite 'database is locked' errors under concurrency.
    Reads run concurrently in WAL mode."""
    if write:
        _write_lock.acquire()
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if write:
        conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        if write:
            conn.commit()
    except Exception:
        if write:
            conn.rollback()
        raise
    finally:
        conn.close()
        if write:
            _write_lock.release()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SCHEMA = """
-- Users
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT NOT NULL,
    full_name       TEXT NOT NULL,
    role            TEXT NOT NULL CHECK(role IN ('user','management','admin')),
    is_active       INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Releases (top of the hierarchy)
CREATE TABLE IF NOT EXISTS releases (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'planned'
                CHECK(status IN ('planned','in_progress','released','cancelled')),
    target_date TEXT,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_releases_status ON releases(status);

-- Features (belong to a release)
CREATE TABLE IF NOT EXISTS features (
    id          INTEGER PRIMARY KEY,
    release_id  INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'draft'
                CHECK(status IN ('draft','in_review','in_sprint','released','cancelled')),
    target_date TEXT,                       -- optional ISO date YYYY-MM-DD
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_features_release ON features(release_id);
CREATE INDEX IF NOT EXISTS idx_features_status ON features(status);

-- Per-user feature access grants — admin grants user access to features beyond
-- the ones they own. Used at the resource-access check.
CREATE TABLE IF NOT EXISTS user_feature_access (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    feature_id INTEGER NOT NULL REFERENCES features(id) ON DELETE CASCADE,
    granted_by INTEGER NOT NULL REFERENCES users(id),
    granted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, feature_id)
);

-- Threat models — owned by a user, belong to a feature
CREATE TABLE IF NOT EXISTS threat_models (
    id          INTEGER PRIMARY KEY,
    feature_id  INTEGER NOT NULL REFERENCES features(id) ON DELETE CASCADE,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    name        TEXT NOT NULL,
    description TEXT,
    system_json TEXT NOT NULL,                          -- the system model dict
    analysis_json TEXT,                                 -- last analysis result, nullable
    methodologies TEXT NOT NULL DEFAULT '["stride"]',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tm_owner ON threat_models(owner_id);
CREATE INDEX IF NOT EXISTS idx_tm_feature ON threat_models(feature_id);

-- Per-threat status tracking. One row per (threat_model, threat_id).
-- Threat IDs are stable across analyses.
CREATE TABLE IF NOT EXISTS threat_status (
    threat_model_id INTEGER NOT NULL REFERENCES threat_models(id) ON DELETE CASCADE,
    threat_id       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK(status IN ('open','in_progress','mitigated','accepted_risk','false_positive')),
    notes           TEXT,
    updated_by      INTEGER REFERENCES users(id),
    updated_at      TEXT NOT NULL,
    -- Closure tracking metadata
    first_opened_at TEXT,                          -- when status row was first created
    closed_at       TEXT,                          -- when first moved to a terminal state
    closed_by       INTEGER REFERENCES users(id),  -- who closed it
    time_to_closure_seconds INTEGER,               -- closed_at - first_opened_at (seconds)
    PRIMARY KEY (threat_model_id, threat_id)
);

-- Status change history — every transition appended for audit
CREATE TABLE IF NOT EXISTS threat_status_history (
    id              INTEGER PRIMARY KEY,
    threat_model_id INTEGER NOT NULL REFERENCES threat_models(id) ON DELETE CASCADE,
    threat_id       TEXT NOT NULL,
    from_status     TEXT,
    to_status       TEXT NOT NULL,
    notes           TEXT,
    changed_by      INTEGER REFERENCES users(id),
    changed_by_email TEXT,
    changed_at      TEXT NOT NULL,
    duration_in_prev_seconds INTEGER     -- seconds spent in the from_status before this change
);
CREATE INDEX IF NOT EXISTS idx_tsh_tm ON threat_status_history(threat_model_id);
CREATE INDEX IF NOT EXISTS idx_tsh_threat ON threat_status_history(threat_model_id, threat_id);

-- Audit log — every authz decision and sensitive action
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    user_id     INTEGER REFERENCES users(id),
    user_email  TEXT,
    action      TEXT NOT NULL,
    resource_type TEXT,
    resource_id INTEGER,
    decision    TEXT NOT NULL CHECK(decision IN ('grant','deny','attempt')),
    ip_address  TEXT,
    user_agent  TEXT,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- Refresh tokens — server-side stored, hashed. Allows revocation.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_hash ON refresh_tokens(token_hash);
"""


def _run_migration(sql: str):
    """Run an idempotent CREATE TABLE/INDEX migration script."""
    with db_conn(write=True) as c:
        c.executescript(sql)


def init_db():
    """Create tables if they don't exist. Idempotent — safe to call on every startup."""
    with db_conn(write=True) as c:
        c.executescript(SCHEMA)
        # Lightweight migrations for existing DBs
        _ensure_column(c, "features", "target_date", "TEXT")
    # Extra feature tables added after the base schema shipped
    _run_migration(INIT_SQL_CUSTOM_RULES)
    _run_migration(INIT_SQL_SHARE_TOKENS)
    _create_seed_admin_if_missing()


def _ensure_column(c, table: str, column: str, type_decl: str):
    """Add a column to an existing table if it doesn't exist (SQLite idempotent migration)."""
    cols = c.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {row["name"] if hasattr(row, "keys") else row[1] for row in cols}
    if column not in existing:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {type_decl}")


def _create_seed_admin_if_missing():
    """If INITIAL_ADMIN_EMAIL + INITIAL_ADMIN_PASSWORD are set in env and no admin
    exists yet, create one. Used for first-run bootstrapping."""
    email = os.getenv("INITIAL_ADMIN_EMAIL")
    password = os.getenv("INITIAL_ADMIN_PASSWORD")
    if not email or not password:
        return
    with db_conn() as c:
        existing = c.execute(
            "SELECT id FROM users WHERE role='admin' LIMIT 1"
        ).fetchone()
        if existing:
            return
    # Avoid circular import — import bcrypt here
    import bcrypt
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    with db_conn(write=True) as c:
        c.execute(
            "INSERT INTO users (email, password_hash, full_name, role, created_at, updated_at) "
            "VALUES (?, ?, ?, 'admin', ?, ?)",
            (email, pw_hash, "Initial Admin", _now(), _now())
        )
    print(f"[db] Seeded initial admin: {email}")


# ---------------------------------------------------------------------------
# Audit log helper — used by every authz decision
# ---------------------------------------------------------------------------
def audit(
    user_id: int | None,
    user_email: str | None,
    action: str,
    decision: str,                 # 'grant' / 'deny' / 'attempt'
    resource_type: str | None = None,
    resource_id: int | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    detail: str | None = None,
):
    """Write an audit log entry. NEVER let audit failures break the request."""
    try:
        with db_conn(write=True) as c:
            c.execute(
                "INSERT INTO audit_log (timestamp, user_id, user_email, action, "
                "resource_type, resource_id, decision, ip_address, user_agent, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (_now(), user_id, user_email, action, resource_type, resource_id,
                 decision, ip_address, user_agent, detail)
            )
    except Exception as e:
        # If we can't audit, log to stderr but don't fail the request
        print(f"[audit] FAILED to log: {action} {decision} for {user_email}: {e}")
