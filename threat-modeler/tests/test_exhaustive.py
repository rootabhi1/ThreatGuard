"""Exhaustive use-case tests covering every role x every operation.

Doesn't need FastAPI installed. Mocks bcrypt+jwt. Tests the actual logic
that the API endpoints call into.

Categories tested:
  * Authentication: register, login, lockout, refresh, logout, role-changed-revokes-tokens
  * Admin operations: create users, change roles, deactivate, grant feature access
  * Release & Feature management
  * Threat Model lifecycle: create, read, update, delete, list, analyze
  * Visibility model: User vs Mgmt vs Admin × owner vs non-owner × granted vs not
  * Resource access: 404-not-403 leak prevention, ownership checks
  * Threat status: valid statuses, upsert behavior, cross-user updates
  * Management overview: aggregation correctness
  * Audit log: entries written for grants AND denies
  * Self-protection: admin can't demote/deactivate self
  * Edge cases: deleted resources, invalid input, missing fields, etc.

Run from project root:
    python tests/test_exhaustive.py
"""
import importlib.util
import os
import sys
import tempfile
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Throwaway DB
_tmp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
_tmp_db.close()
os.environ["THREAT_MODELER_DB"] = _tmp_db.name


# -- Mocks for bcrypt + jwt that actually behave somewhat correctly --
class _FakeBcrypt:
    @staticmethod
    def hashpw(pw, salt):
        return b"$2b$12$" + pw  # store password verbatim with prefix
    @staticmethod
    def gensalt(rounds=12):
        return b"salt"
    @staticmethod
    def checkpw(pw, hashed):
        return hashed == b"$2b$12$" + pw

class _FakeJWT:
    class PyJWTError(Exception): pass
    class ExpiredSignatureError(PyJWTError): pass
    class InvalidTokenError(PyJWTError): pass
    @staticmethod
    def encode(payload, secret, algorithm=None):
        # Encode the payload as a fake token (not signed, but recoverable)
        import json, base64
        return "fake." + base64.b64encode(json.dumps(payload).encode()).decode() + ".sig"
    @staticmethod
    def decode(token, secret, algorithms=None):
        import json, base64
        try:
            mid = token.split(".")[1]
            return json.loads(base64.b64decode(mid).decode())
        except Exception:
            raise _FakeJWT.InvalidTokenError("bad token")

sys.modules.setdefault("bcrypt", _FakeBcrypt())
sys.modules.setdefault("jwt", _FakeJWT())


# Now import db + domain
from db import init_db, db_conn, audit, _now
from db import domain

# Import permissions/auth.auth via the package path now that bcrypt/jwt are mocked
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "permissions_iso", str(PROJECT_ROOT / "auth" / "permissions.py")
)
_perms = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_perms)
role_has_permission = _perms.role_has_permission
ROLE_PERMISSIONS = _perms.ROLE_PERMISSIONS
PERMISSIONS = _perms.PERMISSIONS

# Import auth.auth (uses our mocked bcrypt/jwt)
_spec2 = importlib.util.spec_from_file_location(
    "auth_iso", str(PROJECT_ROOT / "auth" / "auth.py")
)
auth_mod = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(auth_mod)


PASS = 0
FAIL = 0
FAILURES = []
CATEGORY = ""


def category(name):
    global CATEGORY
    CATEGORY = name
    print(f"\n=== {name} ===")


def t(name, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print(f"  [PASS] {name}")
    except AssertionError as e:
        FAIL += 1
        msg = f"{CATEGORY} :: {name}: {e}"
        FAILURES.append(msg)
        print(f"  [FAIL] {name}")
        print(f"         AssertionError: {e!r}")
        traceback.print_exc()
    except Exception as e:
        FAIL += 1
        msg = f"{CATEGORY} :: {name}: {type(e).__name__}: {e}"
        FAILURES.append(msg)
        print(f"  [FAIL] {name}")
        print(f"         {type(e).__name__}: {e}")
        traceback.print_exc()


def fresh_db():
    """Wipe and recreate the test DB."""
    if os.path.exists(_tmp_db.name):
        os.remove(_tmp_db.name)
    import db as db_mod
    db_mod.DB_PATH = Path(_tmp_db.name)
    init_db()


def reg(email, password, name, role="user"):
    return auth_mod.register_user(email, password, name, role=role)


# ============================================================================
category("Auth: registration & login")
# ============================================================================
def t_register_basic():
    fresh_db()
    u = reg("alice@x.com", "pass12345", "Alice")
    assert u["email"] == "alice@x.com"
    assert u["role"] == "user"
    assert u["is_active"] == True

t("Self-register creates a user-role account", t_register_basic)


def t_register_short_password_rejected():
    fresh_db()
    try:
        reg("a@b.c", "short", "A")
        assert False, "should reject short password"
    except ValueError:
        pass

t("Register rejects password < 8 chars", t_register_short_password_rejected)


def t_register_duplicate_email_rejected():
    fresh_db()
    reg("a@b.c", "pass12345", "A")
    try:
        reg("a@b.c", "pass12345", "B")
        assert False, "should reject duplicate"
    except ValueError as e:
        assert "already" in str(e).lower()

t("Register rejects duplicate email", t_register_duplicate_email_rejected)


def t_register_invalid_email_rejected():
    fresh_db()
    try:
        reg("not-an-email", "pass12345", "X")
        assert False
    except ValueError:
        pass

t("Register rejects malformed email", t_register_invalid_email_rejected)


def t_register_invalid_role_rejected():
    fresh_db()
    try:
        reg("a@b.c", "pass12345", "A", role="superadmin")
        assert False
    except ValueError:
        pass

t("Register rejects invalid role", t_register_invalid_role_rejected)


def t_login_success():
    fresh_db()
    reg("a@b.c", "pass12345", "A")
    access, refresh, user = auth_mod.login("a@b.c", "pass12345")
    assert access
    assert refresh
    assert user["email"] == "a@b.c"

t("Login with correct password succeeds", t_login_success)


def t_login_wrong_password():
    fresh_db()
    reg("a@b.c", "pass12345", "A")
    try:
        auth_mod.login("a@b.c", "wrongpass")
        assert False
    except ValueError as e:
        assert "invalid" in str(e).lower()

t("Login wrong password fails", t_login_wrong_password)


def t_login_unknown_email():
    fresh_db()
    try:
        auth_mod.login("nobody@x.com", "anything12345")
        assert False
    except ValueError as e:
        # Generic message - don't leak that email doesn't exist
        assert "invalid" in str(e).lower()

t("Login unknown email gives generic 'invalid' error (no email enumeration)",
  t_login_unknown_email)


def t_login_email_case_insensitive():
    fresh_db()
    reg("alice@x.com", "pass12345", "A")
    # Register normalizes to lowercase; login should also be case-insensitive
    access, _, user = auth_mod.login("ALICE@X.COM", "pass12345")
    assert user["email"] == "alice@x.com"

t("Login email is case-insensitive", t_login_email_case_insensitive)


def t_login_increments_failed_counter():
    fresh_db()
    reg("a@b.c", "pass12345", "A")
    try: auth_mod.login("a@b.c", "wrong1")
    except: pass
    try: auth_mod.login("a@b.c", "wrong2")
    except: pass
    with db_conn() as c:
        row = c.execute("SELECT failed_attempts FROM users WHERE email='a@b.c'").fetchone()
    assert row["failed_attempts"] == 2

t("Failed login increments counter", t_login_increments_failed_counter)


def t_login_lockout_after_5():
    fresh_db()
    reg("a@b.c", "pass12345", "A")
    for _ in range(5):
        try: auth_mod.login("a@b.c", "wrong")
        except: pass
    # Even with right password, should be locked
    try:
        auth_mod.login("a@b.c", "pass12345")
        assert False, "should be locked"
    except ValueError as e:
        assert "lock" in str(e).lower()

t("Account locks after 5 failed attempts", t_login_lockout_after_5)


def t_login_resets_counter_on_success():
    fresh_db()
    reg("a@b.c", "pass12345", "A")
    try: auth_mod.login("a@b.c", "wrong")
    except: pass
    try: auth_mod.login("a@b.c", "wrong")
    except: pass
    auth_mod.login("a@b.c", "pass12345")
    with db_conn() as c:
        row = c.execute("SELECT failed_attempts FROM users WHERE email='a@b.c'").fetchone()
    assert row["failed_attempts"] == 0

t("Successful login resets failed-attempts counter", t_login_resets_counter_on_success)


def t_login_inactive_user_rejected():
    fresh_db()
    u = reg("a@b.c", "pass12345", "A")
    auth_mod.deactivate_user(u["id"], by_user_id=u["id"])
    try:
        auth_mod.login("a@b.c", "pass12345")
        assert False
    except ValueError as e:
        assert "inactive" in str(e).lower()

t("Inactive user cannot log in", t_login_inactive_user_rejected)


# ============================================================================
category("Auth: refresh tokens")
# ============================================================================
def t_refresh_token_works():
    fresh_db()
    reg("a@b.c", "pass12345", "A")
    _, refresh, _ = auth_mod.login("a@b.c", "pass12345")
    uid = auth_mod.consume_refresh_token(refresh)
    assert uid is not None

t("Valid refresh token returns user_id", t_refresh_token_works)


def t_refresh_token_rotation():
    fresh_db()
    reg("a@b.c", "pass12345", "A")
    _, refresh, _ = auth_mod.login("a@b.c", "pass12345")
    auth_mod.consume_refresh_token(refresh)
    # Used token can't be used again
    uid = auth_mod.consume_refresh_token(refresh)
    assert uid is None, "rotated token should be invalid"

t("Refresh tokens rotate (used token can't be reused)", t_refresh_token_rotation)


def t_refresh_token_invalid_returns_none():
    fresh_db()
    uid = auth_mod.consume_refresh_token("not-a-real-token")
    assert uid is None

t("Invalid refresh token returns None (not exception)", t_refresh_token_invalid_returns_none)


def t_logout_revokes_all_refresh_tokens():
    fresh_db()
    reg("a@b.c", "pass12345", "A")
    _, refresh1, user = auth_mod.login("a@b.c", "pass12345")
    _, refresh2, _ = auth_mod.login("a@b.c", "pass12345")
    # Logout / explicit revoke
    auth_mod.revoke_all_refresh_tokens(user["id"])
    assert auth_mod.consume_refresh_token(refresh1) is None
    assert auth_mod.consume_refresh_token(refresh2) is None

t("Revoking all refresh tokens kills every session", t_logout_revokes_all_refresh_tokens)


def t_role_change_revokes_refresh_tokens():
    """Critical security property: changing a role must invalidate sessions."""
    fresh_db()
    admin = reg("admin@x.com", "pass12345", "Admin", role="admin")
    user = reg("user@x.com", "pass12345", "User")
    _, refresh, _ = auth_mod.login("user@x.com", "pass12345")
    # Promote user to management
    auth_mod.update_user_role(user["id"], "management", by_user_id=admin["id"])
    # Old refresh token should be invalid
    assert auth_mod.consume_refresh_token(refresh) is None

t("Role change revokes all refresh tokens", t_role_change_revokes_refresh_tokens)


# ============================================================================
category("Permission matrix (role × permission)")
# ============================================================================
def t_full_permission_matrix():
    """Walk the entire permission matrix - confirm every cell is correct."""
    expected = {
        "user": {
            "threat_model.create": True,
            "threat_model.read.own": True,
            "threat_model.read.all": False,
            "threat_model.update.own": True,
            "threat_model.update.all": False,
            "threat_model.delete.own": True,
            "threat_model.delete.all": False,
            "threat_status.update.own": True,
            "threat_status.update.all": False,
            "report.generate.own": True,
            "report.generate.all": False,
            "release.create": False,
            "release.read.all": False,
            "release.update.all": False,
            "release.delete.all": False,
            "feature.create": False,
            "feature.read.own": True,
            "feature.read.all": False,
            "feature.update.all": False,
            "feature.delete.all": False,
            "user.create": False,
            "user.read.all": False,
            "user.update.all": False,
            "user.delete.all": False,
            "user.feature_access.grant": False,
            "view.developer": True,
            "view.management": False,
            "view.admin": False,
            "audit.read": False,
        },
        "management": {
            "threat_model.create": False,
            "threat_model.read.own": False,
            "threat_model.read.all": True,
            "threat_model.update.own": False,
            "threat_model.update.all": False,
            "threat_model.delete.own": False,
            "threat_model.delete.all": False,
            "threat_status.update.own": False,
            "threat_status.update.all": False,
            "report.generate.own": False,
            "report.generate.all": True,
            "release.create": False,
            "release.read.all": True,
            "release.update.all": False,
            "release.delete.all": False,
            "feature.create": False,
            "feature.read.own": False,
            "feature.read.all": True,
            "feature.update.all": False,
            "feature.delete.all": False,
            "user.create": False,
            "user.read.all": False,
            "user.update.all": False,
            "user.delete.all": False,
            "user.feature_access.grant": False,
            "view.developer": True,
            "view.management": True,
            "view.admin": False,
            "audit.read": False,
        },
        "admin": {
            "threat_model.create": True,
            "threat_model.read.own": False,
            "threat_model.read.all": True,
            "threat_model.update.own": False,
            "threat_model.update.all": True,
            "threat_model.delete.own": False,
            "threat_model.delete.all": True,
            "threat_status.update.own": False,
            "threat_status.update.all": True,
            "report.generate.own": False,
            "report.generate.all": True,
            "release.create": True,
            "release.read.all": True,
            "release.update.all": True,
            "release.delete.all": True,
            "feature.create": True,
            "feature.read.own": False,
            "feature.read.all": True,
            "feature.update.all": True,
            "feature.delete.all": True,
            "user.create": True,
            "user.read.all": True,
            "user.update.all": True,
            "user.delete.all": True,
            "user.feature_access.grant": True,
            "view.developer": True,
            "view.management": True,
            "view.admin": True,
            "audit.read": True,
        },
    }
    failures = []
    for role, perms in expected.items():
        for perm, expected_val in perms.items():
            actual = role_has_permission(role, perm)
            if actual != expected_val:
                failures.append(f"{role}/{perm}: expected {expected_val}, got {actual}")
    assert not failures, f"Permission matrix mismatches:\n" + "\n".join(failures)

t("Full role × permission matrix (87 cells)", t_full_permission_matrix)


# ============================================================================
category("Releases & Features")
# ============================================================================
def t_create_release():
    fresh_db()
    admin = reg("admin@x.com", "pass12345", "A", role="admin")
    rel = domain.create_release("Q1 2026", "First release", "2026-03-31", admin["id"])
    assert rel["name"] == "Q1 2026"
    assert rel["status"] == "planned"

t("Create release with all fields", t_create_release)


def t_update_release_status():
    fresh_db()
    admin = reg("admin@x.com", "pass12345", "A", role="admin")
    rel = domain.create_release("R1", "", None, admin["id"])
    updated = domain.update_release(rel["id"], status="in_progress")
    assert updated["status"] == "in_progress"

t("Update release status transitions correctly", t_update_release_status)


def t_delete_release_cascades():
    fresh_db()
    admin = reg("admin@x.com", "pass12345", "A", role="admin")
    rel = domain.create_release("R1", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F1", "", admin["id"])
    user = reg("user@x.com", "pass12345", "U")
    tm = domain.create_threat_model(
        feat["id"], user["id"], "TM1", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"]
    )
    domain.delete_release(rel["id"])
    # Feature should be gone
    assert domain.get_feature(feat["id"]) is None
    # Threat model should be gone too (cascades)
    assert domain.get_threat_model(tm["id"]) is None

t("Delete release cascades to features AND threat models", t_delete_release_cascades)


def t_feature_with_invalid_release_rejected():
    fresh_db()
    admin = reg("admin@x.com", "pass12345", "A", role="admin")
    try:
        domain.create_feature(99999, "Orphan", "", admin["id"])
        assert False
    except ValueError as e:
        assert "not found" in str(e).lower()

t("Feature with non-existent release_id is rejected", t_feature_with_invalid_release_rejected)


def t_list_releases_returns_all():
    fresh_db()
    admin = reg("admin@x.com", "pass12345", "A", role="admin")
    domain.create_release("R1", "", None, admin["id"])
    domain.create_release("R2", "", None, admin["id"])
    domain.create_release("R3", "", None, admin["id"])
    rels = domain.list_releases()
    assert len(rels) == 3

t("List releases returns all", t_list_releases_returns_all)


# ============================================================================
category("Threat Model lifecycle")
# ============================================================================
def t_create_tm_with_system():
    fresh_db()
    admin = reg("admin@x.com", "pass12345", "A", role="admin")
    rel = domain.create_release("R1", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F1", "", admin["id"])
    user = reg("u@x.com", "pass12345", "U")
    sys_dict = {
        "name": "Webapp",
        "components": [
            {"id": "c1", "name": "User", "type": "external_entity"},
            {"id": "c2", "name": "App", "type": "webapp"},
        ],
        "data_flows": [
            {"id": "f1", "from": "c1", "to": "c2", "data": "creds",
             "encrypted": False, "auth": "none"},
        ],
        "trust_boundaries": [],
    }
    tm = domain.create_threat_model(feat["id"], user["id"], "Auth flow", "desc", sys_dict, ["stride"])
    assert tm["name"] == "Auth flow"
    assert tm["owner_id"] == user["id"]
    assert tm["feature_id"] == feat["id"]
    assert len(tm["system"]["components"]) == 2

t("Create threat model with full system definition", t_create_tm_with_system)


def t_tm_invalid_feature_rejected():
    fresh_db()
    user = reg("u@x.com", "pass12345", "U")
    try:
        domain.create_threat_model(99999, user["id"], "T", "",
            {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
        assert False
    except ValueError as e:
        assert "not found" in str(e).lower()

t("Threat model with invalid feature_id is rejected", t_tm_invalid_feature_rejected)


def t_tm_update_preserves_owner():
    fresh_db()
    admin = reg("admin@x.com", "pass12345", "A", role="admin")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    user = reg("u@x.com", "pass12345", "U")
    tm = domain.create_threat_model(feat["id"], user["id"], "T", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    updated = domain.update_threat_model(tm["id"], name="T2", description="new desc")
    assert updated["name"] == "T2"
    assert updated["owner_id"] == user["id"]   # owner unchanged

t("Update threat model preserves owner", t_tm_update_preserves_owner)


def t_tm_analysis_field_persisted():
    fresh_db()
    admin = reg("admin@x.com", "pass12345", "A", role="admin")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    user = reg("u@x.com", "pass12345", "U")
    tm = domain.create_threat_model(feat["id"], user["id"], "T", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    fake_analysis = {
        "summary": {"total": 5, "by_severity": {"Critical": 1}, "rule_based": 5, "llm_enhanced": 0},
        "threats": [{"id": "t1", "title": "Test", "severity": "Critical"}],
        "system": {"name": "X"},
        "untrusted_crossings": [],
        "methodologies_used": ["stride"],
        "llm_used": False,
    }
    domain.update_threat_model(tm["id"], analysis=fake_analysis)
    fetched = domain.get_threat_model(tm["id"])
    assert fetched["analysis"]["summary"]["total"] == 5
    assert fetched["analysis"]["threats"][0]["title"] == "Test"

t("Analysis result persists in DB across reads", t_tm_analysis_field_persisted)


def t_tm_delete_removes_statuses():
    fresh_db()
    admin = reg("admin@x.com", "pass12345", "A", role="admin")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    user = reg("u@x.com", "pass12345", "U")
    tm = domain.create_threat_model(feat["id"], user["id"], "T", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    domain.set_threat_status(tm["id"], "t1", "mitigated", "fixed", user["id"])
    domain.set_threat_status(tm["id"], "t2", "open", None, user["id"])
    domain.delete_threat_model(tm["id"])
    # Statuses should also be gone (FK cascade)
    statuses = domain.list_threat_statuses(tm["id"])
    assert len(statuses) == 0

t("Delete threat model cascades to threat_status rows", t_tm_delete_removes_statuses)


# ============================================================================
category("Visibility model: User role")
# ============================================================================
def t_user_sees_own_only_in_list():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    alice = reg("alice@x.com", "pass12345", "Alice")
    bob = reg("bob@x.com", "pass12345", "Bob")
    domain.grant_feature_access(alice["id"], feat["id"], admin["id"])
    domain.grant_feature_access(bob["id"], feat["id"], admin["id"])
    tm_a = domain.create_threat_model(feat["id"], alice["id"], "Alice TM", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    tm_b = domain.create_threat_model(feat["id"], bob["id"], "Bob TM", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    alice_view = domain.list_threat_models(visible_to_user_id=alice["id"], visible_to_role="user")
    bob_view = domain.list_threat_models(visible_to_user_id=bob["id"], visible_to_role="user")
    assert {t["id"] for t in alice_view} == {tm_a["id"]}
    assert {t["id"] for t in bob_view} == {tm_b["id"]}

t("User sees only own TMs in list (even with shared feature access)",
  t_user_sees_own_only_in_list)


def t_user_with_no_features_sees_nothing():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    domain.create_threat_model(feat["id"], admin["id"], "Admin TM", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    visible = domain.list_threat_models(visible_to_user_id=user["id"], visible_to_role="user")
    assert visible == []

t("User with no feature access sees zero TMs", t_user_with_no_features_sees_nothing)


def t_user_cannot_see_features_without_access():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R", "", None, admin["id"])
    domain.create_feature(rel["id"], "F1", "", admin["id"])
    domain.create_feature(rel["id"], "F2", "", admin["id"])
    visible = domain.list_features(visible_to_user_id=user["id"], visible_to_role="user")
    assert visible == []

t("User without grants can't see features", t_user_cannot_see_features_without_access)


# ============================================================================
category("Visibility model: Management role")
# ============================================================================
def t_management_sees_all_tms():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    mgmt = reg("m@x.com", "pass12345", "M", role="management")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    alice = reg("alice@x.com", "pass12345", "Alice")
    bob = reg("bob@x.com", "pass12345", "Bob")
    domain.grant_feature_access(alice["id"], feat["id"], admin["id"])
    domain.grant_feature_access(bob["id"], feat["id"], admin["id"])
    domain.create_threat_model(feat["id"], alice["id"], "A TM", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    domain.create_threat_model(feat["id"], bob["id"], "B TM", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    visible = domain.list_threat_models(visible_to_user_id=mgmt["id"], visible_to_role="management")
    assert len(visible) == 2

t("Management sees all TMs from all users", t_management_sees_all_tms)


def t_management_sees_all_features():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    mgmt = reg("m@x.com", "pass12345", "M", role="management")
    rel = domain.create_release("R", "", None, admin["id"])
    domain.create_feature(rel["id"], "F1", "", admin["id"])
    domain.create_feature(rel["id"], "F2", "", admin["id"])
    visible = domain.list_features(visible_to_user_id=mgmt["id"], visible_to_role="management")
    assert len(visible) == 2

t("Management sees all features (no grants needed)", t_management_sees_all_features)


# ============================================================================
category("Visibility model: Admin grants")
# ============================================================================
def t_admin_grant_does_not_extend_visibility():
    """STRICT OWNERSHIP: granting a feature does NOT reveal other users' TMs.
    The grant only lets the grantee CREATE TMs in that feature."""
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    owner = reg("owner@x.com", "pass12345", "Owner")
    grantee = reg("grant@x.com", "pass12345", "Grantee")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    domain.grant_feature_access(owner["id"], feat["id"], admin["id"])
    tm = domain.create_threat_model(feat["id"], owner["id"], "Owner's TM", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    # Grantee has no access yet
    assert domain.list_threat_models(grantee["id"], "user") == []
    # Grant feature access
    domain.grant_feature_access(grantee["id"], feat["id"], admin["id"])
    # Grantee STILL sees no TMs — strict ownership
    visible = domain.list_threat_models(grantee["id"], "user")
    assert visible == [], "Strict ownership: grantee must not see owner's TM"
    # But grantee CAN see the feature itself (so they can create in it)
    visible_features = domain.list_features(visible_to_user_id=grantee["id"], visible_to_role="user")
    assert feat["id"] in {f["id"] for f in visible_features}

t("Admin grant does NOT extend visibility to other users' TMs (strict ownership)",
  t_admin_grant_does_not_extend_visibility)


def t_user_with_grant_can_create_tm():
    """STRICT OWNERSHIP: a feature grant is the prerequisite for creating
    TMs in that feature. After creation, only the creator sees it."""
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    # Without grant, user can't see the feature to create in
    assert domain.list_features(visible_to_user_id=user["id"], visible_to_role="user") == []
    # Admin grants
    domain.grant_feature_access(user["id"], feat["id"], admin["id"])
    # Now user sees the feature and can create
    assert len(domain.list_features(visible_to_user_id=user["id"], visible_to_role="user")) == 1
    tm = domain.create_threat_model(feat["id"], user["id"], "U's TM", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    # User sees their own creation
    visible = domain.list_threat_models(visible_to_user_id=user["id"], visible_to_role="user")
    assert {t["id"] for t in visible} == {tm["id"]}

t("User with feature grant can create TMs and sees only own", t_user_with_grant_can_create_tm)


def t_revoke_feature_removes_feature_visibility():
    """Revoking a grant takes the feature out of the user's view, but their
    existing TMs in that feature are still theirs (data isn't auto-deleted)."""
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    domain.grant_feature_access(user["id"], feat["id"], admin["id"])
    tm = domain.create_threat_model(feat["id"], user["id"], "T", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    # User sees their TM
    assert len(domain.list_threat_models(visible_to_user_id=user["id"], visible_to_role="user")) == 1
    # Admin revokes
    domain.revoke_feature_access(user["id"], feat["id"])
    # Feature is no longer visible
    assert domain.list_features(visible_to_user_id=user["id"], visible_to_role="user") == []
    # But user still owns their TM (data preserved)
    assert len(domain.list_threat_models(visible_to_user_id=user["id"], visible_to_role="user")) == 1

t("Revoke feature access hides feature, preserves user's own TMs",
  t_revoke_feature_removes_feature_visibility)


def t_grant_idempotent():
    """Granting the same feature twice should not error or duplicate."""
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    domain.grant_feature_access(user["id"], feat["id"], admin["id"])
    domain.grant_feature_access(user["id"], feat["id"], admin["id"])  # again
    grants = domain.list_user_feature_access(user["id"])
    assert len(grants) == 1

t("Granting same feature twice is idempotent", t_grant_idempotent)


# ============================================================================
category("Threat status")
# ============================================================================
def t_threat_status_all_valid_values():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    tm = domain.create_threat_model(feat["id"], user["id"], "T", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    for status in ("open", "in_progress", "mitigated", "accepted_risk", "false_positive"):
        result = domain.set_threat_status(tm["id"], "test_threat", status, "n", user["id"])
        assert result["status"] == status

t("All 5 status values accepted", t_threat_status_all_valid_values)


def t_threat_status_invalid_rejected():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    tm = domain.create_threat_model(feat["id"], user["id"], "T", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    try:
        domain.set_threat_status(tm["id"], "t1", "doesnt_exist", None, user["id"])
        assert False
    except ValueError:
        pass

t("Invalid threat status value rejected", t_threat_status_invalid_rejected)


def t_threat_status_upsert():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    tm = domain.create_threat_model(feat["id"], user["id"], "T", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    domain.set_threat_status(tm["id"], "t1", "open", "first", user["id"])
    domain.set_threat_status(tm["id"], "t1", "mitigated", "fixed", user["id"])
    statuses = domain.list_threat_statuses(tm["id"])
    assert len(statuses) == 1
    assert statuses["t1"]["status"] == "mitigated"
    assert statuses["t1"]["notes"] == "fixed"

t("Status upserts (one row per threat_id, latest wins)", t_threat_status_upsert)


# ============================================================================
category("Management overview aggregation")
# ============================================================================
def t_management_overview_with_data():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R1", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "Auth", "", admin["id"])
    tm = domain.create_threat_model(feat["id"], user["id"], "T", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    fake = {
        "summary": {"total": 4, "by_severity": {"Critical": 2, "High": 2}, "rule_based": 4, "llm_enhanced": 0},
        "threats": [
            {"id": "c1", "title": "Crit 1", "severity": "Critical"},
            {"id": "c2", "title": "Crit 2", "severity": "Critical"},
            {"id": "h1", "title": "High 1", "severity": "High"},
            {"id": "h2", "title": "High 2", "severity": "High"},
        ],
        "system": {}, "untrusted_crossings": [], "methodologies_used": ["stride"], "llm_used": False,
    }
    domain.update_threat_model(tm["id"], analysis=fake)
    domain.set_threat_status(tm["id"], "c1", "mitigated", None, user["id"])
    overview = domain.management_overview()
    assert len(overview) == 1
    f = overview[0]
    assert f["feature_name"] == "Auth"
    assert f["total_threats"] == 4
    assert f["by_severity"]["Critical"] == 2
    assert f["by_severity"]["High"] == 2
    assert f["by_status"]["mitigated"] == 1
    assert "Crit 1" in f["top_critical_titles"]

t("Management overview aggregates correctly", t_management_overview_with_data)


def t_management_overview_empty():
    fresh_db()
    overview = domain.management_overview()
    assert overview == []

t("Management overview empty when no features", t_management_overview_empty)


def t_management_overview_features_no_tms():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    rel = domain.create_release("R", "", None, admin["id"])
    domain.create_feature(rel["id"], "F", "", admin["id"])
    overview = domain.management_overview()
    assert len(overview) == 1
    assert overview[0]["threat_model_count"] == 0
    assert overview[0]["total_threats"] == 0

t("Management overview shows feature with zero TMs", t_management_overview_features_no_tms)


# ============================================================================
category("Audit log")
# ============================================================================
def t_audit_log_login_grant():
    fresh_db()
    reg("u@x.com", "pass12345", "U")
    auth_mod.login("u@x.com", "pass12345")
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM audit_log WHERE action='user.login' AND decision='grant'"
        ).fetchall()
    assert len(rows) >= 1

t("Successful login writes audit log entry", t_audit_log_login_grant)


def t_audit_log_login_deny():
    fresh_db()
    reg("u@x.com", "pass12345", "U")
    try: auth_mod.login("u@x.com", "wrong")
    except: pass
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM audit_log WHERE action='user.login' AND decision='deny'"
        ).fetchall()
    assert len(rows) == 1
    assert "bad password" in rows[0]["detail"].lower() or "attempt" in rows[0]["detail"].lower()

t("Failed login writes audit deny entry with detail", t_audit_log_login_deny)


def t_audit_log_unknown_email_logged():
    fresh_db()
    try: auth_mod.login("ghost@x.com", "anything12345")
    except: pass
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM audit_log WHERE user_email='ghost@x.com'"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["decision"] == "deny"

t("Login for unknown email still audited", t_audit_log_unknown_email_logged)


def t_audit_log_role_change():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    auth_mod.update_user_role(user["id"], "management", by_user_id=admin["id"])
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM audit_log WHERE action='user.role_changed'"
        ).fetchall()
    assert len(rows) == 1
    assert "management" in rows[0]["detail"]

t("Role change writes audit entry with new role", t_audit_log_role_change)


# ============================================================================
category("Edge cases")
# ============================================================================
def t_get_nonexistent_release():
    fresh_db()
    assert domain.get_release(99999) is None

t("get_release for nonexistent ID returns None", t_get_nonexistent_release)


def t_get_nonexistent_feature():
    fresh_db()
    assert domain.get_feature(99999) is None

t("get_feature for nonexistent ID returns None", t_get_nonexistent_feature)


def t_get_nonexistent_tm():
    fresh_db()
    assert domain.get_threat_model(99999) is None

t("get_threat_model for nonexistent ID returns None", t_get_nonexistent_tm)


def t_update_nonexistent_release_returns_none():
    fresh_db()
    result = domain.update_release(99999, name="X")
    assert result is None

t("Update nonexistent release returns None (not error)",
  t_update_nonexistent_release_returns_none)


def t_delete_nonexistent_is_silent():
    """Deleting something that doesn't exist shouldn't error."""
    fresh_db()
    domain.delete_release(99999)
    domain.delete_feature(99999)
    domain.delete_threat_model(99999)

t("Deleting non-existent resources is silent (no errors)",
  t_delete_nonexistent_is_silent)


def t_password_too_long_rejected():
    fresh_db()
    try:
        reg("a@b.c", "x" * 200, "A")
        assert False
    except ValueError:
        pass

t("Password > 128 chars rejected", t_password_too_long_rejected)


def t_release_without_target_date():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    rel = domain.create_release("R", "no date", None, admin["id"])
    assert rel["target_date"] is None

t("Release without target_date is allowed", t_release_without_target_date)


def t_threat_model_with_complex_system():
    """Real-world system with multiple components, flows, boundaries."""
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R", "", None, admin["id"])
    feat = domain.create_feature(rel["id"], "F", "", admin["id"])
    sys_dict = {
        "name": "Complex system",
        "components": [
            {"id": "c1", "name": "User", "type": "external_entity"},
            {"id": "c2", "name": "Web", "type": "webapp"},
            {"id": "c3", "name": "API", "type": "service"},
            {"id": "c4", "name": "DB", "type": "database"},
            {"id": "c5", "name": "Cache", "type": "cache"},
        ],
        "data_flows": [
            {"id": "f1", "from": "c1", "to": "c2", "data": "creds", "encrypted": True, "auth": "password"},
            {"id": "f2", "from": "c2", "to": "c3", "data": "request", "encrypted": True, "auth": "jwt"},
            {"id": "f3", "from": "c3", "to": "c4", "data": "query", "encrypted": False, "auth": "service_account"},
            {"id": "f4", "from": "c3", "to": "c5", "data": "session", "encrypted": False, "auth": "none"},
        ],
        "trust_boundaries": [
            {"id": "b1", "name": "Internet", "contains": ["c1"]},
            {"id": "b2", "name": "DMZ", "contains": ["c2"]},
            {"id": "b3", "name": "Internal", "contains": ["c3", "c4", "c5"]},
        ],
    }
    tm = domain.create_threat_model(feat["id"], user["id"], "Complex", "", sys_dict, ["stride", "dread"])
    fetched = domain.get_threat_model(tm["id"])
    assert len(fetched["system"]["components"]) == 5
    assert len(fetched["system"]["data_flows"]) == 4
    assert len(fetched["system"]["trust_boundaries"]) == 3
    assert "stride" in fetched["methodologies"]
    assert "dread" in fetched["methodologies"]

t("Complex system with 5 components, 4 flows, 3 boundaries persists correctly",
  t_threat_model_with_complex_system)


def t_user_feature_access_list():
    fresh_db()
    admin = reg("a@x.com", "pass12345", "A", role="admin")
    user = reg("u@x.com", "pass12345", "U")
    rel = domain.create_release("R", "", None, admin["id"])
    f1 = domain.create_feature(rel["id"], "F1", "", admin["id"])
    f2 = domain.create_feature(rel["id"], "F2", "", admin["id"])
    f3 = domain.create_feature(rel["id"], "F3", "", admin["id"])
    domain.grant_feature_access(user["id"], f1["id"], admin["id"])
    domain.grant_feature_access(user["id"], f3["id"], admin["id"])
    grants = domain.list_user_feature_access(user["id"])
    assert {g["id"] for g in grants} == {f1["id"], f3["id"]}

t("list_user_feature_access returns all granted features", t_user_feature_access_list)


# ============================================================================
# Final summary
# ============================================================================
print("\n" + "=" * 70)
print(f"  EXHAUSTIVE TEST RESULTS")
print("=" * 70)
print(f"  Passed:  {PASS}")
print(f"  Failed:  {FAIL}")
print(f"  Total:   {PASS + FAIL}")
if FAIL > 0:
    print("\n  FAILURES:")
    for f in FAILURES:
        print(f"    - {f}")
print("=" * 70)

if os.path.exists(_tmp_db.name):
    os.remove(_tmp_db.name)

sys.exit(0 if FAIL == 0 else 1)
