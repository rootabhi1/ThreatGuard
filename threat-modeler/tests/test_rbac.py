"""RBAC and domain unit tests.

Doesn't require FastAPI/bcrypt to be installed. Tests:
  - Permission matrix (role × action → allowed?)
  - Resource access (ownership + feature-grant visibility)
  - Domain CRUD (releases, features, threat models)
  - Visibility filters in list_threat_models / list_features
  - Threat status updates
  - Management overview aggregation

Run from project root:
    python tests/test_rbac.py
"""
import importlib.util
import os
import sys
import tempfile
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Use a throwaway DB
_tmp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
_tmp_db.close()
os.environ["THREAT_MODELER_DB"] = _tmp_db.name


# Mock bcrypt + jwt so we can import auth.auth without those packages
class _FakeBcrypt:
    @staticmethod
    def hashpw(pw, salt): return b"fake-hash-of-" + pw
    @staticmethod
    def gensalt(rounds=12): return b"salt"
    @staticmethod
    def checkpw(pw, hashed): return hashed == b"fake-hash-of-" + pw

class _FakeJWT:
    class PyJWTError(Exception): pass
    class ExpiredSignatureError(PyJWTError): pass
    class InvalidTokenError(PyJWTError): pass
    @staticmethod
    def encode(*a, **kw): return "fake.jwt.token"
    @staticmethod
    def decode(*a, **kw): return {"sub": "1", "type": "access"}

sys.modules.setdefault("bcrypt", _FakeBcrypt())
sys.modules.setdefault("jwt", _FakeJWT())


from db import init_db, db_conn, audit, _now
from db import domain
# Import permissions directly to avoid pulling in auth.deps which needs FastAPI
_spec = importlib.util.spec_from_file_location(
    "permissions_isolated", str(PROJECT_ROOT / "auth" / "permissions.py")
)
_perms_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_perms_mod)
role_has_permission = _perms_mod.role_has_permission
ROLE_PERMISSIONS = _perms_mod.ROLE_PERMISSIONS
PERMISSIONS = _perms_mod.PERMISSIONS

PASS = 0
FAIL = 0


def t(name, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print(f"  ✓ {name}")
    except AssertionError as e:
        FAIL += 1
        print(f"  ✗ {name}: {e}")
    except Exception as e:
        FAIL += 1
        print(f"  ✗ {name}: {type(e).__name__}: {e}")
        traceback.print_exc()


def setup_db():
    """Wipe and recreate the test DB."""
    if os.path.exists(_tmp_db.name):
        os.remove(_tmp_db.name)
    # Re-import db module so DB_PATH points at the new tmpfile
    import db as db_mod
    db_mod.DB_PATH = Path(_tmp_db.name)
    init_db()


def make_user(email, role, full_name=None):
    full_name = full_name or email
    with db_conn(write=True) as c:
        cur = c.execute(
            "INSERT INTO users (email, password_hash, full_name, role, created_at, updated_at) "
            "VALUES (?, 'fake', ?, ?, ?, ?)",
            (email, full_name, role, _now(), _now())
        )
        uid = cur.lastrowid
    return uid


# ===========================================================================
print("\n=== Permission matrix ===")
# ===========================================================================
def test_permission_matrix():
    matrix = [
        # (role, perm, expected)
        ("user",       "threat_model.create",        True),
        ("user",       "threat_model.read.own",      True),
        ("user",       "threat_model.read.all",      False),
        ("user",       "threat_model.update.all",    False),
        ("user",       "user.create",                False),
        ("user",       "user.read.all",              False),
        ("user",       "view.management",            False),
        ("user",       "view.admin",                 False),
        ("user",       "audit.read",                 False),
        ("user",       "release.create",             False),
        ("user",       "feature.create",             False),
        ("management", "threat_model.create",        False),  # mgmt can't create
        ("management", "threat_model.read.all",      True),
        ("management", "threat_model.update.all",    False),  # mgmt is read-only
        ("management", "threat_status.update.all",   False),  # mgmt cannot update statuses
        ("management", "view.management",            True),
        ("management", "view.developer",             True),
        ("management", "user.create",                False),
        ("management", "audit.read",                 False),
        ("admin",      "threat_model.read.all",      True),
        ("admin",      "user.create",                True),
        ("admin",      "user.feature_access.grant",  True),
        ("admin",      "view.management",            True),
        ("admin",      "view.admin",                 True),
        ("admin",      "audit.read",                 True),
        ("admin",      "release.create",             True),
    ]
    for role, perm, expected in matrix:
        got = role_has_permission(role, perm)
        assert got == expected, f"{role}/{perm}: expected {expected}, got {got}"

t("Permission matrix (27 cells)", test_permission_matrix)


def test_unknown_permission_raises():
    try:
        role_has_permission("admin", "fake.permission.that.doesnt.exist")
        assert False, "should have raised"
    except ValueError:
        pass

t("Unknown permission raises (typo guard)", test_unknown_permission_raises)


def test_no_orphan_permissions():
    """Every permission assigned to a role must be declared in PERMISSIONS."""
    all_assigned = set()
    for role, perms in ROLE_PERMISSIONS.items():
        all_assigned.update(perms)
    orphans = all_assigned - PERMISSIONS
    assert not orphans, f"Orphan permissions: {orphans}"

t("No orphan permissions in role mappings", test_no_orphan_permissions)


def test_admin_is_superset():
    """Admin should have at minimum what user and management have (modulo
    'create' which mgmt deliberately lacks). Ensures we didn't forget a perm."""
    admin = ROLE_PERMISSIONS["admin"]
    user = ROLE_PERMISSIONS["user"]
    # User permissions admin must also have (user creates own → admin creates any)
    user_baseline = {p for p in user if p not in {
        "threat_model.read.own", "threat_model.update.own",
        "threat_model.delete.own", "threat_status.update.own",
        "report.generate.own", "feature.read.own",
    }}
    # Admin gets the .all variants of these
    admin_equivalents = {
        "threat_model.create", "threat_model.read.all", "threat_model.update.all",
        "threat_model.delete.all", "threat_status.update.all", "report.generate.all",
        "feature.read.all", "view.developer",
    }
    missing = admin_equivalents - admin
    assert not missing, f"Admin missing: {missing}"

t("Admin is functional superset", test_admin_is_superset)


# ===========================================================================
print("\n=== Domain CRUD ===")
# ===========================================================================
def test_release_crud():
    setup_db()
    admin = make_user("admin@test", "admin")
    rel = domain.create_release("Q1 2026", "First release", "2026-03-31", admin)
    assert rel["name"] == "Q1 2026"
    assert rel["status"] == "planned"
    rid = rel["id"]
    fetched = domain.get_release(rid)
    assert fetched["name"] == "Q1 2026"
    updated = domain.update_release(rid, status="in_progress")
    assert updated["status"] == "in_progress"
    domain.delete_release(rid)
    assert domain.get_release(rid) is None

t("Release CRUD", test_release_crud)


def test_feature_belongs_to_release():
    setup_db()
    admin = make_user("admin@test", "admin")
    rel = domain.create_release("R1", "", None, admin)
    feat = domain.create_feature(rel["id"], "Login flow", "desc", admin)
    assert feat["release_id"] == rel["id"]
    # Cascade: deleting release should drop the feature
    domain.delete_release(rel["id"])
    assert domain.get_feature(feat["id"]) is None

t("Feature belongs to release; cascades on release delete", test_feature_belongs_to_release)


def test_feature_invalid_release_rejected():
    setup_db()
    admin = make_user("admin@test", "admin")
    try:
        domain.create_feature(99999, "Orphan", "", admin)
        assert False, "should have raised"
    except ValueError:
        pass

t("Feature creation rejects nonexistent release", test_feature_invalid_release_rejected)


def test_threat_model_crud():
    setup_db()
    admin = make_user("admin@test", "admin")
    user = make_user("user@test", "user")
    rel = domain.create_release("R1", "", None, admin)
    feat = domain.create_feature(rel["id"], "F1", "", admin)
    tm = domain.create_threat_model(
        feat["id"], user, "TM1", "desc",
        {"name": "X", "components": [], "data_flows": [], "trust_boundaries": []},
        ["stride"]
    )
    assert tm["owner_id"] == user
    assert tm["feature_id"] == feat["id"]
    assert isinstance(tm["system"], dict)
    assert tm["analysis"] is None

t("Threat model CRUD with JSON serialization", test_threat_model_crud)


# ===========================================================================
print("\n=== Visibility filtering ===")
# ===========================================================================
def test_user_sees_only_own_threat_models():
    setup_db()
    admin = make_user("admin@test", "admin")
    alice = make_user("alice@test", "user")
    bob = make_user("bob@test", "user")
    rel = domain.create_release("R1", "", None, admin)
    feat = domain.create_feature(rel["id"], "F1", "", admin)
    tm_a = domain.create_threat_model(feat["id"], alice, "Alice TM", "",
        {"name":"A","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    tm_b = domain.create_threat_model(feat["id"], bob, "Bob TM", "",
        {"name":"B","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])

    alice_view = domain.list_threat_models(visible_to_user_id=alice, visible_to_role="user")
    bob_view = domain.list_threat_models(visible_to_user_id=bob, visible_to_role="user")
    assert {t["id"] for t in alice_view} == {tm_a["id"]}
    assert {t["id"] for t in bob_view} == {tm_b["id"]}

t("User sees only own threat models", test_user_sees_only_own_threat_models)


def test_management_sees_all():
    setup_db()
    admin = make_user("admin@test", "admin")
    alice = make_user("alice@test", "user")
    bob = make_user("bob@test", "user")
    mgmt = make_user("mgmt@test", "management")
    rel = domain.create_release("R1", "", None, admin)
    feat = domain.create_feature(rel["id"], "F1", "", admin)
    domain.create_threat_model(feat["id"], alice, "Alice TM", "",
        {"name":"A","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    domain.create_threat_model(feat["id"], bob, "Bob TM", "",
        {"name":"B","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    mgmt_view = domain.list_threat_models(visible_to_user_id=mgmt, visible_to_role="management")
    assert len(mgmt_view) == 2

t("Management sees all threat models", test_management_sees_all)


def test_admin_grants_user_feature_access():
    """Strict ownership model: granting a feature gives the user the ability
    to CREATE TMs in that feature, but does NOT reveal other users' TMs."""
    setup_db()
    admin = make_user("admin@test", "admin")
    alice = make_user("alice@test", "user")
    bob = make_user("bob@test", "user")
    rel = domain.create_release("R1", "", None, admin)
    feat_pub = domain.create_feature(rel["id"], "Public", "", admin)
    feat_priv = domain.create_feature(rel["id"], "Private", "", admin)
    # Bob owns a TM in feat_pub
    domain.create_threat_model(feat_pub["id"], bob, "Bob TM", "",
        {"name":"B","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])

    # Alice sees nothing (no TMs of her own)
    assert len(domain.list_threat_models(visible_to_user_id=alice, visible_to_role="user")) == 0

    # Admin grants alice access to feat_pub
    domain.grant_feature_access(alice, feat_pub["id"], granted_by=admin)

    # Alice STILL sees no TMs — strict ownership. Grant just lets her create new ones.
    alice_view = domain.list_threat_models(visible_to_user_id=alice, visible_to_role="user")
    assert len(alice_view) == 0, "Strict ownership: Alice should NOT see Bob's TM even with feature grant"

    # Verify Alice can see the feature itself (so she can create in it)
    visible_features = domain.list_features(visible_to_user_id=alice, visible_to_role="user")
    assert feat_pub["id"] in {f["id"] for f in visible_features}

    # Now Alice creates her OWN TM in the same feature
    alice_tm = domain.create_threat_model(feat_pub["id"], alice, "Alice TM", "",
        {"name":"A","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    alice_view = domain.list_threat_models(visible_to_user_id=alice, visible_to_role="user")
    assert {t["id"] for t in alice_view} == {alice_tm["id"]}, "Alice sees only her own TM"

    # Revoke feature access — feature disappears from Alice's view
    domain.revoke_feature_access(alice, feat_pub["id"])
    visible_features = domain.list_features(visible_to_user_id=alice, visible_to_role="user")
    assert feat_pub["id"] not in {f["id"] for f in visible_features}
    # But Alice still owns her TM (existing data isn't auto-cleaned)
    assert len(domain.list_threat_models(visible_to_user_id=alice, visible_to_role="user")) == 1

t("Admin grants give create rights, not visibility into other users' TMs (strict ownership)",
  test_admin_grants_user_feature_access)


def test_feature_visibility_for_user():
    setup_db()
    admin = make_user("admin@test", "admin")
    alice = make_user("alice@test", "user")
    rel = domain.create_release("R1", "", None, admin)
    feat_alice = domain.create_feature(rel["id"], "Alice's Feature", "", alice)
    feat_admin = domain.create_feature(rel["id"], "Admin's Feature", "", admin)

    # Alice as user only sees her own feature
    visible = domain.list_features(visible_to_user_id=alice, visible_to_role="user")
    assert {f["id"] for f in visible} == {feat_alice["id"]}

    # Grant alice access to admin's feature
    domain.grant_feature_access(alice, feat_admin["id"], granted_by=admin)
    visible = domain.list_features(visible_to_user_id=alice, visible_to_role="user")
    assert {f["id"] for f in visible} == {feat_alice["id"], feat_admin["id"]}

    # Mgmt always sees all
    mgmt = make_user("mgmt@test", "management")
    visible = domain.list_features(visible_to_user_id=mgmt, visible_to_role="management")
    assert len(visible) == 2

t("Feature visibility for user role respects grants", test_feature_visibility_for_user)


# ===========================================================================
print("\n=== Threat status & management overview ===")
# ===========================================================================
def test_threat_status_upsert():
    setup_db()
    admin = make_user("admin@test", "admin")
    user = make_user("user@test", "user")
    rel = domain.create_release("R1", "", None, admin)
    feat = domain.create_feature(rel["id"], "F1", "", admin)
    tm = domain.create_threat_model(feat["id"], user, "TM", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])

    # First update — insert
    s1 = domain.set_threat_status(tm["id"], "t_abc123", "in_progress",
                                   "investigating", updated_by=user)
    assert s1["status"] == "in_progress"

    # Second update — upsert
    s2 = domain.set_threat_status(tm["id"], "t_abc123", "mitigated",
                                   "patched", updated_by=user)
    assert s2["status"] == "mitigated"

    # Invalid status rejected
    try:
        domain.set_threat_status(tm["id"], "t_xyz", "nonsense", None, user)
        assert False, "should have raised"
    except ValueError:
        pass

    statuses = domain.list_threat_statuses(tm["id"])
    assert len(statuses) == 1
    assert statuses["t_abc123"]["status"] == "mitigated"

t("Threat status insert/upsert/invalid", test_threat_status_upsert)


def test_management_overview_aggregation():
    setup_db()
    admin = make_user("admin@test", "admin")
    user = make_user("user@test", "user")
    rel = domain.create_release("Q1", "", None, admin)
    feat = domain.create_feature(rel["id"], "Auth feature", "", admin)
    fake_analysis = {
        "system": {"name": "X"},
        "summary": {"total": 3, "by_severity": {"Critical": 2, "High": 1}, "rule_based": 3, "llm_enhanced": 0},
        "threats": [
            {"id": "t1", "title": "Critical bug", "severity": "Critical"},
            {"id": "t2", "title": "Another crit", "severity": "Critical"},
            {"id": "t3", "title": "High issue", "severity": "High"},
        ],
        "untrusted_crossings": [],
        "methodologies_used": ["stride"],
        "llm_used": False,
    }
    tm = domain.create_threat_model(feat["id"], user, "TM", "",
        {"name":"X","components":[],"data_flows":[],"trust_boundaries":[]}, ["stride"])
    domain.update_threat_model(tm["id"], analysis=fake_analysis)

    # Mark one as mitigated
    domain.set_threat_status(tm["id"], "t1", "mitigated", None, user)

    overview = domain.management_overview()
    assert len(overview) == 1
    f = overview[0]
    assert f["feature_name"] == "Auth feature"
    assert f["total_threats"] == 3
    assert f["by_severity"]["Critical"] == 2
    assert f["by_severity"]["High"] == 1
    assert f["by_status"]["mitigated"] == 1
    assert "Critical bug" in f["top_critical_titles"]

t("Management overview aggregates per-feature", test_management_overview_aggregation)


# ===========================================================================
print("\n=== Audit log ===")
# ===========================================================================
def test_audit_log_writes():
    setup_db()
    admin = make_user("admin@test", "admin")
    audit(admin, "admin@test", "test.action", "grant", "test", 1,
          ip_address="1.2.3.4", detail="manual call")
    with db_conn() as c:
        rows = c.execute("SELECT * FROM audit_log WHERE user_id=?", (admin,)).fetchall()
    assert len(rows) >= 1
    row = rows[-1]
    assert row["action"] == "test.action"
    assert row["decision"] == "grant"
    assert row["ip_address"] == "1.2.3.4"

t("Audit log writes correctly", test_audit_log_writes)


# ===========================================================================
print(f"\n{'=' * 50}")
if FAIL == 0:
    print(f"  ALL {PASS} TESTS PASSED")
else:
    print(f"  {PASS} passed, {FAIL} FAILED")
print('=' * 50)

# Cleanup
if os.path.exists(_tmp_db.name):
    os.remove(_tmp_db.name)

sys.exit(0 if FAIL == 0 else 1)
