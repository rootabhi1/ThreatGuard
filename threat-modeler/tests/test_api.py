"""API integration tests — exercises the FastAPI app end-to-end via TestClient.

Covers:
  - Auth flows: register, login, refresh, logout, me, lockout
  - Authentication required on every protected endpoint
  - Permission gating: role × endpoint matrix (negative tests too)
  - Resource ownership: user can/can't touch other users' threat models
  - Admin grants extending visibility
  - Threat status updates and validation
  - Management overview aggregation
  - Audit log capture
  - Self-modification protection (admin can't demote self)

Run from project root:
    python3 tests/test_api.py
"""
import os
import sys
import tempfile
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Use a throwaway DB BEFORE importing app
_tmp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
_tmp_db.close()
os.environ["THREAT_MODELER_DB"] = _tmp_db.name
os.environ["JWT_SECRET"] = "test-secret-do-not-use-in-prod-dGVzdA=="
os.environ["INITIAL_ADMIN_EMAIL"] = "admin@example.com"
os.environ["INITIAL_ADMIN_PASSWORD"] = "AdminPass123!"
os.environ["RATE_LIMIT_ENABLED"] = "0"

# Make sure we re-import db with the new path
for mod in list(sys.modules):
    if mod.startswith(("db", "auth", "app", "threat_engine")):
        del sys.modules[mod]

try:
    from fastapi.testclient import TestClient
    from app import app
except ImportError as e:
    print(f"FATAL: Cannot run integration tests — missing dependency: {e}")
    print("Install with: pip install -r requirements.txt")
    sys.exit(2)

client = TestClient(app)
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


def H(token):
    """Auth headers helper."""
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Test fixture helpers
# ---------------------------------------------------------------------------
def login(email, password):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    return r.json()


def admin_token():
    return login("admin@example.com", "AdminPass123!")["access_token"]


def register_user(email, password, full_name):
    r = client.post("/api/auth/register",
                    json={"email": email, "password": password, "full_name": full_name})
    assert r.status_code == 200, f"register failed: {r.text}"
    return r.json()


def admin_create_user(token, email, password, full_name, role, feature_ids=None):
    r = client.post("/api/users",
                    headers=H(token),
                    json={"email": email, "password": password, "full_name": full_name,
                          "role": role, "feature_ids": feature_ids or []})
    assert r.status_code == 200, f"admin create user failed: {r.text}"
    return r.json()


def make_release(token, name="Test Release"):
    r = client.post("/api/releases", headers=H(token),
                    json={"name": name, "description": "test"})
    assert r.status_code == 200, r.text
    return r.json()


def make_feature(token, release_id, name="Test Feature"):
    r = client.post("/api/features", headers=H(token),
                    json={"release_id": release_id, "name": name, "description": "test"})
    assert r.status_code == 200, r.text
    return r.json()


def sample_system():
    return {
        "name": "Demo system",
        "description": "test description",
        "components": [
            {"id": "c1", "name": "User", "type": "external_entity"},
            {"id": "c2", "name": "WebApp", "type": "webapp"},
            {"id": "c3", "name": "DB", "type": "database"},
        ],
        "data_flows": [
            {"id": "f1", "from": "c1", "to": "c2", "data": "credentials",
             "encrypted": False, "auth": "none"},
            {"id": "f2", "from": "c2", "to": "c3", "data": "user data",
             "encrypted": True, "auth": "service_account"},
        ],
        "trust_boundaries": [
            {"id": "b1", "name": "Internet", "contains": ["c1"]},
            {"id": "b2", "name": "Intranet", "contains": ["c2", "c3"]},
        ],
    }


def make_threat_model(token, feature_id, name="Test TM"):
    r = client.post("/api/threat-models", headers=H(token),
                    json={"feature_id": feature_id, "name": name,
                          "description": "test", "system": sample_system(),
                          "methodologies": ["stride"]})
    assert r.status_code == 200, r.text
    return r.json()


# ===========================================================================
print("\n=== Health & public endpoints ===")
# ===========================================================================
def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

t("GET /api/health is public", test_health)


def test_methodologies_requires_auth():
    # Secure-by-default: reference data still requires a valid session.
    assert client.get("/api/methodologies").status_code in (401, 403)
    r = client.get("/api/methodologies", headers=H(admin_token()))
    assert r.status_code == 200
    body = r.json()
    assert "stride" in body and "dread" in body

t("GET /api/methodologies requires auth", test_methodologies_requires_auth)


# ===========================================================================
print("\n=== Auth flows ===")
# ===========================================================================
def test_register_creates_user_role():
    body = register_user("alice@example.com", "AlicePass123!", "Alice")
    assert body["user"]["email"] == "alice@example.com"
    assert body["user"]["role"] == "user"
    assert body["access_token"]
    assert body["refresh_token"]

t("Self-register creates user-role account + auto-login", test_register_creates_user_role)


def test_register_rejects_duplicate_email():
    register_user("bob@example.com", "BobPass123!", "Bob")
    r = client.post("/api/auth/register",
                    json={"email": "bob@example.com", "password": "BobPass123!", "full_name": "Bob"})
    assert r.status_code == 400

t("Duplicate email registration rejected", test_register_rejects_duplicate_email)


def test_register_rejects_short_password():
    r = client.post("/api/auth/register",
                    json={"email": "short@example.com", "password": "x", "full_name": "X"})
    assert r.status_code == 422

t("Short password rejected at validation layer", test_register_rejects_short_password)


def test_login_wrong_password():
    register_user("charlie@example.com", "CharliePass123!", "Charlie")
    r = client.post("/api/auth/login",
                    json={"email": "charlie@example.com", "password": "wrong"})
    assert r.status_code == 401

t("Login with wrong password returns 401", test_login_wrong_password)


def test_login_unknown_email_returns_401_not_404():
    """Don't leak which step failed (email vs password)"""
    r = client.post("/api/auth/login",
                    json={"email": "nobody@example.com", "password": "whatever123"})
    assert r.status_code == 401

t("Login with unknown email returns 401 (not 404 — no enumeration)",
  test_login_unknown_email_returns_401_not_404)


def test_me_requires_auth():
    r = client.get("/api/auth/me")
    assert r.status_code == 401

t("GET /api/auth/me without token is 401", test_me_requires_auth)


def test_me_with_token():
    body = register_user("dave@example.com", "DavePass123!", "Dave")
    r = client.get("/api/auth/me", headers=H(body["access_token"]))
    assert r.status_code == 200
    assert r.json()["user"]["email"] == "dave@example.com"
    assert "threat_model.create" in r.json()["permissions"]

t("GET /api/auth/me with token returns user + permissions", test_me_with_token)


def test_invalid_token():
    r = client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401

t("Invalid token returns 401", test_invalid_token)


def test_refresh_token_flow():
    body = register_user("eve@example.com", "EvePass123!", "Eve")
    # Use refresh token to get a new pair
    r = client.post("/api/auth/refresh",
                    json={"refresh_token": body["refresh_token"]})
    assert r.status_code == 200
    new = r.json()
    assert new["access_token"] != body["access_token"]
    # Old refresh token shouldn't be reusable (rotation)
    r2 = client.post("/api/auth/refresh",
                     json={"refresh_token": body["refresh_token"]})
    assert r2.status_code == 401

t("Refresh token rotation works (old token revoked after use)", test_refresh_token_flow)


def test_logout_revokes_refresh():
    body = register_user("frank@example.com", "FrankPass123!", "Frank")
    r = client.post("/api/auth/logout", headers=H(body["access_token"]))
    assert r.status_code == 200
    # Now refresh should fail
    r2 = client.post("/api/auth/refresh",
                     json={"refresh_token": body["refresh_token"]})
    assert r2.status_code == 401

t("Logout revokes all refresh tokens", test_logout_revokes_refresh)


def test_account_lockout():
    register_user("grace@example.com", "GracePass123!", "Grace")
    # 5 wrong attempts
    for _ in range(5):
        client.post("/api/auth/login",
                    json={"email": "grace@example.com", "password": "wrong"})
    # 6th — even with correct password — should be locked
    r = client.post("/api/auth/login",
                    json={"email": "grace@example.com", "password": "GracePass123!"})
    assert r.status_code == 401
    assert "locked" in r.json()["detail"].lower()

t("Account locked after 5 failed login attempts", test_account_lockout)


# ===========================================================================
print("\n=== Permission gating (role × endpoint) ===")
# ===========================================================================
def test_user_cannot_create_release():
    body = register_user("hank@example.com", "HankPass123!", "Hank")
    r = client.post("/api/releases", headers=H(body["access_token"]),
                    json={"name": "X", "description": ""})
    assert r.status_code == 403

t("User role: cannot POST /api/releases (403)", test_user_cannot_create_release)


def test_user_cannot_create_feature():
    body = register_user("ian@example.com", "IanPass123!", "Ian")
    r = client.post("/api/features", headers=H(body["access_token"]),
                    json={"release_id": 1, "name": "X", "description": ""})
    assert r.status_code == 403

t("User role: cannot POST /api/features (403)", test_user_cannot_create_feature)


def test_user_cannot_list_users():
    body = register_user("jane@example.com", "JanePass123!", "Jane")
    r = client.get("/api/users", headers=H(body["access_token"]))
    assert r.status_code == 403

t("User role: cannot GET /api/users (403)", test_user_cannot_list_users)


def test_user_cannot_read_audit_log():
    body = register_user("ken@example.com", "KenPass123!", "Ken")
    r = client.get("/api/audit-log", headers=H(body["access_token"]))
    assert r.status_code == 403

t("User role: cannot GET /api/audit-log (403)", test_user_cannot_read_audit_log)


def test_user_cannot_view_management_overview():
    body = register_user("lisa@example.com", "LisaPass123!", "Lisa")
    r = client.get("/api/management/overview", headers=H(body["access_token"]))
    assert r.status_code == 403

t("User role: cannot GET /api/management/overview (403)",
  test_user_cannot_view_management_overview)


def test_management_can_view_overview():
    a = admin_token()
    admin_create_user(a, "mgmt1@example.com", "MgmtPass123!", "Mgmt1", "management")
    m_token = login("mgmt1@example.com", "MgmtPass123!")["access_token"]
    r = client.get("/api/management/overview", headers=H(m_token))
    assert r.status_code == 200

t("Management role: can GET /api/management/overview", test_management_can_view_overview)


def test_management_cannot_create_release():
    a = admin_token()
    admin_create_user(a, "mgmt2@example.com", "MgmtPass123!", "Mgmt2", "management")
    m_token = login("mgmt2@example.com", "MgmtPass123!")["access_token"]
    r = client.post("/api/releases", headers=H(m_token),
                    json={"name": "X", "description": ""})
    assert r.status_code == 403

t("Management role: cannot POST /api/releases (403)", test_management_cannot_create_release)


def test_admin_can_do_everything():
    a = admin_token()
    rel = make_release(a)
    assert rel["name"]
    feat = make_feature(a, rel["id"])
    assert feat["release_id"] == rel["id"]
    r = client.get("/api/users", headers=H(a))
    assert r.status_code == 200
    r = client.get("/api/audit-log", headers=H(a))
    assert r.status_code == 200

t("Admin role: can create releases/features, list users, read audit log",
  test_admin_can_do_everything)


# ===========================================================================
print("\n=== Resource ownership & visibility ===")
# ===========================================================================
def test_user_sees_only_own_threat_models():
    a = admin_token()
    rel = make_release(a, "Visibility Release")
    feat = make_feature(a, rel["id"], "Visibility Feature")
    # Grant 2 users access to this feature so they can both create TMs in it
    u1 = admin_create_user(a, "vis1@example.com", "Vis1Pass123!", "Vis1", "user",
                           feature_ids=[feat["id"]])
    u2 = admin_create_user(a, "vis2@example.com", "Vis2Pass123!", "Vis2", "user",
                           feature_ids=[feat["id"]])
    t1 = login("vis1@example.com", "Vis1Pass123!")["access_token"]
    t2 = login("vis2@example.com", "Vis2Pass123!")["access_token"]
    tm1 = make_threat_model(t1, feat["id"], "User1 TM")
    tm2 = make_threat_model(t2, feat["id"], "User2 TM")
    # User 1 lists — should only see their own
    r = client.get("/api/threat-models", headers=H(t1))
    ids = [t["id"] for t in r.json()]
    assert tm1["id"] in ids
    assert tm2["id"] not in ids

t("User sees only own threat models in list (despite shared feature)",
  test_user_sees_only_own_threat_models)


def test_user_404_on_other_users_threat_model():
    """Direct GET on someone else's TM should 404 (not 403 — that would leak existence)"""
    a = admin_token()
    rel = make_release(a, "Privacy Release")
    feat = make_feature(a, rel["id"])
    u1 = admin_create_user(a, "priv1@example.com", "Priv1Pass123!", "Priv1", "user",
                           feature_ids=[feat["id"]])
    u2 = admin_create_user(a, "priv2@example.com", "Priv2Pass123!", "Priv2", "user")
    # u2 has NO feature access
    t1 = login("priv1@example.com", "Priv1Pass123!")["access_token"]
    t2 = login("priv2@example.com", "Priv2Pass123!")["access_token"]
    tm = make_threat_model(t1, feat["id"], "Priv1 TM")
    r = client.get(f"/api/threat-models/{tm['id']}", headers=H(t2))
    assert r.status_code == 404, f"expected 404, got {r.status_code}"

t("User gets 404 (not 403) on another user's threat model — hides existence",
  test_user_404_on_other_users_threat_model)


def test_user_cannot_update_other_users_tm():
    """Strict ownership: even with shared feature grants, users only see/touch their own TMs."""
    a = admin_token()
    rel = make_release(a, "Update Release")
    feat = make_feature(a, rel["id"])
    u1 = admin_create_user(a, "upd1@example.com", "Upd1Pass123!", "Upd1", "user",
                           feature_ids=[feat["id"]])
    u2 = admin_create_user(a, "upd2@example.com", "Upd2Pass123!", "Upd2", "user",
                           feature_ids=[feat["id"]])
    t1 = login("upd1@example.com", "Upd1Pass123!")["access_token"]
    t2 = login("upd2@example.com", "Upd2Pass123!")["access_token"]
    tm = make_threat_model(t1, feat["id"], "Upd1 TM")
    # u2 has feature access (can create their own TMs there), but cannot
    # see/edit/delete u1's TM — strict ownership.
    r = client.delete(f"/api/threat-models/{tm['id']}", headers=H(t2))
    assert r.status_code == 404
    # u2 also can't read it
    r = client.get(f"/api/threat-models/{tm['id']}", headers=H(t2))
    assert r.status_code == 404
    # u2 also can't update it
    r = client.put(f"/api/threat-models/{tm['id']}", headers=H(t2),
                   json={"name": "hacked"})
    assert r.status_code == 404

t("User cannot read/update/delete another user's TM (strict ownership)",
  test_user_cannot_update_other_users_tm)


def test_management_sees_all_threat_models():
    a = admin_token()
    rel = make_release(a, "Mgmt-Vis Release")
    feat = make_feature(a, rel["id"])
    u1 = admin_create_user(a, "mvis1@example.com", "Mvis1Pass!", "Mvis1", "user",
                           feature_ids=[feat["id"]])
    u2 = admin_create_user(a, "mvis2@example.com", "Mvis2Pass!", "Mvis2", "user",
                           feature_ids=[feat["id"]])
    mgmt = admin_create_user(a, "mvismg@example.com", "MvismgPass!", "Mgmt", "management")
    t1 = login("mvis1@example.com", "Mvis1Pass!")["access_token"]
    t2 = login("mvis2@example.com", "Mvis2Pass!")["access_token"]
    mt = login("mvismg@example.com", "MvismgPass!")["access_token"]
    tm1 = make_threat_model(t1, feat["id"], "M1 TM")
    tm2 = make_threat_model(t2, feat["id"], "M2 TM")
    r = client.get("/api/threat-models", headers=H(mt))
    ids = [t["id"] for t in r.json()]
    assert tm1["id"] in ids and tm2["id"] in ids

t("Management sees all threat models", test_management_sees_all_threat_models)


def test_admin_grants_do_not_extend_tm_visibility():
    """STRICT OWNERSHIP: Admin grants user access to a feature → user can CREATE
    TMs there, but does NOT see other users' TMs in that feature."""
    a = admin_token()
    rel = make_release(a, "Grant Release")
    feat = make_feature(a, rel["id"])
    owner = admin_create_user(a, "gowner@example.com", "GownerPass!", "Owner", "user",
                              feature_ids=[feat["id"]])
    grantee = admin_create_user(a, "ggrant@example.com", "GgrantPass!", "Grantee", "user")
    o_token = login("gowner@example.com", "GownerPass!")["access_token"]
    g_token = login("ggrant@example.com", "GgrantPass!")["access_token"]
    tm = make_threat_model(o_token, feat["id"], "Owner TM")

    # Grantee currently can't see it (no grant, no ownership)
    r = client.get(f"/api/threat-models/{tm['id']}", headers=H(g_token))
    assert r.status_code == 404

    # Admin grants grantee access to the feature
    r = client.put(f"/api/users/{grantee['id']}/feature-access", headers=H(a),
                   json={"feature_ids": [feat["id"]]})
    assert r.status_code == 200

    # Grantee STILL can't see Owner's TM — strict ownership
    r = client.get(f"/api/threat-models/{tm['id']}", headers=H(g_token))
    assert r.status_code == 404, "Strict ownership: grantee must NOT see other users' TMs"

    # Grantee's list is still empty (no TMs of their own)
    r = client.get("/api/threat-models", headers=H(g_token))
    assert r.status_code == 200
    assert r.json() == [], "Grantee should see empty list — they have no TMs of their own"

    # But grantee CAN see the feature itself (so they can create TMs in it)
    r = client.get("/api/features", headers=H(g_token))
    assert r.status_code == 200
    assert feat["id"] in {f["id"] for f in r.json()}

t("Admin-granted feature gives create rights, NOT read access to others' TMs",
  test_admin_grants_do_not_extend_tm_visibility)


# ===========================================================================
print("\n=== Threat status & analysis ===")
# ===========================================================================
def test_threat_status_update_flow():
    a = admin_token()
    rel = make_release(a, "Status Release")
    feat = make_feature(a, rel["id"])
    u = admin_create_user(a, "status1@example.com", "StatusPass!", "S", "user",
                          feature_ids=[feat["id"]])
    ut = login("status1@example.com", "StatusPass!")["access_token"]
    tm = make_threat_model(ut, feat["id"])

    # Run analysis to generate threat IDs
    r = client.post(f"/api/threat-models/{tm['id']}/analyze",
                    headers=H(ut),
                    json={"methodologies": ["stride"]})
    assert r.status_code == 200, r.text
    threats = r.json()["threats"]
    assert len(threats) > 0, "analysis produced no threats"
    tid = threats[0]["id"]

    # Update status
    r = client.put(f"/api/threat-models/{tm['id']}/threats/{tid}/status",
                   headers=H(ut),
                   json={"status": "mitigated", "notes": "patched"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "mitigated"

    # Invalid status rejected
    r = client.put(f"/api/threat-models/{tm['id']}/threats/{tid}/status",
                   headers=H(ut),
                   json={"status": "nonsense", "notes": ""})
    assert r.status_code == 422

t("Analyze + threat status update flow works", test_threat_status_update_flow)


def test_management_cannot_update_threat_status():
    """Management is read-only — cannot update threat statuses (only owner or admin can)."""
    a = admin_token()
    rel = make_release(a, "MgmtStatus Release")
    feat = make_feature(a, rel["id"])
    u = admin_create_user(a, "mst1@example.com", "Mst1Pass!", "U", "user",
                          feature_ids=[feat["id"]])
    m = admin_create_user(a, "mstmg@example.com", "MstmgPass!", "M", "management")
    ut = login("mst1@example.com", "Mst1Pass!")["access_token"]
    mt = login("mstmg@example.com", "MstmgPass!")["access_token"]
    tm = make_threat_model(ut, feat["id"])
    r = client.post(f"/api/threat-models/{tm['id']}/analyze",
                    headers=H(ut), json={"methodologies": ["stride"]})
    threats = r.json()["threats"]
    tid = threats[0]["id"]
    # Management tries to update — should be denied (404 to hide the resource)
    r = client.put(f"/api/threat-models/{tm['id']}/threats/{tid}/status",
                   headers=H(mt),
                   json={"status": "in_progress", "notes": "monitoring"})
    assert r.status_code == 404, f"Expected 404 (mgmt is read-only), got {r.status_code}"
    # Management CAN read it
    r = client.get(f"/api/threat-models/{tm['id']}", headers=H(mt))
    assert r.status_code == 200

t("Management is read-only — cannot update threat status",
  test_management_cannot_update_threat_status)


# ===========================================================================
print("\n=== Self-modification protection ===")
# ===========================================================================
def test_admin_cannot_change_own_role():
    a = admin_token()
    me = client.get("/api/auth/me", headers=H(a)).json()
    my_id = me["user"]["id"]
    r = client.put(f"/api/users/{my_id}/role", headers=H(a),
                   json={"role": "user"})
    assert r.status_code == 400
    assert "own role" in r.json()["detail"].lower()

t("Admin cannot demote self", test_admin_cannot_change_own_role)


def test_admin_cannot_deactivate_self():
    a = admin_token()
    me = client.get("/api/auth/me", headers=H(a)).json()
    my_id = me["user"]["id"]
    r = client.delete(f"/api/users/{my_id}", headers=H(a))
    assert r.status_code == 400

t("Admin cannot deactivate self", test_admin_cannot_deactivate_self)


# ===========================================================================
print("\n=== Audit log ===")
# ===========================================================================
def test_audit_log_captures_actions():
    a = admin_token()
    # Trigger some actions
    register_user("audit1@example.com", "AuditPass!", "A1")
    client.post("/api/auth/login",
                json={"email": "audit1@example.com", "password": "wrong"})
    r = client.get("/api/audit-log?limit=50", headers=H(a))
    assert r.status_code == 200
    logs = r.json()
    actions = [l["action"] for l in logs]
    assert "user.register" in actions
    assert "user.login" in actions
    # The wrong-password attempt should appear with decision='deny'
    deny_logins = [l for l in logs if l["action"] == "user.login" and l["decision"] == "deny"]
    assert len(deny_logins) > 0

t("Audit log captures register + login attempts (success and failure)",
  test_audit_log_captures_actions)


# ===========================================================================
print("\n=== Reports ===")
# ===========================================================================
def test_report_requires_analysis():
    a = admin_token()
    rel = make_release(a, "Report Release")
    feat = make_feature(a, rel["id"])
    tm = make_threat_model(a, feat["id"])
    # No analysis run yet — report should 400
    r = client.get(f"/api/threat-models/{tm['id']}/report/markdown", headers=H(a))
    assert r.status_code == 400

t("Cannot generate report before analysis runs", test_report_requires_analysis)


def test_report_after_analysis():
    a = admin_token()
    rel = make_release(a, "Report2 Release")
    feat = make_feature(a, rel["id"])
    tm = make_threat_model(a, feat["id"])
    client.post(f"/api/threat-models/{tm['id']}/analyze", headers=H(a),
                json={"methodologies": ["stride"]})
    for fmt in ("markdown", "html", "pdf"):
        r = client.get(f"/api/threat-models/{tm['id']}/report/{fmt}", headers=H(a))
        assert r.status_code == 200, f"{fmt} report failed: {r.status_code}"
    # Markdown should contain DFD as inline SVG (renders in GitHub)
    md = client.get(f"/api/threat-models/{tm['id']}/report/markdown", headers=H(a)).text
    assert "<svg" in md, "Markdown should contain inline SVG, not just data URI"
    assert "Trust Boundaries" in md, "Should list trust boundaries explicitly"

t("Reports generate after analysis (markdown/html/pdf)", test_report_after_analysis)


# ===========================================================================
print(f"\n{'=' * 60}")
if FAIL == 0:
    print(f"  ALL {PASS} INTEGRATION TESTS PASSED")
else:
    print(f"  {PASS} passed, {FAIL} FAILED")
print('=' * 60)

# Cleanup
if os.path.exists(_tmp_db.name):
    os.remove(_tmp_db.name)

sys.exit(0 if FAIL == 0 else 1)
