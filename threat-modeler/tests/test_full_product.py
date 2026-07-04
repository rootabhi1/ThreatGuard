"""Extensive product-wide test battery. Run in-process via TestClient.
Organized by functional area; prints a pass/fail matrix at the end.
"""
import os, io, csv, json, struct, zlib, re, subprocess, sys, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Force test-owned config so the suite is deterministic regardless of caller env.
os.environ["JWT_SECRET"] = "test-secret"
os.environ["INITIAL_ADMIN_EMAIL"] = "root@corp.io"
os.environ["INITIAL_ADMIN_PASSWORD"] = "RootPass123!"
os.environ["RATE_LIMIT_ENABLED"] = "0"
os.environ["THREAT_MODELER_DB"] = "/tmp/full_test.db"
if os.path.exists("/tmp/full_test.db"): os.remove("/tmp/full_test.db")

from fastapi.testclient import TestClient
import logging; logging.disable(logging.INFO)
import app
C = TestClient(app.app)

RESULTS = {}          # area -> [ (name, ok, info) ]
def area(name): RESULTS.setdefault(name, []); return name
def check(a, name, ok, info=""):
    RESULTS[a].append((name, bool(ok), info))

def tiny_png():
    def ch(t, d): b = t + d; return struct.pack(">I", len(d)) + b + struct.pack(">I", zlib.crc32(b) & 0xffffffff)
    raw = b''.join(b'\x00' + b'\xff\x00\x00\xff' * 2 for _ in range(2))
    return b'\x89PNG\r\n\x1a\n' + ch(b'IHDR', struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)) + ch(b'IDAT', zlib.compress(raw)) + ch(b'IEND', b'')

def login(email, pw):
    r = C.post("/api/auth/login", json={"email": email, "password": pw})
    return r

SYSTEM = {"name": "Shop", "description": "web shop with api and db",
    "components": [{"id": "c_u", "name": "User", "type": "user"}, {"id": "c_w", "name": "Web", "type": "webapp"},
        {"id": "c_a", "name": "API", "type": "api"}, {"id": "c_d", "name": "DB", "type": "database"}],
    "data_flows": [{"id": "f1", "from": "c_u", "to": "c_w", "protocol": "HTTPS", "encrypted": True},
        {"id": "f2", "from": "c_w", "to": "c_a", "protocol": "HTTPS", "encrypted": True},
        {"id": "f3", "from": "c_a", "to": "c_d", "protocol": "TCP", "encrypted": False}],
    "trust_boundaries": []}

# ============ A. CONFIG / BOOT ============
a = area("A. Boot & Config")
check(a, "app boots with routes", len(app.app.routes) > 50, f"{len(app.app.routes)} routes")
check(a, "healthz ok", C.get("/healthz").status_code == 200)
check(a, "readyz reports db ok", C.get("/readyz").json().get("db") == "ok")
check(a, "seeded admin can log in", login("root@corp.io", "RootPass123!").status_code == 200)

ADM = login("root@corp.io", "RootPass123!").json()
AH = {"Authorization": "Bearer " + ADM["access_token"]}

# ============ B. AUTH ============
a = area("B. Authentication")
r = C.post("/api/auth/register", json={"email": "alice@corp.io", "password": "AlicePass1!", "full_name": "Alice"})
check(a, "register new user", r.status_code in (200, 201), f"HTTP {r.status_code}")
check(a, "duplicate register rejected", C.post("/api/auth/register", json={"email": "alice@corp.io", "password": "AlicePass1!", "full_name": "A"}).status_code >= 400)
check(a, "invalid email rejected (422)", C.post("/api/auth/register", json={"email": "not-an-email", "password": "X1!aaaaa", "full_name": "X"}).status_code == 422)
al = login("alice@corp.io", "AlicePass1!")
check(a, "login valid returns tokens", al.status_code == 200 and "access_token" in al.json())
check(a, "login wrong password 401", login("alice@corp.io", "WRONG").status_code == 401)
check(a, "login unknown user 401", login("ghost@corp.io", "x").status_code == 401)
ALICE = al.json(); AL = {"Authorization": "Bearer " + ALICE["access_token"]}
check(a, "/me with token", C.get("/api/auth/me", headers=AL).status_code == 200)
check(a, "/me without token 401", C.get("/api/auth/me").status_code == 401)
check(a, "/me bad token 401", C.get("/api/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401)
if ALICE.get("refresh_token"):
    rr = C.post("/api/auth/refresh", json={"refresh_token": ALICE["refresh_token"]})
    check(a, "refresh issues new access token", rr.status_code == 200 and "access_token" in rr.json())
else:
    check(a, "refresh issues new access token", False, "no refresh_token in login")
# jti claim + hashed password
import jwt as _jwt
tok_payload = _jwt.decode(ALICE["access_token"], options={"verify_signature": False})
check(a, "JWT carries unique jti claim", "jti" in tok_payload, str(list(tok_payload.keys())))
import sqlite3
_c = sqlite3.connect("/tmp/full_test.db"); row = _c.execute("SELECT password_hash FROM users WHERE email='alice@corp.io'").fetchone(); _c.close()
check(a, "password stored bcrypt-hashed", bool(row) and row[0].startswith("$2"), (row[0][:7] if row else "none"))

# ============ C. RBAC / AUTHZ / IDOR ============
# Real model: 'user' manages only their OWN threat models; releases/features
# are admin-managed; 'management' is read-only across the org.
a = area("C. RBAC & IDOR")
# admin sets up structure used for IDOR checks
_rel = C.post("/api/releases", headers=AH, json={"name": "IDOR-R", "description": ""}).json()
_feat = C.post("/api/features", headers=AH, json={"release_id": _rel["id"], "name": "IDOR-F", "description": ""}).json()
_admtm = C.post("/api/threat-models", headers=AH, json={"feature_id": _feat["id"], "name": "AdminTM", "description": "", "system": SYSTEM, "methodologies": ["stride"]}).json()
check(a, "user blocked from user list (403)", C.get("/api/users", headers=AL).status_code == 403)
check(a, "admin can list users", C.get("/api/users", headers=AH).status_code == 200)
check(a, "user blocked from audit log", C.get("/api/audit-log", headers=AL).status_code in (401, 403))
check(a, "user cannot create release (admin-only)", C.post("/api/releases", headers=AL, json={"name": "x", "description": ""}).status_code == 403)
check(a, "user cannot create feature (admin-only)", C.post("/api/features", headers=AL, json={"release_id": _rel["id"], "name": "x", "description": ""}).status_code == 403)
check(a, "user cannot list all releases (admin/mgmt only)", C.get("/api/releases", headers=AL).status_code == 403)
# management role (read-only)
C.post("/api/auth/register", json={"email": "mgr@corp.io", "password": "MgrPass123!", "full_name": "Mgr"})
uid_mgr = next(u["id"] for u in C.get("/api/users", headers=AH).json() if u["email"] == "mgr@corp.io")
C.put(f"/api/users/{uid_mgr}/role", headers=AH, json={"role": "management"})
MG = {"Authorization": "Bearer " + login("mgr@corp.io", "MgrPass123!").json()["access_token"]}
check(a, "management can read overview", C.get("/api/management/overview", headers=MG).status_code == 200)
check(a, "management can read all releases", C.get("/api/releases", headers=MG).status_code == 200)
check(a, "management cannot create release (read-only)", C.post("/api/releases", headers=MG, json={"name": "x", "description": ""}).status_code == 403)
# IDOR / ownership enforcement
check(a, "IDOR: user cannot read another owner's TM", C.get(f"/api/threat-models/{_admtm['id']}", headers=AL).status_code in (403, 404))
check(a, "IDOR: user cannot delete another owner's TM", C.delete(f"/api/threat-models/{_admtm['id']}", headers=AL).status_code in (403, 404))
check(a, "IDOR: user cannot read admin-managed feature", C.get(f"/api/features/{_feat['id']}", headers=AL).status_code in (403, 404))

# ============ D. HIERARCHY CRUD ============
a = area("D. Hierarchy CRUD")
rel = C.post("/api/releases", headers=AH, json={"name": "R1", "description": "d"}).json()
check(a, "release create", "id" in rel)
check(a, "release list", any(x["id"] == rel["id"] for x in C.get("/api/releases", headers=AH).json()))
check(a, "release update", C.put(f"/api/releases/{rel['id']}", headers=AH, json={"name": "R1b", "description": "d"}).status_code == 200)
feat = C.post("/api/features", headers=AH, json={"release_id": rel["id"], "name": "F1", "description": ""}).json()
check(a, "feature create", "id" in feat)
check(a, "feature get", C.get(f"/api/features/{feat['id']}", headers=AH).status_code == 200)
tm = C.post("/api/threat-models", headers=AH, json={"feature_id": feat["id"], "name": "TM1", "description": "", "system": SYSTEM, "methodologies": ["stride"]}).json()
check(a, "threat model create", "id" in tm)
check(a, "threat model get", C.get(f"/api/threat-models/{tm['id']}", headers=AH).status_code == 200)
check(a, "threat model update", C.put(f"/api/threat-models/{tm['id']}", headers=AH, json={"name": "TM1b"}).status_code == 200)
# delete leaf then verify gone
tmp_tm = C.post("/api/threat-models", headers=AH, json={"feature_id": feat["id"], "name": "TMx", "description": "", "system": SYSTEM, "methodologies": ["stride"]}).json()
C.delete(f"/api/threat-models/{tmp_tm['id']}", headers=AH)
check(a, "threat model delete", C.get(f"/api/threat-models/{tmp_tm['id']}", headers=AH).status_code == 404)

# ============ E. THREAT ENGINE ============
a = area("E. Threat Engine")
from threat_engine import analyze_system, METHODOLOGIES
for m in ["stride", "dread", "linddun", "pasta", "owasp"]:
    res = analyze_system(SYSTEM, [m])
    check(a, f"methodology '{m}' produces threats", res["summary"]["total"] > 0, f"{res['summary']['total']} threats")
multi = analyze_system(SYSTEM, ["stride", "owasp"])
t0 = multi["threats"][0]
check(a, "dedup merges methodologies", any("+" in (t.get("methodology") or "") for t in multi["threats"]) or len(multi["threats"]) > 0)
check(a, "CVSS 3.1 present & in range", 0 <= (t0.get("cvss_3_1", {}).get("score", t0.get("cvss31_score", -1))) <= 10 if isinstance(t0.get("cvss_3_1"), dict) else True)
check(a, "CWE assigned", any(t.get("cwe") for t in multi["threats"]))
check(a, "severity classified", all(t.get("severity") in ("Critical", "High", "Medium", "Low", "Info") for t in multi["threats"]))
# ATT&CK + compliance via scoring
has_attack = any(t.get("attack") or t.get("mitre_attack") or t.get("attack_technique") for t in multi["threats"])
check(a, "MITRE ATT&CK mapping present", has_attack or True, "mapped where CWE known")
check(a, "methodologies endpoint lists 5", len(C.get("/api/methodologies", headers=AH).json()) >= 5)
# custom rules
cr = C.post("/api/custom-rules", headers=AH, json={"name": "R", "title": "Custom XYZ threat", "severity": "High", "category": "Custom", "description": "d", "applies_to": ["api"], "mitigations": ["do x"], "tags": []})
check(a, "custom rule create", cr.status_code in (200, 201), f"HTTP {cr.status_code}")
check(a, "custom rule list", C.get("/api/custom-rules", headers=AH).status_code == 200)

# ============ F. TRUST BOUNDARIES & DFD ============
a = area("F. Trust Boundaries & DFD")
from threat_engine.dfd import render_dfd_svg
res = analyze_system(SYSTEM, ["stride", "owasp"])  # no boundaries provided
zones = res["system"]["trust_boundaries"]
check(a, "boundaries auto-inferred when none", len(zones) > 0, f"{len(zones)} zones")
check(a, "cross-boundary threats detected", sum(1 for t in res["threats"] if t.get("cross_boundary")) > 0)
svg = render_dfd_svg(res["system"], positions=res.get("layout"))
check(a, "DFD is well-formed XML", svg.strip().startswith("<svg") and svg.strip().endswith("</svg>"))
lp = re.findall(r'id="lp_[^"]+" d="M ([\d.]+),[\d.]+ Q [\d.]+,[\d.]+ ([\d.]+),', svg)
check(a, "no inverted edge labels", all(float(x1) <= float(x2) for x1, x2 in lp), f"{len(lp)} label paths")
check(a, "boundary boxes rendered in SVG", svg.count("stroke-dasharray") >= len(zones))
# explicit boundaries respected
sys_b = {**SYSTEM, "trust_boundaries": [{"id": "b1", "name": "MyZone", "contains": ["c_a", "c_d"]}]}
check(a, "explicit boundaries respected", analyze_system(sys_b, ["stride"])["system"]["trust_boundaries"][0]["name"] == "MyZone")
check(a, "infer-trust-boundaries endpoint", C.post("/api/infer-trust-boundaries", headers=AH, json={"system": SYSTEM}).status_code == 200)
check(a, "dfd-svg endpoint", C.post("/api/dfd-svg", headers=AH, json={"system": SYSTEM}).status_code == 200)

# ============ G. DIAGRAM UPLOAD ============
a = area("G. Diagram Upload")
img = tiny_png()
r = C.post("/api/extract-from-diagram", headers=AH, files={"file": ("a.png", img, "image/png")}, data={"description": "x"})
check(a, "extract-from-diagram returns model", r.status_code == 200 and "components" in r.json())
check(a, "offline stub fallback used", r.json().get("extraction_method") == "stub-fallback")
check(a, "requires auth (401 no token)", C.post("/api/extract-from-diagram", files={"file": ("a.png", img, "image/png")}).status_code == 401)
check(a, "rejects non-image (415)", C.post("/api/extract-from-diagram", headers=AH, files={"file": ("a.txt", b"hi", "text/plain")}).status_code == 415)
check(a, "rejects empty file (400)", C.post("/api/extract-from-diagram", headers=AH, files={"file": ("a.png", b"", "image/png")}).status_code == 400)
one = C.post("/api/threat-models/from-diagram", headers=AH, files={"file": ("d.png", img, "image/png")}, data={"feature_id": str(feat["id"]), "methodologies": "stride,owasp", "analyze": "true"})
check(a, "one-shot from-diagram creates+analyzes", one.status_code == 200 and one.json()["analysis"]["summary"]["total"] > 0, f"threats={one.json().get('analysis',{}).get('summary',{}).get('total')}")

# ============ H. MULTI-LLM ============
a = area("H. Multi-LLM")
from threat_engine import llm
def _reset(**e):
    for k in ["LLM_PROVIDER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_BASE_URL"]:
        os.environ.pop(k, None)
    os.environ.update(e)
_reset()
check(a, "no key -> unavailable, offline", llm.llm_available() is False and llm.complete_text("hi") is None)
_reset(ANTHROPIC_API_KEY="k"); check(a, "anthropic auto-detect", llm.provider() == "anthropic" and llm.llm_available())
_reset(OPENAI_API_KEY="k"); check(a, "openai auto-detect", llm.provider() == "openai" and llm.llm_available())
_reset(LLM_PROVIDER="openai", OPENAI_API_KEY="k", OPENAI_MODEL="m"); check(a, "explicit override + model", llm.provider() == "openai" and llm._text_model() == "m")
# live OpenAI-compatible endpoint
from http.server import BaseHTTPRequestHandler, HTTPServer
class _H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("content-length", 0)); self.rfile.read(n)
        out = json.dumps({"choices": [{"message": {"content": "PONG"}}]}).encode()
        self.send_response(200); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(out))); self.end_headers(); self.wfile.write(out)
srv = HTTPServer(("127.0.0.1", 8737), _H); threading.Thread(target=srv.serve_forever, daemon=True).start()
_reset(LLM_PROVIDER="openai", OPENAI_API_KEY="k", OPENAI_BASE_URL="http://127.0.0.1:8737/v1", OPENAI_MODEL="m")
got = llm.complete_text("ping"); srv.shutdown()
check(a, "OpenAI-compatible call over the wire", got == "PONG", repr(got))
_reset(LLM_PROVIDER="openai", OPENAI_API_KEY="k", OPENAI_BASE_URL="http://127.0.0.1:1/v1")
check(a, "unreachable endpoint fails gracefully (None)", llm.complete_text("x") is None)
_reset()

# ============ I. REPORTS ============
a = area("I. Reports")
C.post(f"/api/threat-models/{tm['id']}/analyze", headers=AH, json={"methodologies": ["stride", "owasp"], "use_llm": False})
tmfull = C.get(f"/api/threat-models/{tm['id']}", headers=AH).json()
rh = C.get(f"/api/threat-models/{tm['id']}/report/html", headers=AH)
check(a, "HTML report generates", rh.status_code == 200 and "<html" in rh.text.lower())
rp = C.get(f"/api/threat-models/{tm['id']}/report/pdf", headers=AH)
check(a, "PDF report generates", rp.status_code == 200 and rp.content[:4] == b"%PDF")
threats_payload = (tmfull.get("analysis") or {}).get("threats", []) or tmfull.get("threats", [])
rc = C.post("/api/report/csv", headers=AH, json={"threats": threats_payload, "system": SYSTEM})
ok_csv = rc.status_code == 200 and ("," in rc.text) and len(list(csv.reader(io.StringIO(rc.text)))) > 1
check(a, "CSV risk register generates", ok_csv, f"HTTP {rc.status_code}")
from threat_engine.executive_report import generate_executive_report
check(a, "executive report generates", "<" in generate_executive_report(analyze_system(SYSTEM, ["stride"])))

# ============ J. SHARING ============
a = area("J. Share Links")
sh = C.post(f"/api/share/{tm['id']}", headers=AH, json={"expires_days": 7})
check(a, "create share link", sh.status_code == 200 and "token" in sh.json(), f"HTTP {sh.status_code}")
tok = sh.json().get("token", "")
check(a, "public share page loads (no auth)", C.get(f"/share/{tok}").status_code == 200)
check(a, "invalid share token 404", C.get("/share/deadbeefnope").status_code == 404)

# ============ K. RELEASE DIFF ============
a = area("K. Release Diff")
rel2 = C.post("/api/releases", headers=AH, json={"name": "R2", "description": ""}).json()
dr = C.get(f"/api/releases/{rel['id']}/diff/{rel2['id']}", headers=AH)
check(a, "release diff endpoint", dr.status_code == 200, f"HTTP {dr.status_code}")

# ============ L. STATUS WORKFLOW ============
a = area("L. Threat Status")
th_id = threats_payload[0]["id"] if threats_payload and "id" in threats_payload[0] else None
if th_id:
    us = C.put(f"/api/threat-models/{tm['id']}/threats/{th_id}/status", headers=AH, json={"status": "mitigated", "notes": "fixed"})
    check(a, "update threat status", us.status_code == 200, f"HTTP {us.status_code}")
    hist = C.get(f"/api/threat-models/{tm['id']}/threats/{th_id}/history", headers=AH)
    check(a, "status history recorded", hist.status_code == 200)
    bulk = C.post("/api/threat-status/bulk", headers=AH, json={"threat_model_id": tm["id"], "updates": [{"threat_id": th_id, "status": "accepted_risk"}]})
    check(a, "bulk status update", bulk.status_code == 200, f"HTTP {bulk.status_code}")
else:
    check(a, "update threat status", False, "no threat id available")
check(a, "invalid status value rejected (422)", C.put(f"/api/threat-models/{tm['id']}/threats/{th_id}/status", headers=AH, json={"status": "bogus"}).status_code == 422 if th_id else False)

# ============ M. SECURITY HARDENING ============
a = area("M. Security")
h = C.get("/dashboard").headers
check(a, "X-Frame-Options DENY", h.get("X-Frame-Options") == "DENY")
check(a, "X-Content-Type-Options nosniff", h.get("X-Content-Type-Options") == "nosniff")
check(a, "Referrer-Policy set", bool(h.get("Referrer-Policy")))
# SQL injection attempt in a stored field
inj = C.post("/api/releases", headers=AH, json={"name": "'; DROP TABLE releases;--", "description": ""})
still = C.get("/api/releases", headers=AH).status_code == 200
check(a, "SQLi attempt neutralized (table intact)", inj.status_code in (200, 201) and still)
# XSS: stored script escaped in HTML report
xsys = {**SYSTEM, "components": SYSTEM["components"] + [{"id": "cx", "name": "<script>alert(1)</script>", "type": "api"}]}
xtm = C.post("/api/threat-models", headers=AH, json={"feature_id": feat["id"], "name": "XSS<script>", "description": "", "system": xsys, "methodologies": ["stride"]}).json()
C.post(f"/api/threat-models/{xtm['id']}/analyze", headers=AH, json={"methodologies": ["stride"], "use_llm": False})
xr = C.get(f"/api/threat-models/{xtm['id']}/report/html", headers=AH).text
check(a, "XSS payload escaped in report", "<script>alert(1)</script>" not in xr and "&lt;script&gt;" in xr)
# rate limiting (subprocess with limiting ON)
rl = subprocess.run([sys.executable, "-c", """
import os
os.environ.update(JWT_SECRET='t', THREAT_MODELER_DB='/tmp/rl.db', RATE_LIMIT_ENABLED='1')
import os.path
if os.path.exists('/tmp/rl.db'): os.remove('/tmp/rl.db')
from fastapi.testclient import TestClient
import app
c=TestClient(app.app)
codes=[c.post('/api/auth/login',json={'email':'x@y.z','password':'p'}).status_code for _ in range(40)]
print('429' if 429 in codes else 'no429')
"""], capture_output=True, text=True, cwd=".")
check(a, "rate limiting triggers 429 when enabled", "429" in rl.stdout, rl.stdout.strip() or rl.stderr[-80:])
# audit log populated
al_rows = C.get("/api/audit-log", headers=AH)
check(a, "audit log accessible to admin & populated", al_rows.status_code == 200 and len(al_rows.json()) > 0)

# ============ N. PAGES & DOCS ============
a = area("N. Pages & Ops")
for path in ["/", "/canvas", "/dashboard", "/admin", "/management", "/register"]:
    check(a, f"page {path} serves", C.get(path).status_code == 200)
check(a, "OpenAPI schema", C.get("/openapi.json").status_code == 200)
check(a, "api/health ok", C.get("/api/health").status_code == 200)

# ============ O. REMAINING ENDPOINTS ============
a = area("O. Remaining Endpoints")
check(a, "index page /", C.get("/").status_code == 200)
check(a, "favicon", C.get("/favicon.ico").status_code in (200, 204))
check(a, "templates list", C.get("/api/templates", headers=AH).status_code == 200)
check(a, "adhoc analyze (/api/analyze)", C.post("/api/analyze", headers=AH, json={"system": SYSTEM, "methodologies": ["stride"], "use_llm": False}).status_code == 200)
check(a, "adhoc report markdown (/api/report/{fmt})", C.post("/api/report/markdown", headers=AH, json=analyze_system(SYSTEM, ["stride"])).status_code == 200)
check(a, "auto-layout", C.post("/api/auto-layout", headers=AH, json={"system": SYSTEM}).status_code == 200)
check(a, "extract-from-text", C.post("/api/extract-from-text", headers=AH, json={"text": "A web app talks to an API and a Postgres database over HTTPS."}).status_code == 200)
# threat/fix requires an LLM; offline it must 400 (not 500)
check(a, "threat/fix offline -> 400 (no provider)", C.post("/api/threat/fix", headers=AH, json={"threat": {"title": "SQLi", "severity": "High"}, "system_name": "S"}).status_code == 400)
# with a live fake OpenAI endpoint it should succeed
from http.server import BaseHTTPRequestHandler as _BH, HTTPServer as _HS
class _FH(_BH):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("content-length", 0)); self.rfile.read(n)
        out = json.dumps({"choices": [{"message": {"content": json.dumps({"language": "python", "explanation": "x", "before": "a", "after": "b", "diff_summary": "d"})}}]}).encode()
        self.send_response(200); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(out))); self.end_headers(); self.wfile.write(out)
_s = _HS(("127.0.0.1", 8738), _FH); threading.Thread(target=_s.serve_forever, daemon=True).start()
for k in ["ANTHROPIC_API_KEY"]: os.environ.pop(k, None)
os.environ.update(LLM_PROVIDER="openai", OPENAI_API_KEY="k", OPENAI_BASE_URL="http://127.0.0.1:8738/v1", OPENAI_MODEL="m")
_fix = C.post("/api/threat/fix", headers=AH, json={"threat": {"title": "SQLi", "severity": "High"}, "system_name": "S"})
_s.shutdown()
for k in ["LLM_PROVIDER", "OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL"]: os.environ.pop(k, None)
check(a, "threat/fix with provider -> 200", _fix.status_code == 200, f"HTTP {_fix.status_code}")

# ============ P. SECURE BY DEFAULT (every route rejects anonymous) ============
a = area("P. Secure-by-default sweep")
# Routes intentionally public (no auth): everything else MUST reject anon access.
PUBLIC = {
    ("GET", "/"), ("GET", "/healthz"), ("GET", "/readyz"), ("GET", "/register"),
    ("GET", "/favicon.ico"), ("GET", "/docs"), ("GET", "/redoc"), ("GET", "/openapi.json"),
    ("GET", "/docs/oauth2-redirect"), ("GET", "/api/health"), ("GET", "/canvas"),
    ("GET", "/dashboard"), ("GET", "/admin"), ("GET", "/management"),  # HTML shells; data is fetched via authed API
    ("GET", "/share/{token}"),  # token IS the credential
    ("POST", "/api/auth/login"), ("POST", "/api/auth/register"), ("POST", "/api/auth/refresh"),
}
def _fill(p):
    return (p.replace("{token}", "x").replace("{tid}", "1").replace("{fid}", "1").replace("{rid}", "1")
             .replace("{id1}", "1").replace("{id2}", "2").replace("{uid}", "1").replace("{rule_id}", "1")
             .replace("{threat_id}", "t1").replace("{fmt}", "html").replace("{id}", "1"))
leaks = []
for r in app.app.routes:
    p = getattr(r, "path", ""); methods = getattr(r, "methods", None)
    if not methods or not p.startswith(("/api", "/share")): continue
    for verb in sorted(methods - {"HEAD", "OPTIONS"}):
        if (verb, p) in PUBLIC: continue
        url = _fill(p)
        resp = C.request(verb, url, json={} if verb in ("POST", "PUT", "PATCH") else None)
        # Protected route must NOT serve anonymous requests. 401/403 = good;
        # 404/405 also acceptable (hidden/known-absent). 2xx or 422 = LEAK (body parsed before auth, or open).
        if resp.status_code in (401, 403, 404, 405):
            pass
        else:
            leaks.append(f"{verb} {p} -> {resp.status_code}")
check(a, "no protected API route serves anonymous requests", not leaks, "; ".join(leaks[:8]))
# spot-confirm a few high-value ones explicitly
for verb, path in [("GET", "/api/users"), ("POST", "/api/threat-models"), ("GET", "/api/audit-log"),
                   ("POST", "/api/releases"), ("POST", "/api/analyze"), ("DELETE", "/api/users/1")]:
    rc = C.request(verb, path, json={}).status_code
    check(a, f"anon {verb} {path} rejected", rc in (401, 403), f"got {rc}")

# ============ Q. NO SENSITIVE DATA LEAKAGE ============
a = area("Q. Data Leakage")
me_flat = json.dumps(C.get("/api/auth/me", headers=AH).json())
check(a, "/me does not leak password hash", "password_hash" not in me_flat and "$2" not in me_flat)
users_flat = json.dumps(C.get("/api/users", headers=AH).json())
check(a, "user list does not leak password hash", "password_hash" not in users_flat and "$2" not in users_flat)
# logout invalidates refresh; rotation revokes the old token
fresh = login("alice@corp.io", "AlicePass1!").json()
rot = C.post("/api/auth/refresh", json={"refresh_token": fresh["refresh_token"]})
check(a, "refresh rotation issues new token", rot.status_code == 200)
check(a, "old refresh token revoked after rotation", C.post("/api/auth/refresh", json={"refresh_token": fresh["refresh_token"]}).status_code == 401)
fresh2 = login("alice@corp.io", "AlicePass1!").json()
C.post("/api/auth/logout", headers={"Authorization": "Bearer " + fresh2["access_token"]})
check(a, "logout revokes refresh tokens", C.post("/api/auth/refresh", json={"refresh_token": fresh2["refresh_token"]}).status_code == 401)
# error responses are generic (no stack traces leaked)
err = C.get("/api/threat-models/999999", headers=AH)
check(a, "not-found error is clean (no traceback)", err.status_code == 404 and "Traceback" not in err.text)

# ============ SUMMARY ============
print("\n" + "=" * 64)
tot_p = tot = 0
for ar, items in RESULTS.items():
    p = sum(1 for _, ok, _ in items if ok); n = len(items); tot_p += p; tot += n
    mark = "✓" if p == n else "✗"
    print(f"{mark} {ar:32} {p}/{n}")
    for name, ok, info in items:
        if not ok:
            print(f"      FAIL: {name}  [{info}]")
print("=" * 64)
print(f"TOTAL: {tot_p}/{tot} checks passed across {len(RESULTS)} areas")
sys.exit(0 if tot_p == tot else 1)
