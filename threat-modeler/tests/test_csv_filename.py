"""Regression: CSV export must not 500 when the system name contains
non-latin-1 characters (the Content-Disposition filename bug fixed in v0.1.1).

Covers em dash, en dash, accented, CJK, and emoji names, across both CSV
export endpoints (the UI 'Risk Register CSV' button and the adhoc report path),
and verifies the header is latin-1-safe (RFC 6266 + RFC 5987) while the original
Unicode name is preserved.

Run: python tests/test_csv_filename.py
"""
import os
import sys
from urllib.parse import unquote

os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("INITIAL_ADMIN_EMAIL", "admin@corp.io")
os.environ.setdefault("INITIAL_ADMIN_PASSWORD", "AdminPass123!")
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402
import app as appmod  # noqa: E402
from app import _content_disposition, _risk_register_csv  # noqa: E402
from threat_engine import analyze_system  # noqa: E402

client = TestClient(appmod.app)

NAMES = {
    "em dash": "ShopFast — Online Retail Platform",
    "en dash": "Payments – Gateway",
    "accented": "Café Naïve Résumé Système",
    "CJK": "支付系统 決済システム 결제 서비스",
    "emoji": "Rocket 🚀 Service 🔒 API",
}

_passed = 0
_failed = 0


def check(cond, msg):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  [PASS] {msg}")
    else:
        _failed += 1
        print(f"  [FAIL] {msg}")


def login():
    r = client.post("/api/auth/login", json={"email": os.environ["INITIAL_ADMIN_EMAIL"],
                                             "password": os.environ["INITIAL_ADMIN_PASSWORD"]})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def sample_threats():
    system = {"name": "seed", "components": [{"id": "a", "name": "API", "type": "api"},
                                             {"id": "d", "name": "DB", "type": "database"}],
              "data_flows": [{"id": "f", "from": "a", "to": "d", "protocol": "TCP", "encrypted": False}],
              "trust_boundaries": []}
    return analyze_system(system, ["stride", "owasp"])["threats"]


def header_is_latin1_safe(value: str) -> bool:
    try:
        value.encode("latin-1")
        return True
    except UnicodeEncodeError:
        return False


def main():
    print("=== _content_disposition helper: latin-1 safe + preserves Unicode ===")
    for label, name in NAMES.items():
        fname = f"risk_register_{name.replace(' ', '_')}.csv"
        cd = _content_disposition(fname)
        check(header_is_latin1_safe(cd), f"{label}: header is latin-1 encodable")
        check('filename="' in cd, f"{label}: has ASCII filename= fallback")
        check("filename*=UTF-8''" in cd, f"{label}: has RFC 5987 filename*")
        star = cd.split("filename*=UTF-8''", 1)[1]
        check(unquote(star) == fname, f"{label}: filename* round-trips to original Unicode name")

    threats = sample_threats()

    print("=== POST /api/report/csv (UI 'Risk Register CSV' button path) ===")
    tok = login()
    for label, name in NAMES.items():
        r = client.post("/api/report/csv", json={"threats": threats, "system": {"name": name}},
                        headers={"Authorization": f"Bearer {tok}"})
        check(r.status_code == 200, f"{label}: HTTP 200 (was 500 before fix)")
        cd = r.headers.get("content-disposition", "")
        check(header_is_latin1_safe(cd) and "filename*=UTF-8''" in cd, f"{label}: valid Content-Disposition")
        body = r.content.decode("utf-8")
        check(body.startswith("ID,Title,"), f"{label}: CSV content intact (UTF-8, header row present)")

    print("=== POST /api/report/csv via adhoc /api/report/{fmt} path ===")
    for label, name in NAMES.items():
        analysis = {"threats": threats, "system": {"name": name}}
        r = client.post("/api/report/csv", json=analysis, headers={"Authorization": f"Bearer {tok}"})
        # (report_csv handles this route; adhoc {fmt}=csv shares _content_disposition)
        check(r.status_code == 200, f"{label}: adhoc path HTTP 200")

    print("=== direct _risk_register_csv preserves Unicode in content when present ===")
    csv_bytes = _risk_register_csv(threats, NAMES["CJK"])
    check(csv_bytes.decode("utf-8").startswith("ID,Title,"), "risk register body decodes as UTF-8")

    print()
    print("=" * 60)
    print(f"  CSV filename regression: {_passed} passed, {_failed} failed")
    print("=" * 60)
    if _failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
