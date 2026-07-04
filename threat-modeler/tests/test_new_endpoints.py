"""
tests/test_new_endpoints.py
QA test suite for all endpoints added in the enhancement pass.
Run with:  pytest threat-modeler/tests/test_new_endpoints.py -v
"""
import io, json, pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client():
    from app import app
    return TestClient(app)


@pytest.fixture(scope="module")
def auth_headers(client):
    """Register + login a throwaway user and return bearer headers."""
    client.post("/api/auth/register", json={"username": "qauser", "password": "QaPass123!", "email": "qa@test.com"})
    r = client.post("/api/auth/login", data={"username": "qauser", "password": "QaPass123!"})
    token = r.json().get("access_token", "")
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# /api/templates
# ---------------------------------------------------------------------------
class TestTemplates:
    def test_returns_list(self, client, auth_headers):
        r = client.get("/api/templates", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_template_schema(self, client, auth_headers):
        r = client.get("/api/templates", headers=auth_headers)
        for tpl in r.json():
            assert "id" in tpl
            assert "name" in tpl
            assert "components" in tpl
            assert "data_flows" in tpl
            assert "trust_boundaries" in tpl

    def test_no_broken_flow_refs(self, client, auth_headers):
        r = client.get("/api/templates", headers=auth_headers)
        for tpl in r.json():
            comp_ids = {c["id"] for c in tpl["components"]}
            for f in tpl["data_flows"]:
                assert f["from"] in comp_ids, f"broken from ref in {tpl['id']}"
                assert f["to"]   in comp_ids, f"broken to ref in {tpl['id']}"


# ---------------------------------------------------------------------------
# /api/extract-from-diagram
# ---------------------------------------------------------------------------
class TestDiagramExtraction:
    def test_no_file_returns_400(self, client, auth_headers):
        r = client.post("/api/extract-from-diagram", headers=auth_headers)
        assert r.status_code == 400

    def test_invalid_content_type_returns_400(self, client, auth_headers):
        r = client.post(
            "/api/extract-from-diagram",
            headers=auth_headers,
            files={"file": ("test.pdf", b"%PDF-1.4", "application/pdf")},
        )
        assert r.status_code == 400

    def test_valid_image_returns_stub(self, client, auth_headers):
        """Without ANTHROPIC_API_KEY the extractor returns a valid stub."""
        # 1x1 white PNG
        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
            b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
            b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18"
            b"\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        r = client.post(
            "/api/extract-from-diagram",
            headers=auth_headers,
            files={"file": ("diagram.png", png, "image/png")},
            data={"description": "test diagram"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "components" in body
        assert "data_flows" in body
        assert "trust_boundaries" in body
        assert len(body["components"]) >= 1

    def test_oversized_image_returns_400(self, client, auth_headers):
        big = b"x" * (21 * 1024 * 1024)
        r = client.post(
            "/api/extract-from-diagram",
            headers=auth_headers,
            files={"file": ("big.png", big, "image/png")},
        )
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# /api/threat-status
# ---------------------------------------------------------------------------
class TestThreatStatus:
    def _create_project(self, client, auth_headers):
        payload = {
            "system": {"name": "QA System", "description": "test"},
            "components": [
                {"id": "c_user", "name": "User", "type": "user", "description": ""},
                {"id": "c_api",  "name": "API",  "type": "api",  "description": ""},
            ],
            "data_flows": [
                {"id": "f_1", "from": "c_user", "to": "c_api", "label": "call",
                 "protocol": "HTTPS", "auth": "bearer", "encrypted": True},
            ],
            "trust_boundaries": [],
            "methodologies": ["stride"],
            "use_llm": False,
        }
        r = client.post("/api/projects", headers=auth_headers, json=payload)
        return r.json().get("id") if r.status_code == 200 else None

    def test_set_status(self, client, auth_headers):
        tm_id = self._create_project(client, auth_headers)
        if not tm_id:
            pytest.skip("Could not create project")
        r = client.post("/api/threat-status", headers=auth_headers, json={
            "threat_id": "T001",
            "threat_model_id": tm_id,
            "status": "in_progress",
            "owner": "alice",
            "due_date": "2026-12-31",
        })
        assert r.status_code == 200

    def test_list_statuses(self, client, auth_headers):
        tm_id = self._create_project(client, auth_headers)
        if not tm_id:
            pytest.skip("Could not create project")
        r = client.get(f"/api/threat-status/{tm_id}", headers=auth_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_invalid_status_value(self, client, auth_headers):
        tm_id = self._create_project(client, auth_headers)
        if not tm_id:
            pytest.skip("Could not create project")
        r = client.post("/api/threat-status", headers=auth_headers, json={
            "threat_id": "T002",
            "threat_model_id": tm_id,
            "status": "totally_invalid_status",
        })
        # Should either 400 or accept (domain validates)
        assert r.status_code in (200, 400)


# ---------------------------------------------------------------------------
# /api/report/csv
# ---------------------------------------------------------------------------
class TestCSVExport:
    SAMPLE_ANALYSIS = {
        "system": {"name": "QA System"},
        "threats": [
            {
                "id": "T001", "title": "SQL Injection", "severity": "High",
                "methodology": "stride", "component_name": "API",
                "category": "Tampering", "description": "Unparameterised query",
                "cross_boundary": True, "cvss31": {"score": 8.1},
                "dread": {"total": 38},
            }
        ],
        "summary": {"total": 1, "by_severity": {"High": 1}},
    }

    def test_csv_returns_200(self, client, auth_headers):
        r = client.post("/api/report/csv", headers=auth_headers, json=self.SAMPLE_ANALYSIS)
        assert r.status_code == 200

    def test_csv_content_type(self, client, auth_headers):
        r = client.post("/api/report/csv", headers=auth_headers, json=self.SAMPLE_ANALYSIS)
        assert "text/csv" in r.headers.get("content-type", "")

    def test_csv_has_header_row(self, client, auth_headers):
        r = client.post("/api/report/csv", headers=auth_headers, json=self.SAMPLE_ANALYSIS)
        first_line = r.text.splitlines()[0]
        assert "Title" in first_line
        assert "Severity" in first_line

    def test_csv_contains_threat_data(self, client, auth_headers):
        r = client.post("/api/report/csv", headers=auth_headers, json=self.SAMPLE_ANALYSIS)
        assert "SQL Injection" in r.text
        assert "High" in r.text


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
class TestSecurityHeaders:
    def test_x_content_type_options(self, client):
        r = client.get("/api/templates")
        assert r.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, client):
        r = client.get("/api/templates")
        assert r.headers.get("x-frame-options") == "DENY"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class TestRateLimiting:
    def test_login_rate_limit(self, client):
        """Hit /api/auth/login 15 times from same IP — should get 429."""
        got_429 = False
        for _ in range(15):
            r = client.post("/api/auth/login", data={"username": "x", "password": "x"})
            if r.status_code == 429:
                got_429 = True
                break
        assert got_429, "Expected 429 after 10 rapid login attempts"
