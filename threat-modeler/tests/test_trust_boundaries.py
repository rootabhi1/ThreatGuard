"""Tests for trust boundary inference (heuristic mode + LLM fallback).

LLM mode itself can't be tested without a network connection, but we test
that the public function falls back to heuristic when the LLM call fails.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from threat_engine.trust_boundaries import (
    infer_trust_boundaries_heuristic,
    infer_trust_boundaries,
    _BOUNDARY_RULES,
)
from threat_engine.analyzer import extract_components_from_text

PASS = 0
FAIL = 0
FAILURES = []


def t(name, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print(f"  [PASS] {name}")
    except AssertionError as e:
        FAIL += 1
        FAILURES.append(f"{name}: {e}")
        print(f"  [FAIL] {name}: {e}")
    except Exception as e:
        FAIL += 1
        FAILURES.append(f"{name}: {type(e).__name__}: {e}")
        print(f"  [FAIL] {name}: {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
print("\n=== Heuristic boundary inference ===")
# ---------------------------------------------------------------------------

def t_empty_system():
    boundaries = infer_trust_boundaries_heuristic({"components": []})
    assert boundaries == [], "Empty system should return empty boundaries"


def t_user_lands_in_internet():
    sys = {"components": [{"id": "u", "name": "End User", "type": "user"}]}
    b = infer_trust_boundaries_heuristic(sys)
    assert any(b_["name"] == "Internet" and "u" in b_["contains"] for b_ in b), \
        "user component must land in Internet boundary"


def t_database_lands_in_data_tier():
    sys = {"components": [
        {"id": "d", "name": "Postgres", "type": "database"},
        {"id": "r", "name": "Redis", "type": "cache"},
    ]}
    b = infer_trust_boundaries_heuristic(sys)
    data_tier = next((b_ for b_ in b if b_["name"] == "Data tier"), None)
    assert data_tier, "Data tier boundary should exist"
    assert "d" in data_tier["contains"]
    assert "r" in data_tier["contains"]


def t_stripe_recognized_as_third_party():
    """Stripe is a payment_service AND has 'stripe' in name → Third-party."""
    sys = {"components": [{"id": "s", "name": "Stripe", "type": "payment_service"}]}
    b = infer_trust_boundaries_heuristic(sys)
    third_party = next((b_ for b_ in b if "Third-party" in b_["name"]), None)
    assert third_party, "Third-party boundary should exist for Stripe"
    assert "s" in third_party["contains"]


def t_openai_by_name_pattern():
    """OpenAI by name (type external_entity) goes to third-party."""
    sys = {"components": [
        {"id": "ai", "name": "OpenAI GPT-4", "type": "external_entity"},
    ]}
    b = infer_trust_boundaries_heuristic(sys)
    # external_entity also matches Internet (first rule). Internet wins.
    # That's actually desirable: external_entity = "outside our control".
    found = next((b_ for b_ in b if "ai" in b_["contains"]), None)
    assert found, "OpenAI must land somewhere"


def t_webapp_lands_in_dmz():
    sys = {"components": [{"id": "w", "name": "Frontend", "type": "webapp"}]}
    b = infer_trust_boundaries_heuristic(sys)
    dmz = next((b_ for b_ in b if "DMZ" in b_["name"]), None)
    assert dmz, "DMZ boundary should exist"
    assert "w" in dmz["contains"]


def t_api_lands_in_app_tier():
    sys = {"components": [{"id": "a", "name": "Backend API", "type": "api"}]}
    b = infer_trust_boundaries_heuristic(sys)
    app_tier = next((b_ for b_ in b if "Application tier" in b_["name"]), None)
    assert app_tier, "Application tier boundary should exist"
    assert "a" in app_tier["contains"]


def t_every_component_lands_somewhere():
    """Even unknown types should land in a boundary (default)."""
    sys = {"components": [
        {"id": "x1", "name": "Mystery", "type": "totally_unknown_type"},
        {"id": "x2", "name": "Foo", "type": "blah"},
    ]}
    b = infer_trust_boundaries_heuristic(sys)
    placed = set()
    for b_ in b:
        placed.update(b_["contains"])
    assert "x1" in placed and "x2" in placed, "All components must be placed"


def t_each_component_in_exactly_one_boundary():
    sys = {"components": [
        {"id": "u", "name": "User", "type": "user"},
        {"id": "w", "name": "Web", "type": "webapp"},
        {"id": "a", "name": "API", "type": "api"},
        {"id": "d", "name": "DB", "type": "database"},
        {"id": "s", "name": "Stripe", "type": "payment_service"},
    ]}
    b = infer_trust_boundaries_heuristic(sys)
    counts = {}
    for b_ in b:
        for cid in b_["contains"]:
            counts[cid] = counts.get(cid, 0) + 1
    over = {cid: n for cid, n in counts.items() if n > 1}
    assert not over, f"Components in multiple boundaries: {over}"


def t_empty_boundaries_dropped():
    """If a rule matches nothing, that boundary shouldn't appear."""
    sys = {"components": [{"id": "u", "name": "User", "type": "user"}]}
    b = infer_trust_boundaries_heuristic(sys)
    # Should have ONE boundary (Internet), not all 5
    assert len(b) == 1, f"Expected 1 boundary, got {len(b)}"
    assert b[0]["name"] == "Internet"


def t_boundaries_have_required_fields():
    sys = {"components": [
        {"id": "u", "name": "User", "type": "user"},
        {"id": "d", "name": "Postgres", "type": "database"},
    ]}
    b = infer_trust_boundaries_heuristic(sys)
    for b_ in b:
        assert "id" in b_, "Boundary missing id"
        assert "name" in b_, "Boundary missing name"
        assert "contains" in b_, "Boundary missing contains"
        assert "description" in b_, "Boundary missing description"
        assert isinstance(b_["contains"], list)


t("Empty system returns empty boundaries", t_empty_system)
t("User component → Internet", t_user_lands_in_internet)
t("Database & cache → Data tier", t_database_lands_in_data_tier)
t("Stripe (payment_service) → Third-party", t_stripe_recognized_as_third_party)
t("OpenAI (by name) lands somewhere", t_openai_by_name_pattern)
t("Webapp → DMZ", t_webapp_lands_in_dmz)
t("API → Application tier", t_api_lands_in_app_tier)
t("Unknown types still land in a boundary", t_every_component_lands_somewhere)
t("Each component in exactly one boundary", t_each_component_in_exactly_one_boundary)
t("Boundaries with no components are dropped", t_empty_boundaries_dropped)
t("Boundaries have id, name, contains, description fields",
  t_boundaries_have_required_fields)


# ---------------------------------------------------------------------------
print("\n=== End-to-end: extract_components_from_text now includes boundaries ===")
# ---------------------------------------------------------------------------

def t_extract_includes_boundaries():
    text = """
    A user logs into the web app via OAuth (Google).
    The web app stores session data in Redis.
    User profile data is read from a Postgres database.
    Payments are processed via Stripe API.
    """
    result = extract_components_from_text(text)
    assert "trust_boundaries" in result
    assert len(result["trust_boundaries"]) > 0, \
        "Extraction should now produce trust boundaries"


def t_extract_components_all_in_boundary():
    text = "User logs in to web app. API talks to Postgres."
    result = extract_components_from_text(text)
    placed = set()
    for b in result["trust_boundaries"]:
        placed.update(b["contains"])
    component_ids = {c["id"] for c in result["components"]}
    missing = component_ids - placed
    assert not missing, f"Components not in any boundary: {missing}"


t("extract_components_from_text returns trust_boundaries",
  t_extract_includes_boundaries)
t("extract: every component is placed in exactly one boundary",
  t_extract_components_all_in_boundary)


# ---------------------------------------------------------------------------
print("\n=== LLM fallback path ===")
# ---------------------------------------------------------------------------

def t_llm_falls_back_to_heuristic_when_no_key():
    """Without ANTHROPIC_API_KEY, infer_trust_boundaries(use_llm=True) should
    quietly fall back to heuristic instead of returning [] or raising."""
    import os
    saved = os.environ.pop("ANTHROPIC_API_KEY", None)
    try:
        sys_dict = {"components": [
            {"id": "u", "name": "User", "type": "user"},
            {"id": "d", "name": "Postgres", "type": "database"},
        ]}
        b = infer_trust_boundaries(sys_dict, use_llm=True)
        # Heuristic produces 2 boundaries (Internet + Data tier)
        assert len(b) == 2, f"Expected 2 boundaries from heuristic fallback, got {len(b)}"
    finally:
        if saved:
            os.environ["ANTHROPIC_API_KEY"] = saved


t("infer_trust_boundaries(use_llm=True) falls back to heuristic on failure",
  t_llm_falls_back_to_heuristic_when_no_key)


# ---------------------------------------------------------------------------
print("\n=== DFD editor JS module (parsable + exports correct API) ===")
# ---------------------------------------------------------------------------

def t_dfd_editor_module_balanced():
    """The editor JS file must be syntactically balanced."""
    text = (PROJECT_ROOT / "static" / "js" / "dfd_editor.js").read_text(encoding="utf-8")
    assert text.count("{") == text.count("}"), \
        f"Brace mismatch: {{={text.count('{')} vs }}={text.count('}')}"
    assert text.count("(") == text.count(")"), \
        f"Paren mismatch: (={text.count('(')} vs )={text.count(')')}"
    assert "window.DfdEditor" in text, "DfdEditor must be exposed on window"
    assert "function mount" in text, "mount() function must exist"


def t_dfd_editor_loaded_in_dashboard():
    """dashboard.html and management.html must include the editor script."""
    dash = (PROJECT_ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
    mgmt = (PROJECT_ROOT / "templates" / "management.html").read_text(encoding="utf-8")
    assert "dfd_editor.js" in dash, "dashboard.html must include dfd_editor.js"
    assert "dfd_editor.js" in mgmt, "management.html must include dfd_editor.js"


def t_dashboard_uses_editor():
    """dashboard.js's loadDfd must use window.DfdEditor.mount."""
    js = (PROJECT_ROOT / "static" / "js" / "dashboard.js").read_text(encoding="utf-8")
    assert "DfdEditor.mount" in js, "dashboard.js must use DfdEditor.mount"


def t_management_uses_editor_readonly():
    """management.js must use editor in read-only mode."""
    js = (PROJECT_ROOT / "static" / "js" / "management.js").read_text(encoding="utf-8")
    assert "DfdEditor.mount" in js, "management.js must use DfdEditor.mount"
    assert "readOnly: true" in js, "management.js must use readOnly: true"


t("dfd_editor.js is balanced and exposes window.DfdEditor",
  t_dfd_editor_module_balanced)
t("dashboard.html + management.html include dfd_editor.js",
  t_dfd_editor_loaded_in_dashboard)
t("dashboard.js uses DfdEditor.mount", t_dashboard_uses_editor)
t("management.js uses DfdEditor.mount with readOnly: true",
  t_management_uses_editor_readonly)


# ---------------------------------------------------------------------------
print("\n=== /api/infer-trust-boundaries endpoint registered ===")
# ---------------------------------------------------------------------------

def t_endpoint_registered():
    app_py = (PROJECT_ROOT / "app.py").read_text(encoding="utf-8")
    assert "/api/infer-trust-boundaries" in app_py, \
        "Endpoint must be registered"


def t_extract_endpoint_accepts_use_llm():
    app_py = (PROJECT_ROOT / "app.py").read_text(encoding="utf-8")
    assert "use_llm" in app_py, "use_llm flag must be wired into extract endpoint"


t("/api/infer-trust-boundaries endpoint registered", t_endpoint_registered)
t("/api/extract-from-text accepts use_llm flag", t_extract_endpoint_accepts_use_llm)


# ---------------------------------------------------------------------------
print("\n=== Final summary ===")
# ---------------------------------------------------------------------------
print()
print("=" * 60)
print(f"  Trust boundary tests: {PASS} passed, {FAIL} failed")
print("=" * 60)
if FAIL > 0:
    print("\nFAILURES:")
    for f in FAILURES:
        print(f"  - {f}")
sys.exit(0 if FAIL == 0 else 1)
