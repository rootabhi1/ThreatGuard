"""Golden-model tests for release 0.2: agentic threats, multi-value auth/protocol,
flow authorization, and the multi-framework OWASP mapping.

These pin *accuracy* — a canonical agentic model must produce specific threats mapped
to specific OWASP Web/API/LLM/Agentic items, and legacy (string-auth) models must keep
working unchanged. If a rule or mapping regresses, a check here fails.

Run: python tests/test_agentic_owasp.py
"""
import os
import sys

os.environ.setdefault("JWT_SECRET", "test-secret")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_engine.analyzer import analyze_system, parse_structured_system  # noqa: E402
from threat_engine.model_health import has_strong_auth, is_weak_auth, auth_display  # noqa: E402
from threat_engine.owasp import map_threat, FRAMEWORKS  # noqa: E402
from threat_engine.dfd import build_flow_legend  # noqa: E402

_p = _f = 0


def check(cond, msg):
    global _p, _f
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    _p += bool(cond)
    _f += (not cond)


def frameworks_for(threats, title_sub):
    for t in threats:
        if title_sub.lower() in t["title"].lower():
            return {(fr["framework"], fr["id"]) for fr in t.get("frameworks", [])}
    return set()


# Canonical agentic model: autonomous agent, exec tools, no sandbox/HITL, untrusted
# ingest, no prompt-injection defense, unvalidated output, cross-tenant memory,
# web-scraped RAG, unauthorized agent->tool call.
AGENTIC = {
    "name": "Golden Agent",
    "components": [
        {"id": "u", "name": "User", "type": "user"},
        {"id": "ag", "name": "Agent", "type": "ai_agent", "autonomy_level": "autonomous",
         "tool_access": "exec", "human_in_the_loop": "no", "sandboxed": "no",
         "ingests_untrusted_content": "yes", "prompt_injection_defense": "no",
         "output_validated": "no", "can_spawn_agents": "yes"},
        {"id": "kb", "name": "KB", "type": "knowledge_base", "content_source_trust": "web_scraped"},
        {"id": "mem", "name": "Memory", "type": "agent_memory", "memory_scope": "cross_tenant"},
        {"id": "tool", "name": "Shell", "type": "llm_tool"},
    ],
    "data_flows": [
        {"id": "f1", "from": "ag", "to": "tool", "authorization": "none",
         "auth": ["none"], "protocol": ["HTTPS"], "encrypted": True},
    ],
    "trust_boundaries": [],
}


def main():
    print("=== OWASP framework catalog integrity ===")
    check(set(FRAMEWORKS) == {"WEB", "API", "MOBILE", "LLM", "AGENTIC"}, "all 5 frameworks registered")
    for k, (_name, catalog, url) in FRAMEWORKS.items():
        check(bool(catalog) and url.startswith("http"), f"{k} catalog non-empty with a url")

    print("=== Agentic threats fire with correct framework mappings ===")
    res = analyze_system(AGENTIC, ["stride"])
    titles = [t["title"] for t in res["threats"]]
    expected = {
        "Excessive agency": {("LLM", "LLM06"), ("AGENTIC", "T3")},
        "Unsandboxed tool": {("LLM", "LLM06"), ("AGENTIC", "T2")},
        "Prompt injection": {("LLM", "LLM01"), ("AGENTIC", "T6")},
        "output used without validation": {("LLM", "LLM05")},
        "memory shared across tenants": {("LLM", "LLM08"), ("AGENTIC", "T1")},
        "Untrusted grounding": {("LLM", "LLM04")},
        "spawn agents": {("LLM", "LLM10"), ("AGENTIC", "T4")},
        "No authorization on flow": {("WEB", "A01"), ("API", "API1"), ("API", "API5")},
    }
    for sub, must_have in expected.items():
        check(any(sub.lower() in t.lower() for t in titles), f"threat present: {sub}")
        got = frameworks_for(res["threats"], sub)
        check(must_have.issubset(got), f"framework map for '{sub}' ⊇ {sorted(must_have)}  (got {sorted(got)})")

    print("=== Type-driven baseline vs evidenced findings on a clean agent ===")
    clean_agent = {"name": "C", "components": [{"id": "a", "name": "A", "type": "ai_agent"}],
                   "data_flows": [], "trust_boundaries": []}
    r2 = analyze_system(clean_agent, ["stride"])
    # Unanswered attributes never produce an *evidenced* finding (no fabricated proof)...
    check(not any("Excessive agency" in t["title"] and t.get("tier") == "evidenced" for t in r2["threats"]),
          "no evidenced excessive-agency FINDING when attributes are unanswered")
    # ...but the risk surface still appears as a disclosed baseline standard-check,
    # so an agentic system is never silently empty of agentic threats (type-driven).
    ex_baseline = [t for t in r2["threats"]
                   if "excessive agency" in t["title"].lower() and t.get("tier") == "baseline"]
    check(len(ex_baseline) == 1, "excessive-agency appears as a baseline standard-check from the type alone")
    check(all(t["tier"] == "baseline" for t in r2["threats"]
              if any(k in t["title"].lower() for k in ("prompt injection", "excessive agency", "model output"))),
          "clean agent's agentic threats are all baseline (none miscounted as findings)")

    print("=== Multi-value auth: helpers + no silent drop + weak-auth logic ===")
    check(has_strong_auth({"auth": ["none", "mtls"]}), "mtls among auths => strong")
    check(is_weak_auth({"auth": ["none", "basic"]}), "only none/basic => weak")
    check(auth_display({"auth": ["mtls", "bearer"]}) == "mtls + bearer", "auth_display joins list")
    parsed = parse_structured_system("A : api\nB : database\nA -> B : HTTPS, mtls, bearer, rbac, encrypted")
    fl = parsed["data_flows"][0]
    check(fl["auth"] == ["mtls", "bearer"], "parser keeps BOTH auths (no silent drop)")
    check(fl["authorization"] == "rbac", "parser reads authorization model")
    check("sql" not in __import__("threat_engine.analyzer", fromlist=["_PROTOCOLS"])._PROTOCOLS,
          "SQL is not a protocol (accuracy fix)")

    print("=== Backward compatibility: legacy string auth still analyses + maps ===")
    legacy = {"name": "L", "components": [{"id": "api", "name": "API", "type": "api"},
                                          {"id": "db", "name": "DB", "type": "database"}],
              "data_flows": [{"id": "f", "from": "api", "to": "db", "protocol": "TCP",
                              "auth": "none", "encrypted": False}], "trust_boundaries": []}
    r3 = analyze_system(legacy, ["stride"])
    check(r3["summary"]["total"] > 0, "legacy model analyses")
    check(any(t.get("frameworks") for t in r3["threats"]), "legacy threats still get framework refs")
    leg = build_flow_legend(legacy)
    check(leg[0]["auth"] == "none" and leg[0]["protocol"] == "TCP", "legend renders legacy scalars as strings")

    print("=== API/Mobile component lenses ===")
    api_refs = {(r["framework"], r["id"]) for r in map_threat(
        {"title": "Broken access control / missing authz", "category": "Elevation of Privilege"}, {"type": "api"})}
    check(("API", "API1") in api_refs, "api component gets API lens on access-control")

    print("=== Mobile lens fires end-to-end (regression: was silently 0) ===")
    mobile_model = {
        "name": "M", "components": [
            {"id": "app", "name": "Mobile App", "type": "mobile_app"},
            {"id": "api", "name": "API", "type": "api"},
            {"id": "db", "name": "DB", "type": "database"}],
        "data_flows": [
            {"id": "f1", "from": "app", "to": "api", "protocol": "HTTPS", "auth": "none", "encrypted": False},
            {"id": "f2", "from": "api", "to": "db", "protocol": "TCP", "auth": "none", "encrypted": False}],
        "trust_boundaries": []}
    rm = analyze_system(mobile_model, ["stride"])

    def mobile_ids(sub):
        # Union across every threat with this title — the same title can attach to
        # several components (e.g. api + mobile_app); we want the mobile mapping.
        ids = set()
        for t in rm["threats"]:
            if sub.lower() in t["title"].lower():
                ids |= {fr["id"] for fr in t.get("frameworks", []) if fr["framework"] == "MOBILE"}
        return ids

    mob_total = sum(1 for t in rm["threats"] if any(fr["framework"] == "MOBILE" for fr in t.get("frameworks", [])))
    check(mob_total > 0, f"mobile model yields MOBILE-tagged threats (got {mob_total}, must be > 0)")
    # A flow threat attaches to the destination (api); the mobile *source* must still map.
    check("M5" in mobile_ids("Unencrypted flow"), "unencrypted flow from mobile => M5 Insecure Communication")
    check("M3" in mobile_ids("Unauthenticated flow"), "unauthenticated flow from mobile => M3 Insecure Auth")
    check("M4" in mobile_ids("input not validated"), "input-not-validated from mobile => M4 Input/Output Validation")
    check("M1" in mobile_ids("credential stuffing"), "credential threat on mobile => M1 Improper Credential Usage")
    # And a model with NO mobile component must stay clean (no mobile noise).
    nonmobile = {"name": "N", "components": [{"id": "api", "name": "API", "type": "api"},
                                             {"id": "db", "name": "DB", "type": "database"}],
                 "data_flows": [{"id": "f", "from": "api", "to": "db", "protocol": "TCP",
                                 "auth": "none", "encrypted": False}], "trust_boundaries": []}
    rn = analyze_system(nonmobile, ["stride"])
    check(not any(fr["framework"] == "MOBILE" for t in rn["threats"] for fr in t.get("frameworks", [])),
          "non-mobile model has zero MOBILE tags (no noise)")

    print()
    print("=" * 60)
    print(f"  Agentic / OWASP golden-model: {_p} passed, {_f} failed")
    print("=" * 60)
    if _f:
        sys.exit(1)


if __name__ == "__main__":
    main()
