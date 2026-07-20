"""Golden tests for model readiness (0.2 #4) — the question-driven checklist that
turns the generic 'standard checks' pile into a shrinking to-do.

A fresh model should have a low completeness score and many open questions; answering
questions should raise the score and remove them; only *applicable* questions (per the
editor's contextual fields) should be asked.

Run: python tests/test_readiness.py
"""
import os
import sys

os.environ.setdefault("JWT_SECRET", "test-secret")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_engine.analyzer import analyze_system  # noqa: E402
from threat_engine.readiness import compute_readiness, applicable_component_attrs  # noqa: E402

_p = _f = 0


def check(cond, msg):
    global _p, _f
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    _p += bool(cond)
    _f += (not cond)


def main():
    print("=== Readiness is attached to every analysis ===")
    fresh = {"name": "S", "components": [
        {"id": "web", "name": "Web", "type": "webapp"},
        {"id": "api", "name": "API", "type": "api"},
        {"id": "db", "name": "DB", "type": "database"}],
        "data_flows": [{"id": "f1", "from": "web", "to": "api", "protocol": "HTTPS",
                        "auth": "none", "encrypted": False}], "trust_boundaries": []}
    r = analyze_system(fresh, ["stride"])
    rd = r.get("readiness")
    check(isinstance(rd, dict) and "score" in rd, "analysis carries a readiness block")
    check(rd["score"] == 0 and rd["answered"] == 0, "fresh model scores 0% (nothing answered)")
    check(rd["open_count"] == rd["applicable"] > 0, "every applicable question is open on a fresh model")
    check(len(rd["questions"]) > 0, "open questions are enumerated for the checklist")

    print("=== Only applicable questions are asked (editor parity) ===")
    web_q = applicable_component_attrs("webapp")
    check("encodes_output" in web_q and "csrf_protection" in web_q, "webapp is asked about output encoding + CSRF")
    check("mfa" not in web_q, "webapp is NOT asked about MFA (auth-service only)")
    store_q = applicable_component_attrs("database")
    check("encrypted_at_rest" in store_q and "has_backup" in store_q, "a store is asked about at-rest encryption + backup")
    check("enforces_authorization" not in store_q, "a store is NOT asked process-only questions")
    agent_q = applicable_component_attrs("ai_agent")
    check("autonomy_level" in agent_q and "sandboxed" in agent_q, "an agent is asked agentic questions")

    print("=== Answering questions raises the score and removes them ===")
    answered = {"name": "S", "components": [
        {"id": "web", "name": "Web", "type": "webapp",
         "internet_facing": "yes", "enforces_authorization": "yes", "validates_input": "yes",
         "logs_security_events": "yes"},
        {"id": "api", "name": "API", "type": "api"},
        {"id": "db", "name": "DB", "type": "database"}],
        "data_flows": [{"id": "f1", "from": "web", "to": "api", "protocol": "HTTPS",
                        "auth": "none", "encrypted": False}], "trust_boundaries": []}
    r2 = analyze_system(answered, ["stride"])
    rd2 = r2["readiness"]
    check(rd2["score"] > rd["score"], f"score rises after answering ({rd['score']}% -> {rd2['score']}%)")
    check(rd2["open_count"] == rd["open_count"] - 4, "the 4 answered questions leave the open list")
    web_open = [q["attr"] for q in rd2["questions"] if q["target_id"] == "web"]
    check("enforces_authorization" not in web_open, "an answered question no longer appears in the checklist")

    print("=== Answering resolves a generic check (finding or suppression), not just the meter ===")
    # enforces_authorization=yes suppressed the generic 'broken access control' on web.
    active = [t["title"].lower() for t in r2["threats"] if t.get("component_id") == "web"]
    check(not any("broken access control" in t for t in active),
          "answering enforces_authorization=yes clears the generic check on that element")

    print("=== Flow questions are included ===")
    fq = [q for q in rd["questions"] if q["scope"] == "flow"]
    check(any(q["attr"] == "authorization" for q in fq), "the flow is asked about its authorization model")

    print("=== A fully-answered model reports complete ===")
    tiny = {"name": "T", "components": [{"id": "u", "name": "U", "type": "user"}],
            "data_flows": [], "trust_boundaries": []}
    # a 'user' actor has only the common questions; answer them all
    for attr in applicable_component_attrs("user"):
        tiny["components"][0][attr] = "no"
    rt = compute_readiness(tiny)
    check(rt["score"] == 100 and rt["open_count"] == 0, "answering every applicable question reaches 100%")

    print()
    print("=" * 60)
    print(f"  Readiness golden-model: {_p} passed, {_f} failed")
    print("=" * 60)
    if _f:
        sys.exit(1)


if __name__ == "__main__":
    main()
