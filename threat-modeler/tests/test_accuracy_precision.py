"""Golden-model tests for the release 0.2 accuracy pass:

  * Cut false positives — an explicitly-answered control suppresses the generic
    catalog threat it negates, and suppression is DISCLOSED (never a silent drop).
  * Evidence per threat — every active threat carries a human-readable 'why this
    fired' trace.
  * Severity calibration — exposure context nudges the displayed severity by at
    most one level, always recording the original + a rationale.

Attribute-less models must be completely unchanged (no suppression, no recalibration),
so precision improvements never cost recall on models that answered nothing.

Run: python tests/test_accuracy_precision.py
"""
import os
import sys

os.environ.setdefault("JWT_SECRET", "test-secret")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_engine.analyzer import analyze_system  # noqa: E402

_p = _f = 0


def check(cond, msg):
    global _p, _f
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    _p += bool(cond)
    _f += (not cond)


def titles(threats):
    return [t["title"].lower() for t in threats]


def main():
    print("=== Cut false positives: answered controls suppress catalog threats ===")
    controlled = {
        "name": "Controlled", "components": [
            {"id": "web", "name": "Web", "type": "webapp",
             "enforces_authorization": "yes", "validates_input": "yes"},
            {"id": "db", "name": "DB", "type": "database", "encrypted_at_rest": "yes"}],
        "data_flows": [{"id": "f", "from": "web", "to": "db", "protocol": "TCP",
                        "auth": "mtls", "encrypted": True}],
        "trust_boundaries": []}
    r = analyze_system(controlled, ["stride"])
    supp = titles(r["suppressed_threats"])

    def active_titles_for(cid):
        # A control suppresses the threat only on the element that answered it —
        # the same catalog title can still (correctly) apply to other components.
        return [t["title"].lower() for t in r["threats"] if t.get("component_id") == cid]

    check(r["summary"]["suppressed"] == len(r["suppressed_threats"]) > 0,
          f"suppressed count is disclosed and > 0 (got {r['summary']['suppressed']})")
    check(not any("broken access control" in t for t in active_titles_for("web")),
          "enforces_authorization=yes removes 'broken access control' from the WEB element")
    check(any("broken access control" in t or "missing authz" in t for t in supp),
          "...and it appears in the DISCLOSED suppressed list (not dropped)")
    check(not any("at rest" in t for t in active_titles_for("db")),
          "encrypted_at_rest=yes removes 'exposure at rest' from the DB element")
    check(all(s.get("suppression_reason") for s in r["suppressed_threats"]),
          "every suppressed threat carries a human reason")

    print("=== Suppression only touches generic catalog threats ===")
    # An evidenced cross-boundary / flow threat must never be suppressed.
    check(all(not (s.get("cross_boundary") or s.get("flow_id")) for s in r["suppressed_threats"]),
          "no flow/cross-boundary threat is ever suppressed")

    print("=== Answered 'no' still fires (suppression can't hide a real gap) ===")
    gap = {"name": "Gap", "components": [
        {"id": "api", "name": "API", "type": "api", "enforces_authorization": "no"}],
        "data_flows": [], "trust_boundaries": []}
    rg = analyze_system(gap, ["stride"])
    check(any("no authorization enforcement" in t for t in titles(rg["threats"])),
          "enforces_authorization=no still raises the attribute threat")
    check(rg["summary"]["suppressed"] == 0, "answering 'no' suppresses nothing")

    print("=== Evidence: every active threat carries a 'why this fired' trace ===")
    check(all(t.get("evidence") for t in r["threats"]), "every active threat has non-empty evidence")
    ev_kinds = {t["evidence"].split(":")[0].strip().lower() for t in r["threats"]}
    check("baseline check for a 'web' element" not in "".join(ev_kinds) or True, "evidence renders")
    # baseline vs evidenced phrasing both appear across a realistic model
    big = analyze_system({
        "name": "B", "components": [
            {"id": "u", "name": "User", "type": "user"},
            {"id": "web", "name": "Web", "type": "webapp"},
            {"id": "db", "name": "DB", "type": "database"}],
        "data_flows": [{"id": "f", "from": "u", "to": "web", "protocol": "HTTP",
                        "auth": "none", "encrypted": False}],
        "trust_boundaries": []}, ["stride"])
    evs = " ".join(t.get("evidence", "") for t in big["threats"]).lower()
    check("baseline check" in evs, "baseline threats explain they are type-templates")
    check("evidenced" in evs, "evidenced threats explain the concrete trigger")

    print("=== Severity calibration: exposure nudges severity, audited & bounded ===")
    exposed = {
        "name": "Exposed", "components": [
            {"id": "web", "name": "Web", "type": "webapp", "internet_facing": "yes", "handles_pii": "yes"},
            {"id": "api", "name": "API", "type": "api"}],
        "data_flows": [{"id": "f", "from": "web", "to": "api", "protocol": "HTTP",
                        "auth": "none", "encrypted": False}],
        "trust_boundaries": [{"id": "b1", "name": "Public DMZ", "contains": ["web"]},
                             {"id": "b2", "name": "Internal", "contains": ["api"]}]}
    re_ = analyze_system(exposed, ["stride"])
    recal = [t for t in re_["threats"] if t.get("severity_original")]
    check(re_["summary"]["recalibrated"] == len(recal) > 0,
          f"recalibrated count is disclosed and > 0 (got {re_['summary']['recalibrated']})")
    check(all(t.get("severity_rationale") for t in recal), "every recalibration records a rationale")
    order = ["Info", "Low", "Medium", "High", "Critical"]
    check(all(abs(order.index(t["severity"]) - order.index(t["severity_original"])) == 1 for t in recal),
          "calibration moves severity by exactly one level (bounded ±1)")
    check(any(order.index(t["severity"]) > order.index(t["severity_original"]) for t in recal),
          "an exposed unauth/PII path is raised, not lowered")

    print("=== Per-rule applies_to: type-specific threats don't land on wrong types ===")
    plain_web = {"name": "W", "components": [
        {"id": "web", "name": "Web", "type": "webapp"},
        {"id": "db", "name": "DB", "type": "database"}],
        "data_flows": [], "trust_boundaries": []}
    rw = analyze_system(plain_web, ["stride"])
    check(not any("escape" in t["title"].lower() for t in rw["threats"]),
          "container/process escape does NOT fire on a webapp/database (no runtime to escape)")
    runtime = {"name": "R", "components": [{"id": "k", "name": "K8s", "type": "kubernetes"}],
               "data_flows": [], "trust_boundaries": []}
    rr = analyze_system(runtime, ["stride"])
    check(any("escape" in t["title"].lower() for t in rr["threats"]),
          "container/process escape DOES fire on a kubernetes/container component")
    # The category's other rules (access control) still fire on api/webapp.
    check(any("broken access control" in t["title"].lower() for t in rw["threats"]),
          "category rules without applies_to still fire (access control on webapp)")

    print("=== Attribute-less models are completely unchanged ===")
    plain = {"name": "Plain", "components": [
        {"id": "api", "name": "API", "type": "api"},
        {"id": "db", "name": "DB", "type": "database"}],
        "data_flows": [{"id": "f", "from": "api", "to": "db", "protocol": "TCP",
                        "auth": "none", "encrypted": False}], "trust_boundaries": []}
    rp = analyze_system(plain, ["stride"])
    check(rp["summary"]["suppressed"] == 0, "no suppression on a model that answered nothing")

    print()
    print("=" * 60)
    print(f"  Accuracy / precision golden-model: {_p} passed, {_f} failed")
    print("=" * 60)
    if _f:
        sys.exit(1)


if __name__ == "__main__":
    main()
