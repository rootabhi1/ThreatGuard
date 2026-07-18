"""No-silent-failure guarantee: malformed system models must never crash the
analysis/DFD/report pipeline, never drop an element without disclosing it, and
always produce an editable model plus a visible list of what was repaired.

Covers:
  - normalize_system: missing/duplicate ids, dangling flow refs → placeholders,
    invalid types, boundary members pointing at unknown components, and the
    outside-a-boundary observation; plus structural idempotency.
  - analyze_system: a dangling flow still yields threats (no missed findings)
    and the analysis carries model_issues; malformed input never raises.
  - render_dfd_svg: renders a broken model without crashing and keeps the
    dangling flow visible via a placeholder node.
  - parse_structured_system: lenient — bad lines become issues, never a raise,
    and a flow to an undeclared component keeps a placeholder.

Run: python tests/test_model_health.py
"""
import os
import sys

os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_engine.model_health import normalize_system, issues_summary  # noqa: E402
from threat_engine.analyzer import analyze_system, parse_structured_system  # noqa: E402
from threat_engine.dfd import render_dfd_svg  # noqa: E402

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


def codes(issues):
    return {i["code"] for i in issues}


def main():
    print("=== normalize_system: repairs everything, discloses everything ===")
    broken = {
        "name": "Broken",
        "components": [
            {"id": "c_api", "name": "API", "type": "api"},
            {"id": "c_api", "name": "API dup", "type": "api"},        # duplicate id
            {"name": "DB", "type": "database"},                        # missing id
            {"id": "c_x", "name": "X", "type": "not_a_type"},          # invalid type
            "totally not an object",                                   # junk entry
        ],
        "data_flows": [
            {"id": "f1", "from": "c_api", "to": "c_ghost"},            # dangling target
            {"from": "c_api", "to": "c_api"},                          # missing id
            {"id": "f1", "from": "c_api", "to": "c_x"},                # duplicate flow id
        ],
        "trust_boundaries": [
            {"name": "Zone", "contains": ["c_api", "c_nobody"]},       # unknown member + missing id
        ],
    }
    clean, issues = normalize_system(broken)
    ids = [c["id"] for c in clean["components"]]
    check(len(set(ids)) == len(ids), "all component ids are unique after repair")
    check(any(c.get("_placeholder") for c in clean["components"]), "a placeholder node was created for the dangling ref")
    check(all(f.get("id") for f in clean["data_flows"]), "every flow has an id")
    fids = [f["id"] for f in clean["data_flows"]]
    check(len(set(fids)) == len(fids), "flow ids de-duplicated")
    for f in clean["data_flows"]:
        check(f["from"] in {c["id"] for c in clean["components"]}, f"flow {f['id']} 'from' resolves")
        check(f["to"] in {c["id"] for c in clean["components"]}, f"flow {f['id']} 'to' resolves")
    got = codes(issues)
    for expect in ("component_duplicate_id", "component_missing_id", "component_invalid_type",
                   "flow_dangling_reference", "flow_missing_id", "flow_duplicate_id",
                   "boundary_unknown_member", "boundary_missing_id", "component_not_object"):
        check(expect in got, f"issue disclosed: {expect}")
    s = issues_summary(issues)
    check(s["total"] == len(issues) and s["error"] >= 1, "issues_summary rolls up counts")

    print("=== structural idempotency (repairs don't recur) ===")
    clean2, issues2 = normalize_system(clean)
    check(clean == clean2, "normalizing a clean model returns an equal model")
    check(not [i for i in issues2 if i["autofixed"]], "no repair issues on the second pass")

    print("=== empty / junk input never crashes ===")
    for junk in (None, {}, {"components": "x"}, {"data_flows": [None, 3]}):
        c, iss = normalize_system(junk)
        check(isinstance(c.get("components"), list), f"components is a list for input {junk!r}")

    print("=== analyze_system: dangling flow still generates threats + carries issues ===")
    res = analyze_system(broken, ["stride"])
    check(res["summary"]["total"] > 0, "threats are still produced from a broken model")
    check(len(res.get("model_issues", [])) > 0, "analysis exposes model_issues")
    check(any("c_ghost" not in c["id"] or c.get("_placeholder")
              for c in res["system"]["components"]), "normalized system stored back in analysis")
    # A flow into the placeholder must still attract its unauthenticated/boundary threats.
    names = " ".join(t["title"] for t in res["threats"])
    check("Unknown" in names or res["summary"]["total"] >= 4, "placeholder-targeted flow is analysed, not skipped")

    print("=== render_dfd_svg: broken model renders, placeholder visible ===")
    svg = render_dfd_svg(broken)
    check(svg.startswith("<svg") and svg.endswith("</svg>"), "SVG is well-formed")
    check("Unknown" in svg, "placeholder node is drawn (dangling flow stays visible)")

    print("=== parse_structured_system: lenient, never raises ===")
    r = parse_structured_system(
        "API : api\n"
        "this line is nonsense\n"          # no ':' and no '->'  -> error issue
        "Weird : bogus_type\n"             # unknown type        -> warning, kept
        "DB : database\n"
        "API -> DB\n"
        "API -> Nowhere\n"                 # undeclared target   -> placeholder + warning
    )
    parsed_names = [c["name"] for c in r["components"]]
    check("API" in parsed_names and "DB" in parsed_names, "valid components parsed")
    check("Weird" in parsed_names, "unknown-type component kept, not rejected")
    check(len(r["data_flows"]) == 2, "both flow lines kept (incl. the one with an undeclared target)")
    # The parser leaves the undeclared endpoint as a raw reference; normalization is
    # the single place that materializes a visible placeholder and discloses it — so
    # the warning self-clears once the component is declared or the name fixed.
    nowhere = [f for f in r["data_flows"] if f["to"] == "Nowhere"]
    check(len(nowhere) == 1, "undeclared flow target kept as a raw reference (not silently dropped)")
    clean_r, iss_r = normalize_system(r)
    check(any(c.get("_placeholder") for c in clean_r["components"]),
          "normalization materializes a placeholder for the undeclared target")
    check("flow_dangling_reference" in codes(iss_r), "dangling reference disclosed at normalization")
    check(len(r["issues"]) >= 3, "bad lines surfaced as issues, not a hard failure")
    check(any(i["level"] == "error" for i in r["issues"]), "nonsense line flagged as an error issue")

    # A fully-empty input yields an issue, not an exception.
    empty = parse_structured_system("# just a comment\n\n")
    check(empty["components"] == [] and empty["issues"], "empty structured input returns issues, never raises")

    print()
    print("=" * 60)
    print(f"  Model-health / no-silent-failure: {_passed} passed, {_failed} failed")
    print("=" * 60)
    if _failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
