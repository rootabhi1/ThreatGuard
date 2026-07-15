#!/usr/bin/env python3
"""Precision benchmark for the threat engine.

Runs the analyzer over a set of reference systems and reports, per system:

  * Structural metrics (no labels needed) — total threats, evidenced/baseline
    split, evidenced ratio, threats-per-component. These track drift over time.
  * Labelled assertions (expert ground truth) — `must_be_evidenced` /
    `must_not_be_evidenced` from benchmark/labels/<system>.json. These measure
    whether the tool's `evidenced` tier matches expert judgment.

The evidenced tier is the precision signal introduced in #34; this harness makes
its accuracy measurable so later phases (per-rule predicates, data
classification) can be validated with numbers rather than guesses. See #32.

Usage:
    python3 benchmark/run_benchmark.py            # human-readable report
    python3 benchmark/run_benchmark.py --json     # machine-readable metrics

Exit code: 0 if every labelled assertion holds, 1 otherwise (usable as a CI gate).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from threat_engine.analyzer import analyze_system  # noqa: E402


def _matches(threat: dict, label: dict) -> bool:
    return (threat.get("component_name") == label["component"]
            and label["title_contains"].lower() in (threat.get("title") or "").lower())


def _check_system(system_path: Path, labels: dict) -> dict:
    system = json.loads(system_path.read_text())
    methodologies = labels.get("methodologies", ["stride", "linddun", "pasta"])
    result = analyze_system(system, methodologies, use_llm=False)
    threats = result["threats"]
    by_tier = result["summary"]["by_tier"]
    n_comp = max(1, len(system.get("components", [])))
    evidenced = [t for t in threats if t.get("tier") == "evidenced"]

    failures: list[str] = []
    for lab in labels.get("must_be_evidenced", []):
        if not any(_matches(t, lab) for t in evidenced):
            failures.append(f"MISSING evidenced: {lab['component']} ~ '{lab['title_contains']}'")
    for lab in labels.get("must_not_be_evidenced", []):
        if any(_matches(t, lab) for t in evidenced):
            failures.append(f"WRONGLY evidenced: {lab['component']} ~ '{lab['title_contains']}'")

    n_labels = len(labels.get("must_be_evidenced", [])) + len(labels.get("must_not_be_evidenced", []))
    return {
        "system": labels.get("system", system_path.name),
        "total": result["summary"]["total"],
        "evidenced": by_tier["evidenced"],
        "baseline": by_tier["baseline"],
        "evidenced_ratio": round(by_tier["evidenced"] / max(1, result["summary"]["total"]), 3),
        "threats_per_component": round(result["summary"]["total"] / n_comp, 1),
        "labels_checked": n_labels,
        "labels_passed": n_labels - len(failures),
        "failures": failures,
    }


def main() -> int:
    as_json = "--json" in sys.argv
    labels_dir = HERE / "labels"
    systems_dir = HERE / "systems"

    reports = []
    for labels_file in sorted(labels_dir.glob("*.json")):
        labels = json.loads(labels_file.read_text())
        reports.append(_check_system(systems_dir / labels["system"], labels))

    ok = all(not r["failures"] for r in reports)

    if as_json:
        print(json.dumps({"passed": ok, "systems": reports}, indent=2))
        return 0 if ok else 1

    print("=" * 72)
    print("  THREAT-ENGINE PRECISION BENCHMARK")
    print("=" * 72)
    for r in reports:
        print(f"\n  {r['system']}")
        print(f"    total={r['total']}  evidenced={r['evidenced']}  baseline={r['baseline']}"
              f"  ratio={r['evidenced_ratio']}  per-component={r['threats_per_component']}")
        print(f"    labels: {r['labels_passed']}/{r['labels_checked']} passed")
        for f in r["failures"]:
            print(f"      ✗ {f}")
    total_labels = sum(r["labels_checked"] for r in reports)
    passed_labels = sum(r["labels_passed"] for r in reports)
    agg_total = sum(r["total"] for r in reports)
    agg_ev = sum(r["evidenced"] for r in reports)
    pct = round(100 * passed_labels / max(1, total_labels), 1)
    print("\n" + "=" * 72)
    # Accuracy = correctness vs expert labels (the metric that should go up).
    print(f"  ACCURACY (labelled precision): {passed_labels}/{total_labels} assertions held "
          f"({pct}%)  [{'PASS' if ok else 'FAIL'}]  across {len(reports)} systems")
    # Composition is NOT accuracy — it just describes the evidenced/total mix and
    # shifts with catalog size, so don't read it as a quality score.
    print(f"  composition (not accuracy):    {agg_ev}/{agg_total} evidenced "
          f"({round(agg_ev / max(1, agg_total), 3)} ratio)")
    print("=" * 72)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
