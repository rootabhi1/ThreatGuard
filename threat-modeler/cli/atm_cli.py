#!/usr/bin/env python3
"""
cli/atm_cli.py — Automated Threat Modeler CLI
Wraps the REST API for use in CI/CD pipelines.

Usage:
  python atm_cli.py analyze --system-file system.json [options]

Exit codes:
  0 — analysis complete, no threats above threshold
  1 — threats found above threshold (CI should fail)
  2 — error / misconfiguration
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path


DEFAULT_ATM_URL = os.getenv("ATM_URL", "http://localhost:8000")
THRESHOLD_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _api(method: str, path: str, body: dict | None = None, token: str = "") -> dict:
    url  = DEFAULT_ATM_URL.rstrip("/") + path
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"[atm-cli] API error {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(2)


def _login(username: str, password: str) -> str:
    import urllib.parse
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req  = urllib.request.Request(DEFAULT_ATM_URL + "/api/auth/login", data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read()).get("access_token", "")
    except Exception as e:
        print(f"[atm-cli] Login failed: {e}", file=sys.stderr)
        sys.exit(2)


def cmd_analyze(args: argparse.Namespace) -> int:
    # Auth
    token = os.getenv("ATM_TOKEN") or ""
    if not token:
        user = os.getenv("ATM_USER", "admin")
        pw   = os.getenv("ATM_PASS", "admin")
        token = _login(user, pw)

    # Load system definition
    system_file = Path(args.system_file)
    if not system_file.exists():
        print(f"[atm-cli] System file not found: {system_file}", file=sys.stderr)
        sys.exit(2)
    system_def = json.loads(system_file.read_text())

    frameworks = [f.strip() for f in args.frameworks.split(",")]
    payload = {
        "system": system_def.get("system", {"name": system_file.stem}),
        "components":       system_def.get("components", []),
        "data_flows":       system_def.get("data_flows", []),
        "trust_boundaries": system_def.get("trust_boundaries", []),
        "methodologies":    frameworks,
        "use_llm":          args.use_llm,
    }

    print(f"[atm-cli] Analyzing {payload['system'].get('name')} with {frameworks}…")
    result = _api("POST", "/api/analyze", payload, token)

    threats    = result.get("threats", [])
    summary    = result.get("summary", {})
    threshold  = args.threshold.lower()
    t_score    = THRESHOLD_SEVERITY.get(threshold, 3)

    # Count violations
    violations = [
        t for t in threats
        if THRESHOLD_SEVERITY.get(t.get("severity", "info").lower(), 0) >= t_score
    ]

    # Write JSON output
    if args.output_json:
        Path(args.output_json).write_text(json.dumps(result, indent=2))
        print(f"[atm-cli] Full report saved to {args.output_json}")

    # Write Markdown summary
    if args.output_md:
        lines = [
            f"## 🛡 Threat Model — {payload['system'].get('name')}",
            f"",
            f"**Total threats:** {summary.get('total', 0)}  ",
            "**By severity:** " + " · ".join(f"{k}: {v}" for k, v in summary.get("by_severity", {}).items()),
            f"**Threshold:** {threshold.title()} and above  ",
            f"**Violations:** {len(violations)}",
            "",
        ]
        if violations:
            lines += ["### ⚠ Threshold violations", ""]
            lines += [f"- **{t['severity']}** `{t['component_name']}` — {t['title']}" for t in violations[:10]]
            if len(violations) > 10:
                lines += [f"- …and {len(violations) - 10} more"]
        else:
            lines += ["### ✅ No threshold violations found"]
        Path(args.output_md).write_text("\n".join(lines))
        print(f"[atm-cli] Markdown summary saved to {args.output_md}")

    # Print summary
    print(f"[atm-cli] Total: {summary.get('total', 0)} threats · {len(violations)} above {threshold!r} threshold")
    for sev, count in summary.get("by_severity", {}).items():
        marker = "⚠" if THRESHOLD_SEVERITY.get(sev.lower(), 0) >= t_score else " "
        print(f"  {marker} {sev}: {count}")

    if violations:
        print(f"\n[atm-cli] FAIL — {len(violations)} threat(s) at or above {threshold!r} threshold.", file=sys.stderr)
        return 1

    print(f"\n[atm-cli] PASS — no threats above {threshold!r} threshold.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Automated Threat Modeler CLI")
    sub    = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="Run threat analysis on a system definition file")
    analyze.add_argument("--system-file",  default="system.json", help="Path to system.json")
    analyze.add_argument("--frameworks",   default="stride",      help="Comma-separated: stride,dread,linddun,pasta")
    analyze.add_argument("--threshold",    default="high",        choices=["info","low","medium","high","critical"],
                         help="Fail if threats at or above this severity exist (default: high)")
    analyze.add_argument("--use-llm",      action="store_true",   help="Enable Claude LLM enhancement")
    analyze.add_argument("--output-json",  default="",            help="Write full JSON results to file")
    analyze.add_argument("--output-md",    default="",            help="Write Markdown summary to file")

    args = parser.parse_args()
    if args.command == "analyze":
        sys.exit(cmd_analyze(args))
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
