# Phase 5 — Developer Experience

_Sprint 1: Public Launch Readiness (v0.1 Community Preview)_
_Date: 2026-07-05_

## Objective

Complete the Developer Experience items deferred earlier: a one-command local
setup, example threat models, example reports, and example configurations — so a
newcomer can go from clone to a running app (and a sample analysis) in seconds.

## Delivered

- **One-command setup.**
  - A root **`Makefile`**: `make setup | dev | test | lint | clean`.
  - **`run.sh`** now sets **dev-only defaults** for the required secrets
    (`JWT_SECRET`, admin credentials) if they're unset, so `./run.sh` — or
    `make dev` — boots with zero configuration and prints the login. Clearly
    marked *do not use in production*.
- **Example systems** (`examples/systems/`) in the canonical flat format:
  `simple-api.json` (3 components), `saas-app.json` (5), `retail-platform.json`
  (9).
- **Example reports** (`examples/reports/`): `simple-api.md` and
  `simple-api.csv` generated from the engine, plus the earlier full HTML report.
  The rich interactive retail report remains at `docs/sample-report.html`.
- **`examples/README.md`** documenting the format and three ways to use a
  definition: web UI, API (`curl`), and CLI.
- README "Run locally" now leads with the one-command path and links `examples/`.

## Findings & fixes

- **`run.sh` couldn't boot unattended** — it never set `JWT_SECRET`/admin
  credentials, which the app fail-fasts on. Fixed with dev defaults.
- **The `atm_cli.py` CLI was stale against the current API** (a second dormant
  component, like the test file removed in Phase 7):
  - login posted form-encoded `username`; the API expects **JSON `email`**;
  - the analyze payload put `components`/`data_flows` at the top level, but
    `/api/analyze` reads them from `system`, so analyses would have been empty.
  Both repaired; the CLI now runs end-to-end (verified: analyzing
  `simple-api.json` yields 64 threats and writes a Markdown report), and its
  non-zero exit on threshold makes it usable as a CI gate. Defaults align with
  `run.sh` so it works out of the box in dev.
- **Orphaned root `system.json`** (flagged in Phase 1, M3) relocated to
  `examples/systems/saas-app.json` (converted to the flat format); the CLI
  default now points at an example.

## Quality bar

- ✅ Report in `docs/audit/` (this file)
- ✅ Tests passing — 7/7 suites; `ruff check .` clean (includes the CLI edits)
- ✅ Small logical commits (Makefile/run.sh · CLI fix · examples/docs · report)
- ✅ No regressions
- ✅ Docs updated (README run section, examples index)

This closes the Phase 5 gap noted in the Phase 1–7 review.
