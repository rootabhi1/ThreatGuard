# Phase 6 & 7 — Open-Source Readiness + DevSecOps

_Sprint 1: Public Launch Readiness (v0.1 Community Preview)_
_Date: 2026-07-05_

Phases 6 and 7 were done together because the CI (Phase 7) enforces what the
contributor templates (Phase 6) promise.

## Phase 7 — DevSecOps

### The core problem (Phase 1 finding H1)

GitHub Actions only runs workflows in the **repo-root** `.github/workflows/`. The
project's workflows lived under `threat-modeler/.github/workflows/`, so **CI had
never run** and PRs had no checks. Fixed by creating real root workflows.

### What was added

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | push / PR | `ruff` lint + the test suites on a **Python 3.11 & 3.12** matrix |
| `codeql.yml` | push / PR / weekly | CodeQL SAST for Python (`security-and-quality`) |
| `secret-scan.yml` | push / PR / weekly | gitleaks secret scanning over full history |
| `deploy-azure.yml` | **manual only** | relocated from the nested path, gated to `workflow_dispatch`, build path fixed |

The two inert nested workflows were removed. Dependabot (pip + github-actions)
was already configured and now finds the root workflows.

### A real bug the lint baseline caught

Adding `ruff` surfaced a **Python 3.11 portability bug**: `html_report.py` used a
backslash inside an f-string *expression*, which is a `SyntaxError` on Python
3.11 (allowed only from 3.12). The module would not import on the documented
minimum version — but local tests passed because the environment ran 3.12. Fixed
by precomputing the value outside the template. The new **3.11 CI leg** now
guards against regressions of this class.

### Lint policy

`threat-modeler/ruff.toml` enforces real-bug rules (pyflakes `F`, `E4/E7/E9`) and
defers cosmetic style (one-line statements, etc.) as tracked debt, so CI is
meaningful **and** green rather than a wall of style noise. Unused imports and
empty f-strings were auto-fixed across the tree. `ruff check .` is clean.

### Deploy safety

The Azure deploy previously triggered on **every push to `main`** and built from
a root `Dockerfile` that no longer exists. It is now **manual-only** and builds
from `threat-modeler/Dockerfile`, so a public merge can never trigger a deploy.

### Repository-settings recommendations (cannot be set from a PAT)

- Enable **branch protection** on `main` requiring the CI check to pass.
- Enable GitHub **secret scanning + push protection** and **Dependabot security
  alerts** (Settings → Code security).

## Phase 6 — Open-Source Readiness

### Added

- **Issue forms:** `bug_report.yml`, `feature_request.yml`.
- **Chooser config:** blank issues disabled; questions routed to Discussions;
  security reports routed to private GitHub advisories.
- **Pull-request template** with the test + lint checklist.

These resolve the "use the Bug report template" references written in Phase 3.

### Recommendations (maintainer actions)

- **Enable Discussions** (Settings → Features) — `SUPPORT.md` points there.
- **Good first issues:** label small, well-scoped items (doc fixes, added test
  coverage, the tracked lint debt in `ruff.toml`) with `good first issue` and
  `help wanted`.
- **Semantic versioning:** first public tag `v0.1.0`; see `CHANGELOG.md`. Release
  notes for `v0.1.0` are prepared in Phase 11.

## What the first CI run caught

Turning CI on immediately paid for itself. The first run failed (CodeQL and
secret-scan passed) and exposed a problem that had been invisible locally:

- **`tests/test_new_endpoints.py` was a stale, never-executed suite.** It was
  written in **pytest** style (fixtures/classes) while the other suites are
  self-executing scripts, so the `python test_*.py` loop imported it and exited
  0 **without running a single assertion**. It also (a) required `pytest`, which
  is not a dependency, and (b) was written against an **old API** (username +
  form-login; the app now uses email + JSON), so it would have failed wholesale
  had it ever run.
- Every endpoint it targeted (templates, diagram extraction, sharing, release
  diff, status, custom rules) is already covered by the executing
  `test_full_product.py`. It was therefore **removed** rather than rewritten —
  net test coverage is unchanged, and the battery is now **7 genuinely
  executing suites**. Recorded as decision D-016.

This is exactly the class of issue CI exists to catch: a green-looking local run
hiding a test that never actually ran.

## Quality bar

- ✅ Report in `docs/audit/` (this file)
- ✅ Tests passing — 7 suites, verified in a clean virtualenv on the exact CI command
- ✅ `ruff check .` clean
- ✅ Small logical commits (lint baseline; CI workflows; templates)
- ✅ No regressions (behavior unchanged; the only code change is the 3.11 fix)
- ✅ Docs updated where relevant

## Commits

1. `chore(lint): establish ruff baseline and fix Python 3.11 f-string bug`
2. `ci: run lint+test at repo root; add CodeQL and secret scanning; gate deploy`
3. `docs: add issue forms and pull-request template (Phase 6)`
4. `docs(audit): add Phase 6 & 7 report` (this commit)
