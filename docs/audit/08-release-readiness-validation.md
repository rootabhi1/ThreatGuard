# Release Readiness Validation (RRV) — v0.1.0 Community Preview

_Date: 2026-07-05 · Scope: validation only (no features, no refactors, no
architectural changes, no pytest migration)._

---

## 1. Executive Summary

The repository is **ready for its first public release** as a v0.1.0 Community
Preview. Across eight validation phases, every gating item is green and verified
with evidence: CI/CodeQL/secret-scanning pass on `main`; a brand-new-contributor
flow (`make setup/dev/test`) works from a clean machine; the full product path
(auth → analyze → HTML/PDF/CSV/Markdown export → CLI → API) runs end-to-end;
documentation is link-clean and internally consistent; the Pages site is accurate
with no broken links/images; and a security sweep found no secrets, tokens, or
debug artifacts in tracked files.

This validation also **fixed** four real issues without changing behavior:
CI diagnostics (failures were being collapsed/hidden), a Mermaid rendering bug in
the architecture diagrams, stale content on the Pages site, and a `.gitignore`
gap. None were release blockers; all are now resolved.

**Recommendation: 🟢 GO** (evidence in §9).

---

## 2. CI Validation Report

**History (evidence, not guesswork).** The only two CI *failures* ever recorded
were `b92accc` and `e4e04bb`. Root cause, reproduced in a clean virtualenv:
`tests/test_new_endpoints.py` required `pytest` (not a dependency) and threw
`ModuleNotFoundError: No module named 'pytest'`; it was also written against an
old API. It was a pytest-style file that the `python test_*.py` loop imported
without running — a silent no-op locally. **Fixed in `521a5e7`** by removing the
stale, redundant suite (its coverage is in `test_full_product.py`). **Every push
to `main` since — 5 runs — is green.**

**Current status:** CI ✅, CodeQL ✅, Secret scan (gitleaks) ✅ on `main`.
Dependabot ✅ (PRs #8–#11 open). Branch protection ✅ (`main` requires py3.11,
py3.12, gitleaks). The `action_required` run is contributor PR #17 awaiting the
standard first-time-contributor workflow approval — not a failure.

**Diagnostics improved (this validation).** The test step previously wrapped each
suite in a collapsed `::group::`, which *hid* output. It now:
- runs each suite as a script (unchanged framework — no pytest),
- prints per-suite **pass/fail with elapsed time**,
- on failure emits a **GitHub `::error` annotation** pinned to the file and
  prints the **full traceback** (never collapsed/hidden),
- prints a **final PASS/FAIL summary** with total time and exits non-zero.

Both paths were verified locally (pass path: 7/7 in ~50 s; fail path: traceback +
annotation + non-zero exit).

---

## 3. Sanity Test Report

**Fresh-machine flow** (clean virtualenv, following only the README):
`make setup` → deps install ✅ · `make lint` → ruff clean ✅ · `make test` →
7/7 suites ✅ · `make dev` → boots on :8000 ✅.

**End-to-end product path** (via the running app):

| Step | Result |
|------|--------|
| Health / auth (login) | ✅ |
| Create Release → Feature → Threat Model | ✅ |
| Analyze (`simple-api` example) | ✅ 64 threats |
| Export HTML | ✅ 474 KB, valid |
| Export PDF | ✅ valid `%PDF` |
| Export CSV risk register | ✅ 65 rows |
| Export Markdown | ✅ 134 KB |
| CLI (`atm_cli.py` on `saas-app`) | ✅ 71 threats |

**Examples:** all three system definitions parse and analyze (64 / 105 / 145
threats). Every documented feature works.

---

## 4. GitHub Pages Report

Validated against the served source (`gh-pages/index.html`); the sandbox cannot
fetch `*.github.io` directly.

- **Broken links:** none (nav anchors `#features/#quickstart/#api/#troubleshoot`
  all resolve; GitHub URLs valid; `sample-report.html` present).
- **Broken images:** none (the landing page is CSS-driven; no `<img>` refs).
- **Accuracy fixes applied:** removed a mention of the deleted
  `feature/enhancements` branch, replaced the stale "22 endpoints" heading, and
  surfaced `make dev` in the quick start.

The site now represents the repository accurately. _(Minor, non-blocking:
`gh-pages` still carries a few unused files — `threat-modeler.zip`, a Dockerfile —
that don't affect the served site.)_

---

## 5. Documentation Report

- **Links:** 83/83 relative links across all Markdown resolve.
- **Badges:** CI/CodeQL badges point to real workflow files; shields badges valid.
- **Screenshots:** all three referenced images exist.
- **Mermaid:** fixed a real rendering bug — node labels used `\n` (renders
  literally on GitHub); now `<br>`. All diagrams in `ARCHITECTURE.md` and
  `SECURITY_ARCHITECTURE.md` corrected.
- **Commands:** `make` targets, `run.sh`, the test loop, and CLI commands all
  executed successfully during validation.
- **Versions:** app reports `2.1` consistently; the public tag will be `v0.1.0`
  (documented in `CHANGELOG.md`). No stray old versions in tracked files (matches
  were all in the gitignored `.venv/`).
- **Consistency:** the README/nested-README are reconciled; the "7 suites" count
  is consistent repo-wide (historical audit reports intentionally frozen).

Docs verified: README, ARCHITECTURE, SECURITY, SECURITY_ARCHITECTURE,
CONTRIBUTING, FAQ, ROADMAP, KNOWN_LIMITATIONS, SUPPORT, release notes.

---

## 6. Security Report

Final sweep of **tracked** files (excluding `.venv`):

- **No secrets / tokens / credentials.** The only pattern hits were documentation
  **placeholders** (`sk-ant-xxxx`, `sk-ant-...`).
- **No debug artifacts, temp files, or developer-only config** tracked.
- **`.env.example`** contains placeholders/blanks only.
- **`.gitignore`** covers `.env`, `.venv`, `data/`, `__pycache__`, and now
  `*.db` (added this validation).
- **Docker / workflows** reference secrets via `${{ secrets.* }}` / fail-fast env
  vars — nothing hardcoded.
- **Sample & example reports** contain synthetic data only — no real keys/PII.

Posture (from Phase 2 security audit, unchanged): secure-by-default (tested),
JWT rotation, bcrypt, lockout, rate limiting, RBAC + ownership, XSS fixed, safe
CORS, dependency CVEs patched, CodeQL + secret scanning + Dependabot enabled.

_Minor, non-blocking:_ `threat-modeler-XXX` in the Azure deploy guide is a
substitution placeholder (a documented "replace-with-your-value"), not incomplete
content.

---

## 7. Release Readiness Report (Phase 8 checklist)

| Item | Status | Evidence |
|------|--------|----------|
| CI green | ✅ | `main` latest push |
| CodeQL green | ✅ | `main` latest push |
| Dependabot green | ✅ | enabled; PRs #8–#11 |
| Branch protection | ✅ | requires py3.11, py3.12, gitleaks |
| README complete | ✅ | status/maturity + data-handling + contributing + docs index |
| GitHub Pages updated | ✅ | stale content fixed |
| Examples verified | ✅ | 3 systems analyze; reports generated |
| Release notes ready | ✅ | `docs/releases/v0.1.0.md` |
| Version correct | ✅ | `2.1` internal, `v0.1.0` public |
| Screenshots correct | ✅ | present and current |
| Badges correct | ✅ | CI/CodeQL/license resolve |
| Roadmap updated | ✅ | aligns with issues #12/#15/#16 |
| Community docs ready | ✅ | CONTRIBUTING, CoC, SUPPORT, templates, labels |
| No TODOs / placeholders | ✅ | none blocking (deploy-guide `XXX` is intentional) |
| No broken links | ✅ | 83/83 resolve |
| No release blockers | ✅ | see §8 |

**Community experience (Phase 7):** understandable in <2 min (README lead +
principles); installable in <10 min (`make dev`); first threat model in <5 min
(paste an example / upload a diagram); contributable without asking
(CONTRIBUTING + templates + good first issues) — **already proven** by external
PR #17 against issue #13.

---

## 8. Remaining Risks (all non-blocking, tracked)

- **Post-launch triage:** Dependabot PRs #8–#11 (some major bumps — test before
  merging); external PR #17 (approve its workflow run).
- **Tracked hardening issues:** CSP (#15), CSV formula-injection (#16), cosmetic
  lint (#12), example visual assets (#13/#14).
- **Preview-level production posture:** single-instance / SQLite; in-process
  rate-limit and lockout state. Documented in `KNOWN_LIMITATIONS.md`.
- **Cosmetic:** `gh-pages` carries unused files; `LICENSE` copyright holder is the
  GitHub handle (maintainer may set a real name); Windows lacks a one-command path
  (Make is Unix-first).

None of these block a **Community Preview**; all are disclosed.

---

## 9. Launch Recommendation

# 🟢 GO — release as v0.1.0 Community Preview

**Evidence:** CI, CodeQL, and secret scanning are green on `main`; branch
protection, Dependabot, and secret scanning are enabled; a clean-machine
`make setup/dev/test` works; the full product path exports HTML/PDF/CSV/Markdown
and the CLI runs; 83/83 doc links resolve and Mermaid renders correctly; the
Pages site is accurate with no broken links/images; and the security sweep found
no secrets or artifacts. The four issues surfaced during validation were fixed.

The "Community Preview" label honestly frames the known preview-level limits
(self-hosted, single-instance, outputs are drafts for human review).

**Tagging:** per the process, the `v0.1.0` tag should be created **only after**
this GO is accepted by the Product Owner, so any last-minute change lands in the
first release. Everything required for the tag (release notes, changelog,
version) is prepared.
