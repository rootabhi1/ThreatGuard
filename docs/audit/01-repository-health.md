# Phase 1 — Repository Health Report

_Sprint 1: Public Launch Readiness (v0.1 Community Preview)_
_Audit date: 2026-07-05 · Scope: full repository (`main`)_

## Snapshot

The codebase is in good shape: the app boots, all 8 test suites pass, secure-by-default has been verified, the two READMEs are reconciled, the version is unified to `2.1`, and branches are clean (`main` + `gh-pages`, no stray PRs). The gaps for a Community Preview are mostly **repository plumbing and governance**, not application code. The most important finding is that **CI is not actually running.**

Findings are rated Critical / High / Medium / Low. Each has a rationale and a fix. Items mapped to a later phase are implemented there; hygiene items are implemented in Phase 1.

## 🔴 Critical

None that block public sharing structurally. (The deep secrets / authorization review is Phase 2; a first pass shows no tracked secrets — `.env` is gitignored.)

## 🟠 High

| # | Finding | Why it matters | Fix | Phase |
|---|---------|----------------|-----|-------|
| H1 | **CI workflows are misplaced.** They live under `threat-modeler/.github/workflows/`; GitHub only runs workflows in the **repo-root** `.github/workflows/`. `Threat Model CI` (pytest) has therefore never run, and PRs have no status checks. | No automated safety net for contributors or maintainers. | Move to root `.github/workflows/` with `working-directory: threat-modeler`. | 7 |
| H2 | **Azure deploy workflow triggers on every push to `main`.** Currently inert because it's misplaced; relocating it naïvely would silently enable auto-deploy on a public repo. | Accidental deploys / secret exposure risk. | On relocation, gate behind `workflow_dispatch` / tag / protected environment — never bare `push`. | 7 |
| H3 | **Missing OSS governance files** — no `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `ROADMAP.md`, or issue/PR templates. | Expected baseline for a community launch; their absence blocks contribution and responsible disclosure. | Add them. | 3 & 6 |

## 🟡 Medium

| # | Finding | Fix | Phase |
|---|---------|-----|-------|
| M1 | **Nested layout** (`app in threat-modeler/`, meta at root) is the root cause of the duplication (two READMEs, two `.env.example`, CI-path confusion). | Documented in the READMEs now; flattening is a larger refactor deferred to Sprint 2. | 2 (Sprint) |
| M2 | **Large generated artifact at repo root** — `threat_model_1_20260513_100142.html` (1.3 MB). | Relocate into `examples/reports/` (keep, don't delete). | 1 |
| M3 | **`system.json` at root** is a sample CLI input referenced by the CLI default and the CI workflow. | Move into `examples/` and update the CLI default + workflow path together. | 5 |
| M4 | **No linter / formatter config** (ruff/black) and **no CodeQL / secret scanning**. | Add. | 7 |

## 🟢 Low

- **L1** Duplicate `.env.example` (root + nested) — consolidate or cross-reference.
- **L2** `run.sh`, `cli/atm_cli.py`, `deploy/` are undocumented — add a one-line pointer.
- **L3** README FastAPI badge says `0.110+` (now `0.138`). — _fixed in Phase 1._
- **L4** No `.editorconfig`.

## Already solid ✅

`.gitignore` (env / pycache / data / uploads), MIT `LICENSE`, `dependabot.yml` (pip + github-actions), `.dockerignore`, the 8-suite test battery (incl. a 119-check whole-product sweep with an anonymous secure-by-default pass), reconciled docs, unified version, no tracked secrets.

## Dependency note (no action)

`python-multipart`, `anthropic`, and `openai` look unused to a naïve grep but are **required** — `python-multipart` powers multipart file uploads; `anthropic`/`openai` are lazily imported by the provider layer (`threat_engine/llm.py`). They must not be removed.

## Improvement plan (sprint order)

1. **Fix CI** — relocate workflows to root, add a lint + test pipeline, gate deploy. _(Phase 7, High priority)_
2. **Governance docs** — CONTRIBUTING / SECURITY / CODE_OF_CONDUCT / CHANGELOG / ROADMAP. _(Phase 3)_
3. **Issue & PR templates.** _(Phase 6)_
4. **CodeQL + secret scanning + lint/format config.** _(Phase 7)_
5. **Relocate root artifacts** into `examples/` / `docs/`. _(Phases 1 & 5)_
6. **Branding** — description, topics, badges. _(Phase 8)_

## Phase 1 fixes implemented

- Relocated the legacy 1.3 MB sample report from the repo root into `examples/reports/`.
- Corrected the FastAPI version badge in the root README.
- Saved this report to `docs/audit/` as a permanent engineering record.
