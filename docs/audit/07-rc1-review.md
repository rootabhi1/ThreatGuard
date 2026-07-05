# RC1 — Release Candidate Assessment (v0.1.0 Community Preview)

_Sprint 1: Public Launch Readiness · Date: 2026-07-05_
_Merges Phases 9 (Community), 10 (Production Readiness), 11 (Release Checklist)._
_Written from the maintainer's seat, preparing the first public release._

---

## 1. Community Readiness Review

| Item | Status | Evidence |
|------|--------|----------|
| Contributor onboarding | ✅ | `CONTRIBUTING.md`: layout, one-command + manual setup, test/lint commands, conventions, PR flow |
| Issue templates | ✅ | `.github/ISSUE_TEMPLATE/` bug + feature forms; `config.yml` disables blank issues, routes security → private advisories, questions → Discussions |
| PR workflow | ✅ | `.github/PULL_REQUEST_TEMPLATE.md` with a test/lint checklist; CI runs on every PR |
| Discussions | ✅ | Enabled (verified via API); `SUPPORT.md` points there |
| Labels | ✅ | `good first issue`, `help wanted`, `documentation`, `security` present |
| Good First Issues | ✅ | #12–#16 opened from real findings; **already picked up** — external PR #17 addresses #13 |
| Documentation consistency | ✅ | 75/75 relative links resolve; README/nested-README reconciled; "8→7 suites" corrected repo-wide (historical audit reports intentionally unchanged) |
| Roadmap consistency | ✅ | `ROADMAP.md` aligns with `KNOWN_LIMITATIONS.md` and the tracked issues (#12/#15/#16 map to roadmap items) |

**Live signal:** within this sprint the repo already attracted a Dependabot flow
(PRs #8–#11) and a human contributor (#17). Community scaffolding works.

---

## 2. Production Readiness Scorecard

Scores are for a **v0.1 Community Preview** (self-hosted, single-instance),
not a hardened multi-tenant SaaS. Each includes evidence.

### Security — 8/10
JWT with refresh-token rotation + revocation, bcrypt, account lockout, per-IP
rate limiting; RBAC + per-resource ownership; **secure-by-default verified by a
test that calls every route anonymously**; parameterised SQL (whitelisted dynamic
columns); XSS fixed in reports; safe CORS default; security headers; dependency
CVEs patched; CodeQL + secret scanning + Dependabot enabled; a control-by-control
`SECURITY_ARCHITECTURE.md`. _Deductions:_ no CSP yet (#15), CSV formula-injection
(#16), single-tenant trust model, prompt-injection bounded but present.

### Architecture — 7/10
Clean separation (`app` / `auth` / `db` / `threat_engine`), documented with
Mermaid diagrams; rules-first with a fail-safe optional LLM layer. _Deductions:_
the root/`threat-modeler/` nested layout, single-instance/SQLite only, a couple
of helpers still living in `app.py`.

### Code Quality — 7/10
`ruff` clean on real-bug rules; 7 executing test suites incl. a 119-check
whole-product sweep; dead/stale code removed (a never-run test suite and a stale
CLI both found and fixed). _Deductions:_ deferred cosmetic-lint debt (#12), some
large modules, a custom (non-pytest) test harness.

### Documentation — 9/10
README (overview, why, principles, security, config, examples, contributing),
ARCHITECTURE, SECURITY, SECURITY_ARCHITECTURE, CONTRIBUTING, FAQ,
KNOWN_LIMITATIONS, ROADMAP, CHANGELOG, SUPPORT, CODE_OF_CONDUCT, a worked
`examples/` set, a full `docs/audit/` trail, and an engineering notebook.
_Deduction:_ a few areas could go deeper; historical reports intentionally frozen.

### Maintainability — 8/10
CI (lint+test on 3.11/3.12), CodeQL, secret scanning, Dependabot, branch
protection; a decision log and audit trail; clean, small-commit history.
_Deductions:_ nested layout, custom harness, single maintainer.

### Developer Experience — 8/10
`make dev` / `run.sh` one-command boot with dev defaults; `make setup/test/lint`;
working examples and CLI; troubleshooting docs. _Deductions:_ Windows lacks a
one-command path (Make is Unix-first); no devcontainer yet.

### Community Readiness — 8/10
Governance docs, templates, labels, good first issues, Discussions, and a live
external contributor. _Deductions:_ solo maintainer, no response SLA, no track
record yet (expected for a new project).

### Production Readiness — 6/10
Boots, tested, CI-gated, hardened, installs cleanly; suitable for small,
self-hosted, internal use with the documented hardening. _Deductions:_
single-instance/SQLite, in-process rate-limit/lockout state, no CSP, no
horizontal scale, LLM output quality is the operator's responsibility. Honest for
a **preview** — ready to use and evaluate, not to run unattended as critical
multi-tenant infrastructure.

**Composite:** strong for a v0.1 Community Preview. Documentation and security
lead; production hardening and layout are the known growth areas (all tracked).

---

## 3. Final Release Checklist

| Check | Status | Evidence |
|-------|--------|----------|
| CI passing | ✅ | `CI` success on `main` (latest push) |
| CodeQL passing | ✅ | `CodeQL` success on `main` |
| Secret scanning enabled | ✅ | enabled via API (+ gitleaks workflow green) |
| Dependabot enabled | ✅ | alerts on; PRs #8–#11 open |
| Branch protection enabled | ✅ | `main` requires py3.11, py3.12, gitleaks |
| README complete | ✅ | overview, why, principles, install, config, security, examples, contributing, docs index; status/maturity + data-handling callout added |
| Architecture docs complete | ✅ | `ARCHITECTURE.md` + `docs/security/SECURITY_ARCHITECTURE.md` |
| Security docs complete | ✅ | `SECURITY.md` + `SECURITY_ARCHITECTURE.md` + `docs/audit/02` |
| Examples working | ✅ | 3 example systems parse & analyze (64/105/145 threats); CLI verified end-to-end |
| Installation verified | ✅ | clean virtualenv install of `requirements.txt` resolves and runs |
| Quick Start verified | ✅ | `make dev` / `run.sh` boot with dev defaults; manual steps validated |
| Tests passing | ✅ | 7/7 suites; `ruff` clean |
| Release notes prepared | ✅ | `docs/releases/v0.1.0.md` |

---

## 4. Final Repository Audit

| Check | Result |
|-------|--------|
| Broken links | ✅ 75/75 relative links resolve |
| Broken images | ✅ all screenshot references exist |
| Broken badges | ✅ CI/CodeQL badges point to real workflow files; shields badges are static |
| Broken examples | ✅ all example systems analyze; example reports generated from the engine |
| Broken commands | ✅ `make` targets, `run.sh`, test loop, and CLI commands all executed successfully |
| Broken scripts | ✅ `run.sh` syntax-checked and boots; `Makefile` targets run |
| Typos | ◐ no blocking typos found on review; not exhaustively spell-checked |
| Inconsistent versions | ✅ app reports `2.1` consistently; public tag will be `v0.1.0` (documented in `CHANGELOG.md`) |

**Fixed during RC1:** README "8 files → 7 files"; added a status/maturity +
data-handling callout, naming/subfolder clarity, a Contributing section, and
security evidence links.

---

## 5. Launch Recommendation

# 🟢 Ready to Launch — as v0.1.0 Community Preview

**Evidence:** CI, CodeQL, and secret scanning are green on `main`; branch
protection, Dependabot, and secret scanning are enabled; installation, quick
start, examples, and 7 test suites are verified; security is hardened (CVEs
patched, secure-by-default proven, XSS fixed); documentation is comprehensive and
link-clean; and the community scaffolding is already attracting real activity.

The "Community Preview" framing correctly sets expectations: this is ready to be
**shared, used, and contributed to**, with the honest caveat (stated in the
README and `KNOWN_LIMITATIONS.md`) that it is self-hosted, single-instance, and
produces drafts for human review — not a production multi-tenant service.

**Not blocking (post-launch triage):**
- Review/merge or close Dependabot PRs #8–#11 (some are major bumps — test first).
- Review external contributor PR #17 (approve its workflow run).
- Burn down tracked issues: CSP (#15), CSV formula-injection (#16), cosmetic lint
  (#12), example assets (#13, #14).
- Optional: set a real `LICENSE` copyright holder; produce the social-preview
  image (Phase 8 recommendation).

**Do not tag yet** — hold `v0.1.0` until this RC1 review is accepted, so any
last-minute fix lands in the first release instead of a quick `v0.1.1`.
