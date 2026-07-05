# Phase 3 — Documentation + Developer Experience

_Sprint 1: Public Launch Readiness (v0.1 Community Preview)_
_Date: 2026-07-05_

## Objective

Expand Phase 3 beyond the original documentation list into
**Documentation + Developer Experience**: produce the governance and reference
docs a first-time contributor and an evaluating security engineer need, written
in a professional, concise, practical tone. No product features, no behavior
changes.

## Delivered

| Document | Purpose | Audience |
|----------|---------|----------|
| `CONTRIBUTING.md` | Layout, setup, tests, conventions, PR flow | First-time contributor |
| `CODE_OF_CONDUCT.md` | Community standards (Contributor Covenant 2.1) | Everyone |
| `SECURITY.md` | Private disclosure, posture summary, hardening | Security researchers / operators |
| `SUPPORT.md` | Where to ask, report, request — GitHub-native | Users |
| `CHANGELOG.md` | Keep a Changelog; v0.1.0 preview baseline | Everyone |
| `ROADMAP.md` | Near/mid/long-term direction | Users / contributors |
| `KNOWN_LIMITATIONS.md` | Candid AI-output caveats, un/supported cases, data flow | Evaluators |
| `ARCHITECTURE.md` | Components, data flow, trust boundaries, LLM flow (Mermaid) | Security engineers |
| `FAQ.md` | Why AI, LLMs, local models, accuracy, data, self-host | Users |
| `docs/images/README.md` | Visual-asset catalog + placeholders | Contributors |

README additions: **Why this project exists**, **Design principles** (AI assists
— not replaces; human validation required; secure by default; framework
agnostic; explainable outputs), and a **documentation index** table.

## Design decisions

- **GitHub-native contact channels.** No email/contact was invented. Security
  reports use GitHub Private Vulnerability Reporting; questions use Discussions;
  bugs/features use Issues. The maintainer can add a direct email later.
- **Mermaid for architecture diagrams.** Diagrams live as text, render on GitHub,
  and can't drift against a stale binary export. `docs/images/` therefore
  *catalogs and points to* canonical assets instead of duplicating them — the
  same anti-duplication principle applied to the READMEs earlier.
- **Honesty over polish.** `KNOWN_LIMITATIONS.md` is deliberately blunt about
  experimental AI output, the single-instance/SQLite model, heuristic boundary
  inference, and data egress to LLM providers.
- **Versioning noted, not forced.** The app reports internal `2.1`; the first
  public tag will be `v0.1.0`. The changelog states this openly rather than
  silently renumbering.

## Quality bar

- ✅ Report in `docs/audit/` (this file)
- ✅ Tests passing — 8/8 suites (no code changed this phase)
- ✅ Small logical commits — 7 commits, grouped by concern
- ✅ No regressions
- ✅ Documentation updated (this *is* the documentation phase)

## Commits

1. `docs: add CONTRIBUTING and CODE_OF_CONDUCT`
2. `docs: add SECURITY policy and SUPPORT guide`
3. `docs: add CHANGELOG, ROADMAP, and KNOWN_LIMITATIONS`
4. `docs: add ARCHITECTURE with Mermaid diagrams and docs/images catalog`
5. `docs: add FAQ`
6. `docs(readme): add Why-this-project-exists, Design Principles, and a docs index`
7. `docs(audit): add Phase 3 report` (this commit)

## Follow-ups for later phases

- Phase 6: issue/PR templates referenced by `SUPPORT.md`/`CONTRIBUTING.md` need to
  be created so the "use the Bug report template" instructions resolve.
- Phase 7: CI must run at the repo root; `CONTRIBUTING.md`'s "tests must pass on
  every PR" only becomes enforceable once CI is wired.
- Phase 8: branding assets (`banner`, `social-preview`) are placeholders in
  `docs/images/`.
