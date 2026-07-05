# Decision Log

A lightweight record of significant engineering decisions and **why** they were
made — so future contributors (and future us) don't have to reverse-engineer the
reasoning six months from now. Newest first. Each entry: context → decision →
rationale → consequences.

Evidence for many of these lives in [`../audit/`](../audit/).

---

### D-015 · Keep the audit reports in the repo permanently
**Context:** the Sprint produced per-phase reports under `docs/audit/`.
**Decision:** keep them in version control indefinitely.
**Rationale:** they capture *why* things changed (CORS, reportlab, docs) —
engineering history that is expensive to reconstruct later.
**Consequences:** a small amount of repo weight in exchange for durable memory.

### D-014 · Ruff lint: enforce real bugs, defer cosmetics
**Decision:** `ruff.toml` selects pyflakes + real-error rules and ignores
pervasive style (one-line statements, etc.) as tracked debt.
**Rationale:** CI lint should catch genuine problems and stay green, not drown
contributors in style noise on a pre-existing codebase.
**Consequences:** meaningful CI now; a future cosmetic-style cleanup remains an
easy "good first issue."

### D-013 · CI at the repo root; deploy gated to manual
**Context:** workflows lived under `threat-modeler/.github/` and never ran.
**Decision:** put CI/CodeQL/secret-scan at the root; make the Azure deploy
`workflow_dispatch`-only.
**Rationale:** Actions only runs root workflows; auto-deploying a public repo on
push is unsafe.
**Consequences:** real checks on every PR; deploys are deliberate.

### D-012 · Support Python 3.11+ (and mean it)
**Context:** an f-string used a backslash in an expression — a 3.12-only syntax —
so a module wouldn't import on 3.11 despite the documented "3.11+".
**Decision:** fix the code and add a 3.11 CI leg.
**Rationale:** honor the stated minimum; CI now guards it.
**Consequences:** broader compatibility; one small refactor in `html_report.py`.

### D-011 · GitHub-native contact channels; no invented emails
**Decision:** route security to GitHub Private Vulnerability Reporting, questions
to Discussions, bugs/features to Issues.
**Rationale:** don't fabricate contact info; use durable, maintainer-agnostic
channels.
**Consequences:** the maintainer can add a direct email later without breaking docs.

### D-010 · Mermaid for diagrams; catalog images rather than duplicate
**Decision:** author architecture diagrams as Mermaid in Markdown; have
`docs/images/` point to canonical assets instead of copying them.
**Rationale:** text diagrams render on GitHub and can't drift against a stale
binary export; duplication is what caused earlier doc drift.
**Consequences:** diagrams stay in sync for free.

### D-009 · Two READMEs reconciled — nested defers to root
**Context:** the app lives in `threat-modeler/`, and both it and the root had a
full README; they had drifted.
**Decision:** the root README is canonical; the nested one is a developer
reference that defers to it for the overview.
**Rationale:** a single source of truth prevents drift.
**Consequences:** overview edits happen in one place.

### D-008 · Keep the nested repo layout for now
**Context:** `app in threat-modeler/`, meta at root — the source of duplication.
**Decision:** document it clearly now; defer flattening to a later, tested
refactor.
**Rationale:** moving the app to the root touches CI paths, Dockerfiles, and the
Dependabot config; too risky to rush during a polish sprint.
**Consequences:** a known wart, tracked on the roadmap.

### D-007 · Unify internal version to 2.1; first public tag v0.1.0
**Context:** the app reported `2.0`/`2.1` in different places; a README said
`v2.4`.
**Decision:** unify internal reporting to `2.1`; ship the first *public* release
as `v0.1.0` (Community Preview).
**Rationale:** internal consistency now; a clean public SemVer starting point.
**Consequences:** the changelog notes the internal/public split openly.

### D-006 · Bump reportlab to 4.4.10 (install-blocking fix)
**Context:** `svglib 2.0.2` requires `reportlab >= 4.4.3`, but reportlab was
pinned to `4.2.5` — a clean `pip install` failed with `ResolutionImpossible`.
**Decision:** pin `reportlab==4.4.10`.
**Rationale:** the pinned set must actually install for new contributors/CI.
**Consequences:** clean resolution; PDF generation still passes.

### D-005 · CORS never combines wildcard with credentials
**Context:** default was `allow_origins=*` **and** `allow_credentials=True`,
which reflects any origin with credentials.
**Decision:** enable credentials only for explicitly configured origins; the `*`
default is credential-free.
**Rationale:** safe-by-default; header-based auth doesn't need credentialed CORS.
**Consequences:** the default is safe; production sets `CORS_ORIGINS`.

### D-004 · Secure by default, enforced by a test
**Decision:** every data endpoint requires a session; a test calls every route
anonymously and asserts none leak.
**Rationale:** "auth on everything" is only real if it's verified; it caught an
open `/api/methodologies`.
**Consequences:** new routes must enforce auth or CI fails.

### D-003 · SQLite, single-instance by default
**Decision:** ship with SQLite and design for single-instance use.
**Rationale:** zero-setup self-hosting; the common case for a preview.
**Consequences:** horizontal scale and a networked DB are future work (roadmap).

### D-002 · Multi-provider LLM + offline rules-only
**Decision:** support Anthropic and any OpenAI-compatible endpoint (incl. local),
auto-detected from the key; run fully on rules with no key.
**Rationale:** avoid vendor lock-in; let operators keep data local.
**Consequences:** a thin provider layer (`llm.py`); model quality is the
operator's choice.

### D-001 · Rules-first, AI-optional
**Decision:** a deterministic rule engine is the authoritative source of threats;
AI is additive enrichment that fails safe.
**Rationale:** reproducibility, explainability, and trust; the tool must work and
be correct without any model.
**Consequences:** AI can be wrong without breaking the product; output is always
reviewable.

---

_Add a new `D-0NN` entry when you make a decision a future contributor would
otherwise have to reverse-engineer._
