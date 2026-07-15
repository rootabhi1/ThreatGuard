# Roadmap

This roadmap communicates direction, not commitments or dates. It is a community
project maintained on a best-effort basis; priorities shift with feedback and
contributions. See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for what the tool
does and doesn't do today.

## Now — v0.1.0 (Community Preview)

Goal: a polished, secure, well-documented preview that's safe to share and easy
to contribute to.

- [x] Multi-LLM support (Anthropic + OpenAI-compatible) with offline rules-only
- [x] Trust-boundary inference + data-flow diagram
- [x] Reports: HTML, PDF, Markdown, CSV, executive summary
- [x] Security pass: secure-by-default, XSS fix, safe CORS default
- [x] Governance + contributor documentation
- [ ] CI running at the repo root (lint + tests) — *in progress this sprint*
- [ ] CodeQL, secret scanning, and dependency audit in CI
- [ ] Content-Security-Policy (with nonces, without breaking the UI)
- [ ] First tagged release: `v0.1.0`

## Accuracy roadmap

"Accuracy" here means two distinct things, tracked separately, because conflating
them is what caused earlier mislabeling:

1. **Truthfulness** — the tool describes *what it is* honestly (framework labeling).
2. **Precision** — the threats it reports are actually *applicable* to your model.

### Achieved

- [x] **Framework fidelity.** STRIDE / PASTA / LINDDUN are the threat-modeling
  methodologies; **DREAD** is a risk-scoring lens (independent per-axis scores +
  risk tiers); **OWASP Top 10** is a reference mapping — neither is a methodology.
  One consistent vocabulary across engine, reports, UI, docs, and the site.
- [x] **Applicability tiers.** Every threat is tagged `evidenced` (proven by a
  fact in your model) or `baseline` (a generic type-based check). Reports default
  to *evidenced*, with a one-click toggle to reveal baseline — high-signal by
  default, nothing dropped.
- [x] **Measurement harness.** Reference systems with expert-labelled
  applicable/not (`benchmark/`), so correctness is tracked as a number and
  regression-gated in CI. Accuracy is the labelled-assertion pass rate — *not*
  the evidenced/total ratio, which is a composition metric that shifts with
  catalog size.
- [x] **Per-rule evidence predicates.** Each rule declares its precondition
  explicitly via an `evidence` signal; the old keyword heuristic is retired.
- [x] **Data classification.** Optional `sensitivity` tags (PII / PHI / PCI /
  secrets) on flows and components move **LINDDUN** privacy threats to evidenced,
  and drive *class-aware* compliance findings (PHI→HIPAA, PII→GDPR/CCPA,
  PCI→PCI-DSS).

### Next

- [ ] **Expand the labelled corpus.** More reference systems and per-threat
  labels (ideally a second reviewer) so precision/recall can be quoted with
  confidence rather than as a small-sample gate.
- [ ] **Sensitivity in the UI.** Let users tag data classification in the builder
  so the data-classification precision is reachable without hand-editing JSON.
- [ ] **Feedback loop.** Persistent "not applicable / accepted" that suppresses a
  threat on re-analysis, plus optional LLM triage of baseline items.

**Guardrail:** baseline threats are always de-emphasised, never removed — recall
is preserved (worst case is one extra click, never a missed finding). Tracked in
issue #32.

## Next — v0.2.x (Hardening & DX)

- Flatten the repository layout (move the app to the root) to remove the
  root/`threat-modeler/` split — a larger, carefully-tested refactor.
- One-command local bootstrap (script or `make`) and a devcontainer.
- Broaden automated coverage for the DFD editor and report renderers.
- Documented recipes for local models (Ollama / vLLM) and Azure OpenAI.
- Configurable data retention and clearer audit-log export.

## Later — exploratory

- Pluggable/custom methodology packs beyond the built-in methodologies.
- Alternative storage backend (e.g. PostgreSQL) for multi-instance deployments.
- Deeper CI/CD integration (threat models as a pipeline check).
- Richer compliance mappings and export formats.
- Optional SSO / OIDC.

## Explicitly out of scope (for now)

- Becoming a full GRC platform.
- Replacing human security review (see [design principles](README.md)).
- Guaranteeing LLM output quality — model choice is the operator's.

Have an idea? Open a [Discussion](SUPPORT.md) or a feature-request issue.
