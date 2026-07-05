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

## Next — v0.2.x (Hardening & DX)

- Flatten the repository layout (move the app to the root) to remove the
  root/`threat-modeler/` split — a larger, carefully-tested refactor.
- One-command local bootstrap (script or `make`) and a devcontainer.
- Broaden automated coverage for the DFD editor and report renderers.
- Documented recipes for local models (Ollama / vLLM) and Azure OpenAI.
- Configurable data retention and clearer audit-log export.

## Later — exploratory

- Pluggable/custom methodology packs beyond the built-in five.
- Alternative storage backend (e.g. PostgreSQL) for multi-instance deployments.
- Deeper CI/CD integration (threat models as a pipeline check).
- Richer compliance mappings and export formats.
- Optional SSO / OIDC.

## Explicitly out of scope (for now)

- Becoming a full GRC platform.
- Replacing human security review (see [design principles](README.md)).
- Guaranteeing LLM output quality — model choice is the operator's.

Have an idea? Open a [Discussion](SUPPORT.md) or a feature-request issue.
