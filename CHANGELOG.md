# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

> **Note on versioning.** The application currently reports an internal version
> of `2.1` (a legacy number from earlier development). The first *public* release
> is being prepared as **v0.1.0 — Community Preview**; public tags start from
> `0.1.0`. The internal number will be reconciled with the public scheme in a
> future release.

## [0.1.1] — 2026-07-05

### Fixed
- **CSV export** returned HTTP 500 when the system name contained a non-latin-1
  character (em dash, en dash, accented, CJK, or emoji): the raw name was placed
  directly in the `Content-Disposition` filename, which is a latin-1 HTTP header.
  The filename is now emitted per RFC 6266 / RFC 5987 with an ASCII-safe
  `filename` and a UTF-8 `filename*`, and the original Unicode name is preserved.
  Added regression tests covering em dash, en dash, accented, CJK, and emoji
  names across both CSV export paths. (Other export formats were unaffected.)

## [Unreleased] — targeting v0.1.0 (Community Preview)

### Added
- Multi-LLM provider support: **Anthropic (Claude)** and any **OpenAI-compatible**
  endpoint (OpenAI, Azure OpenAI, Ollama, vLLM, …), selected via `LLM_PROVIDER`
  and auto-detected from the configured key. Fully offline **rules-only** mode
  when no key is set.
- Architecture-diagram upload (PNG/JPEG/WebP) → system model, via a vision model
  when configured, with an editable fallback otherwise.
- Automatic trust-boundary inference when none are defined, flowing into
  cross-boundary detection, the data-flow diagram, and reports.
- CSV risk register and executive-summary report formats.
- Interactive DFD editor (drag, inline edit, add/remove, layer toggles, re-infer).
- A generated sample report (`docs/sample-report.html`) and refreshed screenshots.
- Governance and contributor documentation (this changelog, CONTRIBUTING,
  SECURITY, SUPPORT, CODE_OF_CONDUCT, ROADMAP, ARCHITECTURE, FAQ,
  KNOWN_LIMITATIONS) and a `docs/audit/` engineering record.

### Changed
- Unified the reported version to `2.1` across the app, `/healthz`, and the UI.
- Reconciled the root and `threat-modeler/` READMEs (the nested one now defers to
  the root for the overview to prevent drift).
- Dependency updates: FastAPI, Pydantic, PyJWT, email-validator, svglib,
  reportlab.
- Repository hygiene: removed committed build artifacts and broken root Docker
  files; relocated sample artifacts under `examples/`.

### Fixed
- Application failed to boot due to malformed module headers and a missing
  migration helper.
- **Stored XSS** in the HTML report (user-supplied names embedded in an inline
  JSON block are now escaped).
- Several `500`s: custom-rule creation, three access-control checks missing their
  action argument, and the public share page's report rendering.
- CSV export was shadowed by another route and returned `400`.
- Data-flow-diagram edge labels rendered upside-down on right-to-left flows.
- **Install-blocking dependency conflict**: `svglib 2.0` requires
  `reportlab >= 4.4.3`, but `reportlab` was pinned to `4.2.5`, so a clean
  `pip install` failed.

### Security
- CORS no longer combines a wildcard origin with credentials; credentials are
  enabled only for explicitly configured origins.
- Verified secure-by-default: an automated sweep calls every route anonymously
  and confirms none serve protected data.
- Container image now runs as a non-root user.
- Removed two unwired, undocumented integration stubs (`notifications.py`,
  `ticket_export.py`) from the release to reduce attack surface; they will
  return, wired and tested, when the roadmap integrations land.

[Unreleased]: https://github.com/rootabhi1/ThreatGuard/commits/main
