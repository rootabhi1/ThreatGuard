# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

> **Note on versioning.** The application currently reports an internal version
> of `2.1` (a legacy number from earlier development). The first *public* release
> is being prepared as **v0.1.0 — Community Preview**; public tags start from
> `0.1.0`. The internal number will be reconciled with the public scheme in a
> future release.

## [Unreleased]

### Added
- **Element security attributes (Microsoft Threat Modeling Tool style).** Each
  component and data flow can declare security properties (answered yes / no /
  unknown, contextual to the type) — data sensitivity, encrypted at rest, stores
  credentials, backed up, enforces authorization, validates input, encodes
  output, MFA, rate limiting, PII/PHI/PCI handling, code-integrity verification,
  removable media, safe error handling; flows add integrity, replay protection,
  and TLS-certificate validation. A risky answer generates a specific, DREAD-
  scored threat on re-analysis.
- **Expanded component vocabulary (13 → ~40 types).** Cloud-native and modern
  services: serverless, container, kubernetes, service_mesh, api_gateway,
  load_balancer, cdn, waf, dns, bastion, object_storage, data_warehouse,
  vector_db, search_service, data_pipeline, scheduler, monitoring,
  notification_service, secrets_manager, iam, llm, identity_provider,
  email_service, sms_gateway, iot_device. Available in the DFD editor,
  structured input, and diagram extraction, and auto-detected from free text.
- **First-run admin.** On a brand-new deployment with no admin, the first person
  to register becomes the admin, so an instance is never a dead end even without
  `INITIAL_ADMIN_*` set.
- **Edit / rename** for threat models (name + description) and for releases and
  features in the admin console; **delete** affordances on model cards and on
  release/feature rows.
- **Meaningful compare** — comparing two unrelated systems now warns that they
  don't share components or threats instead of showing a misleading diff.
- **LLM & Jira configured in the admin UI** (Settings tab), with secrets stored
  encrypted at rest, in addition to environment variables. Optional Jira
  integration files a ticket from a threat.
- **Richer management portfolio view.** The read-only management/admin overview
  gained a portfolio remediation progress bar; a needs-attention panel that
  flags blind spots (models not analyzed, stale models, features with no threat
  model); an in-app OWASP Top 10 drill-down that lists the matching threats
  across the portfolio (instead of only linking out to owasp.org); a
  searchable, sortable "all threat models" table with per-model risk badges and
  analyzed/stale flags; and a one-click CSV export of every threat. Admins can
  file a Jira ticket directly from this view (the management role stays
  read-only). Backed by a new `GET /api/management/threats` endpoint.

### Changed
- Free-text component names now use conventional acronym/brand casing (LLM, API,
  S3, IdP, MySQL, OpenAI, SendGrid…) instead of blunt Title Case.
- Creating a model from a text description auto-fills its description from that
  text when the Notes field is left blank.
- DFD drag now uses pointer events, so it works on touch/tablet as well as mouse.

### Fixed
- **Data-flow diagram in reports** was broken — overlapping trust-boundary boxes,
  clipped labels, a fixed viewBox that clipped larger layouts, and it ignored the
  arrangement saved in the editor. The report layout is now boundary-aware, sized
  to fit its content, and reuses the editor-saved layout across HTML, Markdown,
  and PDF.
- Hardened several endpoints to return clean `4xx` instead of `500` on bad input:
  the share-link endpoint (empty/invalid body) and admin user endpoints
  (role / deactivate / feature-access with an unknown user id).

## [0.1.2] — 2026-07-06

### Changed
- Unified the product name to **ThreatGuard** everywhere it is user-visible: the
  repository was renamed to `ThreatGuard`, and the in-app display name (API title,
  page titles, report footers, CLI help) changed from "Threat Modeler" to
  "ThreatGuard". Internal plumbing (the `threat-modeler/` directory, the
  `THREAT_MODELER_DB` environment variable, deployment resource names) is
  unchanged. The previous repository URL redirects automatically.

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
- Multi-LLM provider support: **Anthropic** and any **OpenAI-compatible**
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
