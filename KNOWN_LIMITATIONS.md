# Known Limitations

ThreatGuard is useful, but it is not magic. This document is deliberately blunt
about what the tool does and does not do, so you can use it responsibly. If you
hit something not listed here, please open a [Discussion](SUPPORT.md).

## Experimental AI output

- LLM enrichment (threat suggestions, fix generation, diagram extraction, richer
  narratives) is **assistive and experimental**. It can be incomplete, generic,
  or wrong.
- Output **quality depends entirely on the model you configure**. The project
  tests the *plumbing* (provider selection, request/response, graceful failure,
  offline fallback) — not the correctness of any given model's answers.
- The deterministic **rule engine** is the primary, reproducible source of
  threats; AI is layered on top, never a replacement for it.

## Human review is required

- Treat every output — rule-based or AI-generated — as a **draft for a human to
  review**, not a finished assessment.
- A generated threat model does not constitute a security sign-off, an audit, or
  compliance certification. Map findings to your own context before acting.

## Supported architectures

- Works best on **request/response, service-oriented systems** described as
  components (users, web apps, APIs, services, databases, external providers) and
  the data flows between them.
- Trust-boundary inference is a **heuristic** (grouping by component type/name
  into Internet / DMZ / Application tier / Data tier / Third-party). It is a
  sensible starting point, **not** a substitute for an architect defining zones.

## Unsupported / weak scenarios

- Deeply event-driven, streaming, or highly asynchronous topologies are only
  partially modeled.
- Very large systems (many dozens of components) may produce noisy or repetitive
  threat lists.
- Diagram extraction from images is best-effort and depends on the vision model;
  hand-drawn or low-contrast diagrams may extract poorly. Always review and edit
  the extracted model.
- Non-English system descriptions are not specifically tuned for.

## Operational limitations

- **Single instance / SQLite.** The default store is SQLite and the app is
  designed for single-instance use. Horizontal scaling, shared sessions, and a
  networked database are not yet supported.
- **No multi-tenant isolation** beyond role-based access control and per-resource
  ownership. It is not designed to isolate mutually-distrusting tenants.
- Rate limiting and lockout state are in-process (not shared across instances).

## Security posture gaps (tracked)

- No Content-Security-Policy yet (planned; needs nonces so it doesn't break the
  UI's inline scripts).
- Code/dependency scanning (CodeQL, secret scanning, `pip-audit`) is not yet
  enforced in CI.

See [SECURITY.md](SECURITY.md) and [`docs/audit/`](docs/audit/) for the full
posture, and [ROADMAP.md](ROADMAP.md) for what's planned.

## Data & privacy

- With **no LLM key**, everything stays local — nothing leaves your machine.
- With a provider configured, the system description (and, for diagram upload,
  the image) is sent to **that provider** for enrichment. See [FAQ.md](FAQ.md).
