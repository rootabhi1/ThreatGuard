# Visual assets

An index of ThreatGuard's diagrams and imagery. To avoid the duplication that
causes docs to drift, this folder **points to the canonical location** of each
asset rather than copying it.

## Architecture diagrams

Rendered inline (Mermaid) in **[../../ARCHITECTURE.md](../../ARCHITECTURE.md)**:

- High-level component diagram
- Data-flow (analysis) sequence
- Application trust-boundary diagram
- LLM interaction flow

Mermaid is used so the diagrams live in version control as text, render on
GitHub, and never go stale against a binary export.

## Screenshots

Canonical screenshots live in [`../screenshots/`](../screenshots/) and are
embedded in the root README:

- `01_dashboard.png` — dashboard
- `02_new_threat_model.png` — threat-modeling canvas
- `03_threat_analysis.png` — analysis / data-flow diagram

## Sample report

A full generated report: [`../sample-report.html`](../sample-report.html).

## Placeholders (to be added)

These are intentionally listed but not yet produced — contributions welcome:

- `workflow.*` — an end-to-end workflow diagram (describe → analyze → review →
  report). _Placeholder._
- `demo.gif` — a short screen capture of the create-and-analyze flow.
  _Placeholder._
- `banner.*` / `social-preview.*` — repository branding imagery (see the Phase 8
  branding notes). _Placeholder._

If you add a binary asset here, keep it optimized (compress PNGs, keep GIFs
short) so the repository stays lean.
