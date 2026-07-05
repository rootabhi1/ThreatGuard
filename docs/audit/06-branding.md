# Phase 8 — Repository Branding

_Sprint 1: Public Launch Readiness (v0.1 Community Preview)_
_Date: 2026-07-05_

Presentation and identity. Per the sprint brief, this phase **applies the small
concrete items** (settings, badges) and **recommends** the visual identity —
without generating finished marketing assets yet.

## Applied

**Repository metadata** (set via the GitHub API during the maintainer actions):

- **Description:** _"AI-assisted threat modeling — STRIDE/DREAD/LINDDUN/PASTA/OWASP
  with CVSS, CWE & MITRE ATT&CK. Self-hosted, rules-first, works offline or with
  any LLM."_
- **Homepage:** the GitHub Pages site.
- **Topics (16):** `threat-modeling`, `security`, `appsec`, `cybersecurity`,
  `stride`, `owasp`, `cvss`, `mitre-attack`, `devsecops`, `security-tools`,
  `threat-analysis`, `self-hosted`, `fastapi`, `python`, `llm`, `ai-security`.

**README badges** — added live **CI** and **CodeQL** status badges alongside the
existing Live-Site / Python / FastAPI / License badges. Build health is now
visible at a glance.

## Recommendations (to produce later)

> "Do not generate marketing material yet" — these are specs/concepts for
> whoever creates the assets.

### Tagline

A short, professional one-liner for the social preview and site header. Options,
in order of preference:

1. **"Threat modeling that actually happens."**
2. "Structured threat models in minutes — rules-first, AI-optional."
3. "Automated threat modeling for engineering teams."

### Logo concept

- A **shield** (the current 🛡 motif) whose interior is a small **node-and-edge
  data-flow graph** (2–3 nodes, one dashed edge crossing a boundary) — signalling
  "threat modeling / DFD" rather than a generic security padlock.
- Flat, single-weight line style; works in monochrome and at 32 px favicon size.
- Palette from the app UI: deep slate background `#0f172a`, accent violet
  `#7c3aed`/`#a855f7`, with the existing boundary colors (rose/sky/amber/teal) as
  optional zone accents.

### Banner concept (repo social/README header, ~1280×320)

- Dark slate background; left: logo + wordmark **"ThreatGuard"** + tagline;
  right: a faint, stylized data-flow diagram with dashed trust-boundary zones
  (reuse the report's DFD aesthetic).
- Keep text minimal and high-contrast; avoid stock imagery.

### Social preview image (GitHub "Open Graph", **1280×640**)

- Same visual language as the banner, centered.
- Include: logo + "ThreatGuard", the tagline, and 3–4 keyword chips
  (STRIDE · OWASP · CVSS · self-hosted).
- Set under **Settings → General → Social preview**. This is what renders when
  the repo is shared on LinkedIn/X — high leverage for a launch.

### Badge inventory

Present: CI, CodeQL, Live Site, Python, FastAPI, License. Optional additions once
the repo is public and active: a **release** badge (after tagging `v0.1.0`), a
**"PRs welcome"** badge, and a **Discussions** badge.

## Production guidance

- Prefer **SVG** for logo/banner (crisp, tiny, diff-able); export PNG only for
  the social preview (GitHub requires a raster there).
- Keep everything **lean** — optimize PNGs; a logo SVG should be a few KB.
- Store finished assets in `docs/images/` (already catalogued with placeholders).
- No third-party trademarks or stock art.

## Quality bar

- ✅ Report in `docs/audit/` (this file)
- ✅ Tests unaffected (docs/metadata only — no code changed)
- ✅ Small logical commits (badges · report)
- ✅ No regressions
- ✅ Docs updated

## Note

This completes the *applyable* branding. The visual assets (logo/banner/social
preview) are intentionally left to a designer or a follow-up, per the brief.
