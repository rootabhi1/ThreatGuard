# Vision

_The north star for ThreatGuard. Short by design; principles over promises._

## The problem

Threat modeling is one of the highest-leverage security practices and one of the
most often skipped. Done by hand it is slow, inconsistent between reviewers, and
easy to defer until "later" — so systems ship without anyone systematically
asking *what could go wrong here?*

## What ThreatGuard is

A tool that turns a description of a system — typed, drawn, or uploaded as a
diagram — into a structured, methodology-backed threat model in minutes, with
consistent scoring, clear mitigations, and a data-flow diagram. It gives
engineers a strong first draft to review instead of a blank page, so threat
modeling actually happens.

## Who it's for

Security engineers, and the software engineers who work with them. Self-hosted,
so teams keep control of their data.

## Principles

1. **AI assists — it does not replace security engineers.** A deterministic rule
   engine is the backbone; AI is optional enrichment.
2. **Human validation is required.** Every output is a draft for review, never a
   sign-off.
3. **Secure by default**, and provably so (a test enforces it).
4. **Framework agnostic** — works offline on rules, or with Claude or any
   OpenAI-compatible model, including local ones.
5. **Explainable** — every finding maps to a methodology, CWE, CVSS, ATT&CK, and
   concrete mitigations. No black box.

## What success looks like

- A team can produce a credible first-pass threat model for a service in minutes.
- The output is trustworthy enough to review and act on, and honest about its
  limits.
- Contributors can understand and extend the project quickly.
- It stays small, focused, and secure rather than sprawling.

## What it will never be

- A replacement for human security judgment.
- A black-box "AI security oracle."
- A full GRC/compliance platform.

See [ROADMAP.md](../../ROADMAP.md) for planned direction and
[FUTURE_IDEAS.md](FUTURE_IDEAS.md) for unvetted ideas.
