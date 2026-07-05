# Future Ideas

A scratchpad for **unvetted** ideas — things worth remembering but not yet
committed to. This is deliberately different from the [ROADMAP](../../ROADMAP.md),
which is planned direction. Nothing here is a promise; anything here may be a bad
idea. Promote an item to the roadmap only after it earns a decision in
[DECISIONS.md](DECISIONS.md).

## Workflow & integration

- **Threat-model-as-code**: a versioned `system.yaml` in a repo, analyzed by CI,
  failing the build on new high-severity threats (dogfood the tool on itself).
- **SARIF export** so findings surface in the GitHub "Security" tab / code
  scanning UI.
- **Issue-tracker sync**: open/track mitigations as GitHub or Jira issues.
- **Diff-driven modeling**: "what threats changed since the last model?" as a
  first-class, reviewable artifact.

## Modeling depth

- **Custom methodology packs** beyond the built-in five (org-specific rules).
- **Attack-path / chaining** analysis across components, not just per-component
  threats.
- Better handling of **event-driven / streaming** topologies (a current weak
  spot).
- **Data-classification tags** on flows (PII/PCI/secret) driving targeted rules.

## AI / LLM

- **Local-model presets** (Ollama/vLLM recipes) shipped as documented profiles.
- **Grounded prompting** with retrieval over the org's own standards/policies.
- **Confidence signals** on AI-generated threats so reviewers can triage faster.
- Optional **redaction** pass before anything crosses the LLM boundary.

## Operations & scale

- **PostgreSQL backend** option for multi-instance deployments.
- **SSO / OIDC** for team auth.
- Shared/distributed **rate-limit and lockout** state.
- Configurable **data retention** and export.

## Developer experience

- One-command bootstrap (`make dev`) and a **devcontainer**.
- A small **plugin API** for custom rules and report formats.
- Property-based tests for the scoring/mapping logic.

## Hardening (candidates, some already tracked)

- **Content-Security-Policy** with nonces.
- **CSV formula-injection** neutralization in the risk-register export.
- Signed release artifacts / SBOM.

---

_Have an idea? Add a bullet here, or open a [Discussion](../../SUPPORT.md). Keep
entries short — this is a memory aid, not a spec._
