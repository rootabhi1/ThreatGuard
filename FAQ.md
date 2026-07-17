# Frequently Asked Questions

## Why use AI at all?

ThreatGuard's core is a **deterministic rule engine** — the STRIDE, PASTA and
LINDDUN methodologies applied to your components and data flows, with DREAD risk
scoring on every threat and OWASP Top 10 reference mapping on findings. That works with no AI
and gives reproducible results. AI is layered on top to help with the fuzzy
parts: turning a plain-English description (or an architecture image) into a
structured model, suggesting context-specific threats, and drafting fixes. AI
**assists**; it does not replace the rule engine or a human reviewer. You can
turn it off entirely.

## Which LLMs are supported?

Two provider families:

- **Anthropic** — set `ANTHROPIC_API_KEY`.
- **Any OpenAI-compatible endpoint** — set `OPENAI_API_KEY` (and `OPENAI_BASE_URL`
  for non-OpenAI hosts). This covers OpenAI, Azure OpenAI, and self-hosted
  runtimes like Ollama and vLLM.

The provider is auto-detected from whichever key is set, or forced with
`LLM_PROVIDER=anthropic|openai`. See [`.env.example`](.env.example). You can also
configure the provider, model, and key from the app itself — **Admin → Settings →
AI provider** — where the key is stored encrypted at rest instead of in an env var.

## How do I get an admin account?

Set `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` to seed one on first run, or
just leave them unset and register — on a fresh instance with no admin yet, the
**first person to register becomes the admin**. After that, admins create further
accounts and grant feature access from **Admin → Users & Access**.

## Can I use local models?

Yes. Point the OpenAI-compatible settings at a local runtime, e.g. Ollama:

```bash
export OPENAI_API_KEY=ollama            # any non-empty value
export OPENAI_BASE_URL=http://localhost:11434/v1
export OPENAI_MODEL=llama3.1
```

With a local model, no data leaves your machine and you still get AI enrichment.
Quality will depend on the model you run.

## How accurate are the results?

The **rule-based** findings are consistent and explainable — each threat maps to
a methodology, a CWE, CVSS scores, and mitigations. Coverage still depends on how
completely you describe the system.

The **AI-generated** parts are assistive and can be wrong, generic, or
incomplete; their quality depends on the model you choose. Treat all output as a
**draft for human review**, not a security sign-off. See
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

## Is my data sent externally?

- **No LLM key configured:** nothing leaves your machine. The rule engine runs
  entirely locally.
- **A cloud provider configured:** the system description (and, for diagram
  upload, the image) is sent to **that provider** for enrichment, subject to
  their data policies.
- **A local model configured:** data stays on your infrastructure.

The application does not phone home or send telemetry.

## Can I self-host?

Yes — self-hosting is the intended deployment. Run it directly with Python or via
the Docker setup in `threat-modeler/`. See the [README](README.md) and
[CONTRIBUTING.md](CONTRIBUTING.md). Set a strong `JWT_SECRET`, restrict
`CORS_ORIGINS`, and serve over HTTPS for production (see [SECURITY.md](SECURITY.md)).

## Do I need an internet connection?

Only if you use a cloud LLM provider. The rule engine — and local-model
enrichment — work offline.

## Is this a replacement for a security review or a pentest?

No. It accelerates and structures threat modeling and produces a reviewable
first draft. A human security engineer should validate the output, and it is not
an audit, pentest, or compliance certification.

## What does it store, and where?

Threat models, users, and analysis results are stored in a local **SQLite**
database (`data/threat_modeler.db` by default; override with
`THREAT_MODELER_DB`). There is no external database dependency.

## How do I report a bug or ask a question?

See [SUPPORT.md](SUPPORT.md). Security issues follow the private process in
[SECURITY.md](SECURITY.md).
