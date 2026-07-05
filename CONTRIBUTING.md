# Contributing to ThreatGuard

Thanks for your interest in improving ThreatGuard. This guide is written for
someone seeing the project for the first time — it should get you from clone to
merged pull request without guesswork.

## Ground rules

- Be respectful — see the [Code of Conduct](CODE_OF_CONDUCT.md).
- Keep changes focused. One logical change per pull request.
- Don't break existing behavior. Tests must pass.
- Security issues go through private disclosure, **not** public issues — see
  [SECURITY.md](SECURITY.md).

## Project layout (the one thing to know first)

The application lives in **`threat-modeler/`**, not at the repository root. The
root holds project-level meta (README, license, governance docs, `docs/`,
`examples/`). Almost everything you edit is under `threat-modeler/`.

```
threat-modeler/
  app.py            FastAPI app — routes, middleware, auth wiring
  auth/             JWT, RBAC permission registry, dependencies
  db/               SQLite schema + domain queries
  threat_engine/    methodologies, scoring, DFD, trust boundaries,
                    diagram extraction, the LLM provider layer, reports
  templates/ static/ server-rendered UI
  tests/            7 in-process test suites
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for how these fit together.

## Local setup

Requires **Python 3.11+**.

```bash
git clone https://github.com/rootabhi1/Automated-Threat-Modelling
cd Automated-Threat-Modelling/threat-modeler

python3 -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
export INITIAL_ADMIN_EMAIL=admin@example.com
export INITIAL_ADMIN_PASSWORD='ChangeMe123!'
python app.py            # http://localhost:8000
```

No LLM key is required — the app runs fully on its rule engine. To exercise the
AI paths, set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` (+ `OPENAI_BASE_URL`). All
variables are documented in [`.env.example`](.env.example).

## Running the tests

The suites run in-process against a real app instance and SQLite — no server or
network needed. **Every PR must keep all seven green.**

```bash
cd threat-modeler
export JWT_SECRET=test INITIAL_ADMIN_EMAIL=admin@corp.io \
       INITIAL_ADMIN_PASSWORD='AdminPass123!' RATE_LIMIT_ENABLED=0
for t in tests/test_*.py; do python3 "$t" || echo "FAILED: $t"; done
```

`tests/test_full_product.py` is the whole-product sweep (119 checks / 17 areas),
including a secure-by-default pass that calls every route anonymously. If you add
or change an endpoint, add coverage there. See [TESTING.md](TESTING.md).

## Coding conventions

- **Style:** standard PEP 8. Keep functions small and readable; match the
  surrounding style rather than reformatting unrelated code.
- **SQL:** always parameterised. If you build a dynamic `SET`/column list, the
  column names must come from a **whitelist**, never from user input.
- **User input in reports/UI:** treat everything (including LLM output) as
  untrusted — never render it unescaped. Templates use Jinja2 autoescape; the
  HTML report escapes names inside its embedded JSON.
- **Auth:** every data endpoint requires a session. New routes must enforce the
  right permission/ownership — the secure-by-default test will fail otherwise.
- **Secrets:** never commit them. Read from environment variables; add new ones
  to `.env.example`.

## Commits and pull requests

- Use clear, conventional-style messages where possible: `fix:`, `feat:`,
  `docs:`, `chore:`, `test:`, `build:`.
- Keep commits small and logical — one concern each.
- Before opening a PR: tests pass, no secrets, docs updated if behavior changed.
- Fill in the pull-request template. Link any related issue.
- Maintainers review on a best-effort basis; expect iteration.

## Good first contributions

Look for issues labeled **good first issue** and **help wanted**. Documentation
fixes, additional test coverage, and small, well-scoped bug fixes are always
welcome. If you're unsure whether a change fits, open a
[Discussion](SUPPORT.md) first.

## What not to do in a PR

- Don't rename the repository or restructure directories without prior
  discussion.
- Don't add large new features without an issue/Discussion agreeing on scope —
  this project deliberately favors stability and clarity.
- Don't add dependencies casually; justify them in the PR.
