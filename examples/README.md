# Examples

Ready-to-use inputs and sample outputs for ThreatGuard.

```
examples/
├── systems/    system definitions you can analyze
└── reports/    example generated reports
```

## System definitions (`systems/`)

Each file is a **flat system definition** — the format the engine, API, and UI
use: a `name`, `description`, `components`, `data_flows`, and optional
`trust_boundaries` (boundaries are inferred automatically if you omit them).

| File | Size | What it shows |
|------|------|---------------|
| `simple-api.json` | 3 components | A minimal user → API → database service |
| `saas-app.json` | 5 components | A SaaS web app: user, web, API, Postgres, Redis |
| `retail-platform.json` | 9 components | A multi-tier retail platform with an external payment provider and an admin portal |

## Sample reports (`reports/`)

- `simple-api.md` — Markdown report generated from `simple-api.json`
- `simple-api.csv` — the CSV risk register for the same system
- `sample-report-2026-05-13.html` — an earlier full HTML report

A rich, interactive HTML report for the retail platform is at
[`../docs/sample-report.html`](../docs/sample-report.html).

## How to use a system definition

**In the web UI** — start the app (`make dev` or `./threat-modeler/run.sh`), open
`http://localhost:8000`, create a new threat model, and paste the JSON into the
component builder (or describe your system in plain English, or upload a diagram).

**Via the API** — wrap the file as the `system` field:

```bash
TOKEN=...   # from POST /api/auth/login
curl -s -X POST http://localhost:8000/api/analyze \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"system\": $(cat examples/systems/simple-api.json), \"methodologies\": [\"stride\",\"owasp\"], \"use_llm\": false}"
```

**Via the CLI** — with the app running (the defaults match `run.sh`):

```bash
cd threat-modeler
python cli/atm_cli.py analyze \
  --system-file ../examples/systems/simple-api.json \
  --frameworks stride,owasp --output-md report.md
# Override creds with ATM_USER / ATM_PASS, or pass a token via ATM_TOKEN.
```

The CLI exits non-zero when threats meet or exceed `--threshold`, so it can gate a
CI pipeline.
