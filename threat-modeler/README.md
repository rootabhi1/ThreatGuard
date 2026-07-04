# ThreatGuard — Application (developer reference) · v2.1

The FastAPI application that powers ThreatGuard.

> **For the project overview, feature list, screenshots, and quick start, see the [root README](../README.md).**
> This document is the app-level developer reference: setup from this folder, the interactive DFD editor, the roles/permissions model, code layout, the test suites, and troubleshooting. It intentionally does **not** repeat the feature overview, so the two READMEs can't drift.

**Providers:** runs fully offline on the rule engine. Optional AI enrichment via **Claude** (`ANTHROPIC_API_KEY`) or any **OpenAI-compatible** endpoint (`OPENAI_API_KEY`, plus `OPENAI_BASE_URL` for Azure/Ollama/vLLM/…). All variables are documented in [`../.env.example`](../.env.example).

---

## Setup (from this folder)

```bash
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
export INITIAL_ADMIN_EMAIL=admin@example.com
export INITIAL_ADMIN_PASSWORD='ChangeMe123!'
# optional AI:  export ANTHROPIC_API_KEY=sk-ant-...   (or OPENAI_API_KEY / OPENAI_BASE_URL)

python app.py            # http://localhost:8000
```

Sign in with the `INITIAL_ADMIN_*` credentials. If `bcrypt` fails to build on Windows:
`pip install bcrypt --only-binary :all:` then re-run the install. Docker instructions are in the [root README](../README.md#docker).

---

## Interactive DFD editor

The Data Flow Diagram tab in the threat-detail modal is a full editor:

- **Smart trust-boundary inference** — components partition into Internet / DMZ / Application tier / Data tier / Third-party zones. Heuristic mode is the default (deterministic, no API key). LLM mode (Claude or an OpenAI-compatible model) can reason about zones when a key is configured. Re-infer any time from the toolbar; if none are defined, boundaries are inferred automatically at analysis time.
- **Drag** components to reposition (snap-to-grid); drag across a zone and membership reassigns.
- **Click** any component / flow / boundary to edit inline — rename, change type, toggle encryption, edit description, add/remove from boundaries.
- **Add** components, draw flows (→ then click two components), create boundaries.
- **Toggle** layers: boundaries, encryption icons, labels.
- **Save** layout + edits back to the model in one click.

Management sees the same editor in **read-only** mode (pan/zoom/inspect, no edits).

---

## Methodologies & scoring

STRIDE / DREAD / LINDDUN / PASTA / OWASP Top 10, applied automatically. Each threat carries CVSS 3.1 + 4.0, a CWE, MITRE ATT&CK technique/tactic, and SOC 2 / ISO 27001 / PCI-DSS control mapping. A plain-English description — or an **uploaded architecture diagram** (PNG/JPEG/WebP) — auto-extracts components, flows, and trust boundaries.

Reports: Markdown, interactive HTML (with embedded DFD), PDF, a CSV risk register, and an executive summary.

---

## Roles and permissions

| Permission | User | Management | Admin |
|---|:---:|:---:|:---:|
| Create threat models | ✓ (in granted features) | — | ✓ |
| Edit own DFD | ✓ | — (read-only) | ✓ |
| Edit any DFD | — | — | ✓ |
| Read all threat models | — | ✓ | ✓ |
| Update threat status | own only | — | all |
| Generate reports | own | all | all |
| Create users / change roles | — | — | ✓ |
| Read audit log | — | — | ✓ |

---

## Project structure

```
threat-modeler/
├── app.py                       # FastAPI app — all routes, middleware, auth wiring
├── auth/                        # RBAC: permission registry, JWT, dependencies
├── db/                          # SQLite schema + domain CRUD
├── threat_engine/
│   ├── methodologies.py         # STRIDE / DREAD / LINDDUN / PASTA / OWASP rules
│   ├── analyzer.py              # Rule engine + extraction; infers trust boundaries
│   ├── trust_boundaries.py      # Heuristic + LLM boundary inference
│   ├── dfd.py                   # Server-side static SVG (used in reports)
│   ├── scoring.py               # CVSS 3.1 + 4.0
│   ├── detail.py                # CWE mapping, attack scenarios, mitigations
│   ├── llm.py                   # Provider layer — Anthropic + OpenAI-compatible
│   ├── diagram_extractor.py     # Architecture-diagram → system model (vision)
│   ├── html_report.py           # Standalone interactive HTML report
│   ├── executive_report.py      # Executive summary
│   └── report.py                # Markdown + PDF generation
├── templates/                   # Jinja2 templates
├── static/
│   ├── css/app.css              # Design system + DFD editor styles
│   └── js/
│       ├── auth.js, ui.js       # Token management + UI helpers
│       ├── admin.js, dashboard.js, management.js
│       ├── dfd_editor.js        # Interactive DFD editor
│       └── app.js               # Canvas
└── tests/                       # 8 suites (see below)
```

---

## Tests

All eight suites run in-process against a real app instance and SQLite — no server or network needed:

```bash
export JWT_SECRET=test INITIAL_ADMIN_EMAIL=admin@corp.io INITIAL_ADMIN_PASSWORD='AdminPass123!' RATE_LIMIT_ENABLED=0
for t in tests/test_*.py; do python3 "$t"; done
```

- `test_rbac.py` — role/permission enforcement
- `test_exhaustive.py` — use cases + edge cases across the engine
- `test_component_coverage.py` — threat-engine accuracy
- `test_page_integrity.py` — UI/template integrity
- `test_trust_boundaries.py` — boundary inference + DFD
- `test_api.py` — API integration, auth flows, account lockout
- `test_new_endpoints.py` — sharing, release diff, status workflow, custom rules
- `test_full_product.py` — whole-product sweep (119 checks across 17 areas), including a **secure-by-default** pass that calls every route anonymously to confirm none leak

See [`../TESTING.md`](../TESTING.md) for the detailed matrix.

---

## Manual test plan: trust boundaries + DFD editor (~10 min)

### Test 1: Heuristic boundary inference (auto)
1. Login as user → **+ New Threat Model**
2. Use this description:
   ```
   A user logs into the web app via OAuth (Google).
   The web app issues a JWT and stores session data in Redis.
   User profile data is read from a Postgres database.
   Payments are processed via Stripe API.
   Push notifications go through APNS.
   ```
3. Leave **Enable AI enhancement** OFF → Create & analyze
4. Open detail → **Data Flow Diagram** tab
5. **Expected**: 5 zones — Internet (User), DMZ (Web App), Application tier (auth), Data tier (Postgres + Redis), Third-party (Stripe + APNS)

### Test 2: LLM boundary inference (requires a provider key)
1. Set `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) → restart server
2. New TM → toggle **Enable AI enhancement** ON → use a complex multi-tier description
3. **Expected**: more nuanced zone names (e.g. "PCI scope", "Customer data tier") with model-written descriptions

### Test 3: Drag & reposition
Drag a component; it snaps to a 20px grid. Drop it inside a different boundary → membership reassigns, box redraws, Save appears.

### Test 4: Inline edit
Click a component → side panel; rename (updates live), change type (icon updates). Click a flow → untick **Encrypted in transit** → line turns red-dashed with ⚠.

### Test 5: Add / remove
**＋ Component** adds a service at center (rename in panel). **→ Flow** then click two components to connect. Click a flow → **Delete flow**. **🛡 Boundary** adds an empty zone; tick components to add them.

### Test 6: Toggle layers
Untick **Boundaries** / **Encryption icons** / **Labels** in the toolbar → each layer hides; re-tick restores.

### Test 7: Re-infer + save
**↻ Re-infer** (heuristic) or **🤖 Infer with AI** (if a key is set) resets zones. Make edits → **Save layout & changes** → re-open → changes persisted.

### Test 8: Management read-only
Login as management → open any TM → DFD tab: only layer toggles + zoom (no add/delete/save); clicking a component opens a read-only panel.

---

## Troubleshooting

**Login shows "Auth.setToken is not a function"** — cached JS; hard refresh (`Ctrl+Shift+R`).

**DFD tab is blank** — open DevTools → Console; usually `static/js/dfd_editor.js` failed to load.

**Trust boundaries don't appear** — the model predates inference; open the TM → DFD tab → **↻ Re-infer**.

**"Infer with AI" failed** — no provider key set, the provider SDK isn't installed, or a network/auth issue. The editor falls back to heuristic mode automatically.

**Database location** — SQLite lives at `data/threat_modeler.db` by default; override with `THREAT_MODELER_DB`.
