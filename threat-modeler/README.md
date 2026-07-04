# ThreatGuard — Automated Threat Modeling Platform · v2.4

Web app for automated threat modeling with role-based access control and an
**interactive DFD editor with AI-powered trust boundary inference**.

## What's new in v2.4

### Smart trust boundary inference
- Components automatically partition into Internet / DMZ / Application tier / Data tier / Third-party zones
- **Heuristic mode** (default): deterministic rules based on component type + name patterns. No API key required.
- **LLM mode**: enable AI in the create-TM modal to use Claude for smarter trust-zone reasoning. Requires `ANTHROPIC_API_KEY`.
- Re-infer at any time from the DFD editor toolbar.

### Interactive DFD editor
The Data Flow Diagram tab in the threat detail modal is now a full editor:
- **Drag** components to reposition (snap-to-grid)
- **Click** any component / flow / boundary to edit inline (rename, change type, toggle encryption, edit description, add/remove from boundaries)
- **Add** components (＋ Component button), draw flows (→ Flow then click two components), create boundaries (🛡 Boundary)
- **Drag** components between trust boundaries — membership reassigns automatically
- **Toggle** visual layers: boundaries on/off, encryption icons on/off, labels on/off
- **Re-infer** trust boundaries from current components (heuristic or AI)
- **Save** layout + edits back to the threat model with one click

Management view shows the same editor in **read-only mode** — no edits possible, but full pan/zoom/inspect.

---

## Core features (carry-over from v2.3)

- **STRIDE / DREAD / LINDDUN / PASTA** methodologies applied automatically
- **CVSS 3.1 + 4.0**, **CWE**, **OWASP Top 10** mapping per threat
- **Three roles**: Admin (full control), User (creates threat models), Management (read-only oversight)
- **Plain-English system descriptions** auto-extract components, flows, **and trust boundaries**
- **Reports**: Markdown, HTML, PDF (with embedded DFD)
- **Optional LLM enhancement** via Anthropic Claude API (threat suggestions + boundary inference)

---

## Quick start (Windows / PowerShell)

```powershell
cd $HOME\Downloads
Expand-Archive threat-modeler.zip -DestinationPath . -Force
cd threat-modeler

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If `bcrypt` errors:
```powershell
pip install bcrypt --only-binary :all:
pip install -r requirements.txt
```

```powershell
$env:JWT_SECRET = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:INITIAL_ADMIN_EMAIL = "admin@example.com"
$env:INITIAL_ADMIN_PASSWORD = "ChangeMe123!"

# Optional: enable LLM-based trust boundary inference + threat suggestions
# $env:ANTHROPIC_API_KEY = "sk-ant-..."

python app.py
```

Open <http://localhost:8000/> and sign in as `admin@example.com` / `ChangeMe123!`.

---

## Quick start (Linux / macOS)

```bash
cd ~/Downloads && unzip threat-modeler.zip && cd threat-modeler
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
export INITIAL_ADMIN_EMAIL=admin@example.com
export INITIAL_ADMIN_PASSWORD=ChangeMe123!
python app.py
```

---

## Run the test suites

Five sandbox-runnable test layers (no FastAPI server needed):

```powershell
python tests\test_rbac.py              # 15 tests — RBAC unit tests
python tests\test_exhaustive.py        # 57 tests — every use case + edge case
python tests\test_component_coverage.py # 5 tests — threat-engine accuracy
python tests\test_page_integrity.py    # 19 tests — UI/template integrity
python tests\test_trust_boundaries.py  # 20 tests — NEW: trust boundary inference + DFD editor
```

**Expected: 116/116 passing.**

---

## Manual test plan: trust boundaries + DFD editor (10 min)

After completing initial admin/user/management setup, test the new features:

### Test 1: Heuristic boundary inference (auto)

1. Login as user → **+ New Threat Model**
2. Use this system description:
   ```
   A user logs into the web app via OAuth (Google).
   The web app issues a JWT and stores session data in Redis.
   User profile data is read from a Postgres database.
   Payments are processed via Stripe API.
   Push notifications go through APNS.
   ```
3. Leave **Enable AI enhancement** OFF
4. Create & analyze
5. Open detail → switch to **Data Flow Diagram** tab
6. **Expected**: 5 boundaries — Internet (User), DMZ (Web App), Application tier (auth), Data tier (Postgres + Redis), Third-party (Stripe + APNS)

### Test 2: LLM boundary inference (requires API key)

1. Set `ANTHROPIC_API_KEY` env var → restart server
2. New TM → toggle **Enable AI enhancement** ON
3. Use a complex system description (microservices, multi-tier)
4. Create & analyze
5. **Expected**: more nuanced boundary names (e.g. "PCI scope", "Customer data tier") with LLM-written descriptions

### Test 3: DFD editor — drag & reposition

1. In the DFD tab, **drag** any component
2. Components snap to a 20px grid
3. Cross a boundary line during the drag
4. **Expected**: when dropped inside a different boundary, the component's membership reassigns. The boundary box redraws around it. Save button appears.

### Test 4: DFD editor — inline edit

1. **Click** any component → side panel opens on the right
2. Change the name → diagram updates live as you type
3. Change the type from a dropdown → icon updates
4. **Click** any flow → side panel shows protocol, auth, encrypted toggle
5. Untick **Encrypted in transit** → flow line turns red dashed with ⚠ icon

### Test 5: DFD editor — add/remove

1. Click **＋ Component** → new "service" component appears at center
2. Side panel auto-opens — rename it
3. Click **→ Flow** → banner says "Click source...". Click two components → flow appears
4. Click any flow → side panel → **Delete flow** button → confirms → removed
5. Click **🛡 Boundary** → new empty boundary added → tick components in side panel to add them

### Test 6: DFD editor — toggle layers

In the toolbar:
- Untick **Boundaries** → all dashed boundary rectangles vanish
- Untick **Encryption icons** → 🔒/⚠ midpoint icons hide
- Untick **Labels** → component names + flow labels hide
- Re-tick all → restored

### Test 7: DFD editor — re-infer + save

1. Click **↻ Re-infer** → boundaries reset based on current components (heuristic)
2. If `ANTHROPIC_API_KEY` is set, click **🤖 Infer with AI** → AI re-reasons about zones (~3s)
3. Make some edits → **Save layout & changes** button appears
4. Click Save → toast confirms → close & re-open detail → changes persisted

### Test 8: Management read-only

Login as management user → open any TM → DFD tab:
- Toolbar shows **only** the layer toggles + zoom (no add/delete/save buttons)
- Clicking components opens side panel as **read-only** — fields are disabled

---

## Project structure

```
threat-modeler/
├── app.py                       # FastAPI app — all routes
├── auth/                        # RBAC: permissions, auth, deps
├── db/                          # SQLite schema + domain CRUD
├── threat_engine/
│   ├── methodologies.py         # STRIDE / DREAD / LINDDUN / PASTA rules
│   ├── analyzer.py              # Rule engine + extraction (now infers boundaries)
│   ├── trust_boundaries.py      # NEW: heuristic + LLM boundary inference
│   ├── dfd.py                   # Server-side static SVG (used by reports)
│   ├── scoring.py               # CVSS 3.1 + 4.0
│   ├── detail.py                # CWE mapping, attack scenarios, mitigations
│   ├── html_report.py           # Standalone interactive HTML report
│   └── report.py                # Markdown + PDF generation
├── templates/                   # Jinja2 templates
├── static/
│   ├── css/app.css              # Design system + DFD editor styles
│   └── js/
│       ├── auth.js, ui.js       # Token mgmt + UI helpers
│       ├── admin.js, dashboard.js, management.js
│       ├── dfd_editor.js        # NEW: interactive DFD editor module
│       └── app.js               # Legacy canvas
└── tests/                       # 116 tests across 5 layers
```

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

## Troubleshooting

### Login shows "Auth.setToken is not a function"
Browser cached old JS. **Hard refresh** with `Ctrl+Shift+R`.

### DFD tab is blank
Check browser DevTools (F12) → Console. Most likely `dfd_editor.js` failed to load — verify it exists at `static/js/dfd_editor.js`.

### Trust boundaries don't appear after creating a TM
The system was created before v2.4 inference was added. Open the TM → DFD tab → click **↻ Re-infer**.

### "Infer with AI" says it failed
- `ANTHROPIC_API_KEY` not set, or
- The `anthropic` Python package isn't installed (`pip install anthropic`), or
- Network/auth issue. The editor falls back to heuristic mode automatically.

### Database persistence
SQLite DB is at `data/threat_modeler.db` by default. Override with `THREAT_MODELER_DB`.
