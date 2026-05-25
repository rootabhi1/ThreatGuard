<div align="center">

# 🛡️ Automated Threat Modelling

**AI-powered threat modeling platform — ThreatGuard**

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![Azure](https://img.shields.io/badge/Azure-deployable-0078D4?style=flat-square&logo=microsoftazure)](https://azure.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

*Describe your system in plain English → get a full STRIDE/PASTA/LINDDUN threat model in seconds*

</div>

---

## Screenshots

### Dashboard — All Threat Models at a Glance
![Dashboard](docs/screenshots/01_dashboard.png)

### New Threat Model — Describe System, Pick Methodologies, Enable AI
![New Threat Model](docs/screenshots/02_new_threat_model.png)

### Threat Analysis Results — Full STRIDE Table with Status Tracking
![Threat Analysis](docs/screenshots/03_threat_analysis.png)

---

## What is ThreatGuard?

ThreatGuard is an open-source web application that automatically generates comprehensive threat models from your system description using industry-standard methodologies.

**Key capabilities:**

- 📝 **Text-to-threat-model** — describe your system in plain English, the engine extracts components, data flows, and trust boundaries automatically
- 🔍 **Multi-methodology** — STRIDE, DREAD, PASTA, LINDDUN run simultaneously
- 🤖 **AI enhancement** — optional Claude AI for context-specific threat reasoning and smarter trust boundary inference
- 🏢 **Full RBAC** — Admin / Management / User roles with feature-level access control
- 📊 **Export reports** — Markdown, HTML, or PDF
- 🔐 **JWT auth** — access + refresh tokens, full audit log
- 🐳 **Docker ready** — one command to run
- ☁️ **Azure deployable** — Bicep templates + GitHub Actions CI/CD

---

## How it works

```
Plain-text system description
           │
           ▼
  ┌─────────────────┐     ┌──────────────────────────────┐
  │  Text extractor  │────►│       Threat Engine           │
  │  (auto-detects   │     │  ┌────────────────────────┐  │
  │   components,    │     │  │ STRIDE · DREAD         │  │
  │   data flows,    │     │  │ PASTA  · LINDDUN       │  │
  │   trust zones)   │     │  └────────────────────────┘  │
  └─────────────────┘     │  + Claude AI (optional)       │
                          └──────────────┬────────────────┘
                                         │
                          ┌──────────────▼────────────────┐
                          │  Threat Report                 │
                          │  • Threats by category         │
                          │  • Severity scoring (CVSS)     │
                          │  • Concrete mitigations        │
                          │  • Trust boundary map          │
                          │  • Status tracking             │
                          │  • Export MD / HTML / PDF      │
                          └───────────────────────────────┘
```

---

## User Roles

| Role | Access |
|------|--------|
| **Admin** | Full access — manage users, releases, features, all threat models, audit log |
| **Management** | Read-only overview of all features and threat summaries |
| **User** | Create and manage own threat models for assigned features |

---

## Prerequisites

| Tool | Version | Required for |
|------|---------|-------------|
| Python | 3.11+ | Local run |
| Docker | 20+ | Docker run |
| Docker Compose | v2 | Docker run |
| Azure CLI | Any | Azure deploy |

---

## Option 1 — Run Locally (Python)

```bash
# 1. Extract
unzip threat-modeler.zip && cd threat-modeler

# 2. Virtual environment
python3 -m venv venv
source venv/bin/activate          # macOS/Linux
# venv\Scripts\activate           # Windows

# 3. Install
pip install -r requirements.txt

# 4. Set required env vars
export INITIAL_ADMIN_EMAIL=admin@yourcompany.com
export INITIAL_ADMIN_PASSWORD=changeme123
export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")

# Optional — enables Claude AI enrichment
export ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxx

# 5. Run
python app.py
```

Open → **http://127.0.0.1:8000**

Log in with your `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD`.

---

## Option 2 — Docker (recommended)

```bash
# 1. Extract
unzip threat-modeler.zip && cd threat-modeler

# 2. Create .env
cat > .env << EOF
INITIAL_ADMIN_EMAIL=admin@yourcompany.com
INITIAL_ADMIN_PASSWORD=ChangeMe123!
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
ANTHROPIC_API_KEY=sk-ant-xxxx
EOF

# 3. Start
docker compose up -d
```

Open → **http://localhost:8000**

```bash
docker compose logs -f          # live logs
docker compose down             # stop
docker compose up -d --build    # rebuild after changes
```

> Data persists in `./data/` — SQLite survives restarts.

---

## Option 3 — Deploy to Azure

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export LOCATION="eastus"
export RG="threat-modeler-rg"

chmod +x deploy/azure/deploy.sh && ./deploy/azure/deploy.sh
```

Takes 5–8 minutes. Prints your HTTPS URL at the end.
**Cost: ~$18/month** (App Service B1 ~$13 + ACR Basic ~$5)

See [`deploy/azure/README.md`](deploy/azure/README.md) for GitHub Actions CI/CD and custom domain setup.

---

## First Run Walkthrough

### Step 1 — Log in as Admin
Go to `http://localhost:8000` and sign in with your admin credentials.

### Step 2 — Create a Release *(Admin → Releases → Create)*
```
Name: v2.0
Status: in_progress
```

### Step 3 — Create a Feature *(Admin → Features → Create)*
```
Release: v2.0
Name: User Authentication Flow
```

### Step 4 — Create a Threat Model *(Dashboard → + New Threat Model)*
Select the feature, give it a name, then describe your system:
```
A user logs in via the React web app which sends credentials to the FastAPI
backend. The backend validates against PostgreSQL and issues a JWT token.
Redis caches session data. An OAuth provider handles social login.
Admins access a separate admin panel behind VPN.
```
Select methodologies → enable AI if available → **Create & analyze**

### Step 5 — Review threats
Threats table shows: category, severity (Critical/High/Medium/Low), status, mitigations.

### Step 6 — Track status per threat
`open` → `in_progress` → `mitigated` → `accepted_risk` → `false_positive`

### Step 7 — Export
**Export PDF / MD / HTML** from the analysis results panel.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `INITIAL_ADMIN_EMAIL` | ✅ Yes | Admin account email (created on first run) |
| `INITIAL_ADMIN_PASSWORD` | ✅ Yes | Admin password (min 8 chars) |
| `JWT_SECRET` | ✅ Yes | Random 48-char string for signing JWT tokens |
| `ANTHROPIC_API_KEY` | Optional | Claude AI enrichment — [console.anthropic.com](https://console.anthropic.com) |
| `HOST` | Optional | Bind address (default: `127.0.0.1`) |
| `PORT` | Optional | Port number (default: `8000`) |
| `CORS_ORIGINS` | Optional | Allowed origins (default: `*`) |

---

## Threat Methodologies

### STRIDE

| Letter | Threat | Example |
|--------|--------|---------|
| **S** | Spoofing | Impersonating a user via stolen credentials |
| **T** | Tampering | SQL injection modifying database records |
| **R** | Repudiation | Denying actions due to missing audit logs |
| **I** | Information Disclosure | PII exposed in verbose error messages |
| **D** | Denial of Service | Flooding the login endpoint |
| **E** | Elevation of Privilege | IDOR accessing other users' data |

### DREAD
Risk scoring: Damage + Reproducibility + Exploitability + Affected users + Discoverability

### PASTA
Process for Attack Simulation and Threat Analysis — risk-centric, attacker-focused.

### LINDDUN
Privacy threat modeling: Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance.

---

## API Reference

All endpoints require `Authorization: Bearer <token>` except auth routes.
Interactive docs at `http://localhost:8000/docs`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Login → access + refresh tokens |
| `POST` | `/api/auth/register` | Self-register (User role) |
| `POST` | `/api/auth/refresh` | Refresh access token |
| `POST` | `/api/threat-models` | Create threat model |
| `POST` | `/api/threat-models/{id}/analyze` | Run analysis |
| `GET` | `/api/threat-models/{id}/report/{fmt}` | Export markdown/html/pdf |
| `PUT` | `/api/threat-models/{id}/threats/{tid}/status` | Update threat status |
| `POST` | `/api/extract-from-text` | Extract components from plain text |
| `GET` | `/api/audit-log` | Full audit log (admin only) |
| `GET` | `/api/health` | Health check + LLM status |

---

## Project Structure

```
threat-modeler/
├── app.py                      # FastAPI app — all routes
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── auth/                       # JWT auth + RBAC
├── db/                         # SQLite CRUD layer
├── threat_engine/
│   ├── analyzer.py             # Component extraction + threat rules
│   ├── methodologies.py        # STRIDE/DREAD/PASTA/LINDDUN catalogs
│   ├── dfd.py                  # Data flow diagram SVG renderer
│   ├── scoring.py              # CVSS-inspired severity scoring
│   ├── trust_boundaries.py     # Auto-infer Internet/DMZ/App/Data zones
│   └── report.py               # MD / HTML / PDF export
├── static/js/                  # Vanilla JS frontend
├── templates/                  # Jinja2 HTML templates
├── tests/                      # pytest suite
├── docs/screenshots/           # App screenshots
└── deploy/azure/               # Bicep templates + deploy scripts
```

---

## Running Tests

```bash
source venv/bin/activate
python -m pytest tests/ -v

# Quick smoke test (requires running server)
chmod +x tests/smoke_test.sh && ./tests/smoke_test.sh
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` with venv active |
| `JWT_SECRET not set` | `export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")` |
| Port 8000 in use | `export PORT=8080` then restart |
| Admin account missing | Set `INITIAL_ADMIN_EMAIL` + `INITIAL_ADMIN_PASSWORD` before first run |
| PDF export fails | `apt-get install libpango-1.0-0 libpangoft2-1.0-0` (Linux) |
| Azure 502 on first deploy | Wait 2 min — normal container cold start |
| AI not enriching threats | Check `ANTHROPIC_API_KEY` is set; verify at `/api/health` |

---

## Claude AI Enhancement (Optional)

When `ANTHROPIC_API_KEY` is set, the engine upgrades from rule-based to AI-powered:
- Context-specific threats tailored to your actual architecture
- Smarter trust boundary inference understanding your system layout
- Richer, actionable mitigations for your specific stack

```bash
# Local
export ANTHROPIC_API_KEY=sk-ant-xxxx && python app.py

# Docker
echo "ANTHROPIC_API_KEY=sk-ant-xxxx" >> .env && docker compose up -d

# Azure
az webapp config appsettings set -n <app-name> -g <rg> \
  --settings ANTHROPIC_API_KEY="sk-ant-xxxx"
```

Get a key at **https://console.anthropic.com**

---

## Contributing

PRs welcome. Key areas:
- Additional methodologies (MITRE ATT&CK, DREAD scoring UI)
- PostgreSQL backend option
- Slack / Jira integration for threat tracking
- Expanded test coverage

---

## Security Notes

- Change `INITIAL_ADMIN_PASSWORD` immediately after first login
- Generate a unique `JWT_SECRET` per environment
- Never commit `.env` files (they are gitignored)
- All state changes recorded in the audit log at `/api/audit-log`

---

## License

MIT License — free for personal and commercial use.

---

<div align="center">

Built with FastAPI · SQLite · Claude AI · Azure

**[⬆ Back to top](#)**

</div>
