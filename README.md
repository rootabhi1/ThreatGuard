<div align="center">

# 🛡️ Automated Threat Modelling

**AI-powered threat modeling platform with STRIDE, PASTA & LINDDUN methodologies**

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![Azure](https://img.shields.io/badge/Azure-deployable-0078D4?style=flat-square&logo=microsoftazure)](https://azure.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

*Draw your system architecture → get a full threat model in seconds*

</div>

---

## What is this?

Automated Threat Modelling is an open-source web application that takes your system architecture — described either as a diagram or in plain text — and automatically generates a comprehensive threat model using industry-standard methodologies.

**Key capabilities:**

- 🎨 **Visual DFD canvas** — drag-and-drop data flow diagram editor with auto-layout
- 📝 **Text-to-diagram** — describe your system in plain English, the engine extracts components automatically
- 🔍 **Multi-methodology analysis** — STRIDE, PASTA, LINDDUN applied simultaneously
- 🤖 **AI enhancement** — optional Claude AI enrichment for deeper threat reasoning
- 🏢 **Full RBAC** — three-tier role system (Admin / Management / User)
- 📊 **Reports** — export as Markdown, HTML, or PDF
- 🔐 **JWT auth** — access tokens + refresh tokens with full audit log
- 🐳 **Docker ready** — single command to run
- ☁️ **Azure deployable** — Bicep templates + GitHub Actions included

---

## How it works

```
Your system description
        │
        ▼
┌───────────────────┐     ┌─────────────────────────┐
│   DFD Editor      │ ──► │   Threat Engine          │
│  (drag & drop)    │     │                          │
│                   │     │  ┌─────────────────────┐ │
│  OR               │     │  │ STRIDE analysis     │ │
│                   │     │  │ PASTA analysis      │ │
│  Text description │     │  │ LINDDUN analysis    │ │
│  (auto-extracted) │     │  └─────────────────────┘ │
└───────────────────┘     │                          │
                          │  + Claude AI (optional)  │
                          └──────────┬──────────────┘
                                     │
                          ┌──────────▼──────────────┐
                          │  Threat Report           │
                          │  • Threats by category   │
                          │  • Severity scoring      │
                          │  • Mitigations           │
                          │  • Trust boundary map    │
                          │  • Export MD/HTML/PDF    │
                          └─────────────────────────┘
```

---

## User Roles

| Role | What they can do |
|------|-----------------|
| **Admin** | Full access — manage users, releases, features, all threat models, audit log |
| **Management** | Read-only overview of all features and threat summaries (no editing) |
| **User** | Create and manage their own threat models for features they're assigned to |

---

## Prerequisites

| Tool | Version | Required for |
|------|---------|-------------|
| Python | 3.11+ | Local run |
| pip | Any | Local run |
| Docker | 20+ | Docker run |
| Docker Compose | v2 | Docker run |
| Azure CLI | Any | Azure deploy |

---

## Option 1 — Run Locally (Python)

### Step 1 — Extract the project

```bash
# Download threat-modeler.zip from the repo, then:
unzip threat-modeler.zip
cd threat-modeler
```

### Step 2 — Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate          # macOS / Linux
# OR
venv\Scripts\activate             # Windows
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Set environment variables

**Required:**
```bash
export INITIAL_ADMIN_EMAIL=admin@yourcompany.com
export INITIAL_ADMIN_PASSWORD=changeme123          # change this!
export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
```

**Optional — enables Claude AI enrichment:**
```bash
export ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxx       # get free credits at console.anthropic.com
```

> **Windows users** — use `set` instead of `export`:
> ```cmd
> set INITIAL_ADMIN_EMAIL=admin@yourcompany.com
> set INITIAL_ADMIN_PASSWORD=changeme123
> set JWT_SECRET=any-long-random-string-here
> ```

### Step 5 — Run the app

```bash
python app.py
```

### Step 6 — Open in browser

```
http://127.0.0.1:8000
```

Log in with your `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD`.

---

## Option 2 — Run with Docker (recommended)

No Python installation needed.

### Step 1 — Extract and navigate

```bash
unzip threat-modeler.zip
cd threat-modeler
```

### Step 2 — Configure environment

Create a `.env` file in the project root:

```bash
cat > .env << EOF
INITIAL_ADMIN_EMAIL=admin@yourcompany.com
INITIAL_ADMIN_PASSWORD=ChangeMe123!
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
ANTHROPIC_API_KEY=sk-ant-xxxx     # optional — remove line if not using AI
EOF
```

### Step 3 — Start with Docker Compose

```bash
docker compose up -d
```

### Step 4 — Open the app

```
http://localhost:8000
```

### Useful Docker commands

```bash
docker compose logs -f              # watch live logs
docker compose down                 # stop
docker compose down -v              # stop + delete data
docker compose up -d --build        # rebuild after code changes
```

> Data is persisted in `./data/` — SQLite database survives container restarts.

---

## Option 3 — Deploy to Azure

Full Azure deployment with HTTPS, managed identity, and optional GitHub Actions CI/CD.

### Prerequisites

```bash
az login
az account set --subscription "your-subscription-name"
```

### One-command deploy

```bash
# From project root
export ANTHROPIC_API_KEY="sk-ant-..."   # optional
export LOCATION="eastus"                # Azure region
export RG="threat-modeler-rg"          # resource group name

chmod +x deploy/azure/deploy.sh
./deploy/azure/deploy.sh
```

Takes 5–8 minutes. Prints your HTTPS URL at the end.

**What gets created:**

```
threat-modeler-rg/
├── tmacrXXXXXX          Azure Container Registry  (~$5/mo)
├── threat-modeler-plan  App Service Plan B1 Linux (~$13/mo)
└── threat-modeler-XXX   Web App for Containers
```

**Total cost: ~$18/month**

### Set up auto-deploy (GitHub Actions)

1. Edit `.github/workflows/deploy-azure.yml` — update the three env vars at the top:
   ```yaml
   AZURE_WEBAPP_NAME: your-app-name
   ACR_NAME: your-acr-name
   AZURE_RESOURCE_GROUP: threat-modeler-rg
   ```

2. Set up OIDC federation (instructions are at the bottom of the workflow file)

3. Push to `main` → auto-deploys ✓

---

## First Run Walkthrough

### 1. Log in as Admin

Go to `http://localhost:8000` and log in with your admin credentials.

### 2. Create a Release

Releases group related features. Go to **Admin → Releases → Create**.
```
Name: v2.0
Status: in_progress
```

### 3. Create a Feature

Features are what you're threat modeling. Go to **Admin → Features → Create**.
```
Release: v2.0
Name: User Authentication Flow
Description: Login, registration, password reset
```

### 4. Create a User account (optional)

Go to **Admin → Users → Create** to add a developer who will own the threat model:
```
Email: developer@company.com
Role: user
Feature access: User Authentication Flow  ← grant them access
```

### 5. Create a Threat Model

Log in as the developer (or stay as admin). Go to **Dashboard → New Threat Model**.

**Option A — Draw it:**
- Drag components onto the canvas (User, API, Database, Auth Service, etc.)
- Connect them with data flow arrows
- Click **Analyze**

**Option B — Describe it in text:**
```
Our system has a React web app that talks to a FastAPI backend.
The backend authenticates users via JWT and stores data in PostgreSQL.
A Redis cache sits in front of the database. Admins access an admin panel.
Payments go through Stripe.
```
Click **Extract Components** → review the auto-detected diagram → **Analyze**

### 6. Review the threat report

The analysis returns threats organized by:
- **Category** (Spoofing, Tampering, Repudiation, etc. for STRIDE)
- **Severity** (Critical / High / Medium / Low)
- **Mitigations** (specific, actionable steps)
- **Trust boundary violations**

### 7. Track threat status

For each threat, set its status:
- `open` — not yet addressed
- `in_progress` — being worked on
- `mitigated` — fix implemented
- `accepted_risk` — known and accepted
- `false_positive` — not applicable

### 8. Export the report

Click **Export** → choose **Markdown**, **HTML**, or **PDF**.

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `INITIAL_ADMIN_EMAIL` | ✅ Yes | Admin account email (created on first run) |
| `INITIAL_ADMIN_PASSWORD` | ✅ Yes | Admin account password (min 8 chars) |
| `JWT_SECRET` | ✅ Yes | Secret for signing JWT tokens — use a random 48-char string |
| `ANTHROPIC_API_KEY` | Optional | Enables Claude AI threat enrichment. Get at [console.anthropic.com](https://console.anthropic.com) |
| `HOST` | Optional | Bind address (default: `127.0.0.1` locally, `0.0.0.0` in Docker) |
| `PORT` | Optional | Port number (default: `8000`) |
| `CORS_ORIGINS` | Optional | Comma-separated allowed origins (default: `*`) |

---

## Threat Methodologies

### STRIDE
Microsoft's classic threat model covering six categories:

| Letter | Threat | Example |
|--------|--------|---------|
| **S** | Spoofing | Impersonating a user via stolen credentials |
| **T** | Tampering | SQL injection modifying database records |
| **R** | Repudiation | Denying actions due to missing audit logs |
| **I** | Information Disclosure | Exposing PII through verbose error messages |
| **D** | Denial of Service | Flooding the API to prevent legitimate access |
| **E** | Elevation of Privilege | IDOR allowing access to other users' data |

### PASTA
Process for Attack Simulation and Threat Analysis — risk-centric, attacker-focused.

### LINDDUN
Privacy-focused threat modeling:
Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance.

---

## API Reference

All endpoints require a Bearer token (except auth endpoints):
```
Authorization: Bearer <access_token>
```

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Self-register (creates User role) |
| `POST` | `/api/auth/login` | Login → returns access + refresh tokens |
| `POST` | `/api/auth/refresh` | Refresh access token |
| `POST` | `/api/auth/logout` | Revoke all refresh tokens |
| `GET` | `/api/auth/me` | Current user + permissions |

### Threat Models
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/threat-models` | Create new threat model |
| `GET` | `/api/threat-models` | List (filtered by role) |
| `GET` | `/api/threat-models/{id}` | Get with threat statuses |
| `PUT` | `/api/threat-models/{id}` | Update |
| `DELETE` | `/api/threat-models/{id}` | Delete |
| `POST` | `/api/threat-models/{id}/analyze` | Run analysis |
| `GET` | `/api/threat-models/{id}/report/{fmt}` | Export (markdown/html/pdf) |
| `PUT` | `/api/threat-models/{id}/threats/{tid}/status` | Update threat status |

### Utilities
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/extract-from-text` | Extract components from plain text |
| `POST` | `/api/analyze` | Ad-hoc analysis (no DB save) |
| `POST` | `/api/dfd-svg` | Render DFD as SVG |
| `POST` | `/api/auto-layout` | Auto-position diagram nodes |
| `GET` | `/api/methodologies` | List available methodologies |
| `GET` | `/api/health` | Health check |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/users` | List / create users |
| `PUT` | `/api/users/{id}/role` | Change user role |
| `DELETE` | `/api/users/{id}` | Deactivate user |
| `PUT` | `/api/users/{id}/feature-access` | Grant feature access |
| `GET` | `/api/releases` | List releases |
| `POST` | `/api/releases` | Create release |
| `GET` | `/api/audit-log` | Full audit log |

Full interactive API docs available at `http://localhost:8000/docs` (Swagger UI).

---

## Project Structure

```
threat-modeler/
├── app.py                      # FastAPI application — all routes
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── run.sh                      # Local run helper script
│
├── auth/                       # Authentication & authorization
│   ├── auth.py                 # JWT + refresh tokens + bcrypt
│   ├── deps.py                 # FastAPI dependency injectors
│   └── permissions.py          # RBAC permission registry
│
├── db/                         # Database layer (SQLite)
│   ├── __init__.py             # Connection, init_db, audit()
│   └── domain.py               # All CRUD operations
│
├── threat_engine/              # Core threat analysis
│   ├── analyzer.py             # Text extraction + threat rules engine
│   ├── methodologies.py        # STRIDE / PASTA / LINDDUN catalogs
│   ├── dfd.py                  # DFD → SVG renderer
│   ├── scoring.py              # CVSS-inspired severity scoring
│   ├── trust_boundaries.py     # Trust boundary inference
│   ├── report.py               # Markdown + PDF export
│   └── html_report.py          # HTML export
│
├── static/
│   ├── css/app.css
│   └── js/
│       ├── app.js              # Main canvas UI
│       ├── auth.js             # Login/register flow
│       ├── dashboard.js        # User dashboard
│       ├── admin.js            # Admin console
│       ├── management.js       # Management view
│       ├── dfd_editor.js       # DFD drag-and-drop editor
│       └── ui.js               # Shared UI utilities
│
├── templates/                  # Jinja2 HTML templates
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── admin.html
│   └── management.html
│
├── tests/                      # Test suite
│   ├── test_api.py             # API endpoint tests
│   ├── test_rbac.py            # Role-based access control tests
│   ├── test_trust_boundaries.py
│   ├── test_exhaustive.py
│   └── smoke_test.sh           # Quick smoke test script
│
└── deploy/
    └── azure/
        ├── deploy.sh           # One-shot Azure deployment script
        ├── main.bicep          # Infrastructure as code
        ├── README.md           # Full Azure deployment guide
        └── custom-domain.md    # Custom domain + HTTPS setup
```

---

## Running Tests

```bash
# Activate venv first
source venv/bin/activate

# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_rbac.py -v

# Quick smoke test (requires running server)
chmod +x tests/smoke_test.sh && ./tests/smoke_test.sh
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` with venv active |
| `JWT_SECRET not set` | Set it: `export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")` |
| Port 8000 already in use | Change port: `export PORT=8080` then restart |
| Admin account not created | Set `INITIAL_ADMIN_EMAIL` + `INITIAL_ADMIN_PASSWORD` before first run |
| PDF export fails | Install system deps: `apt-get install libpango-1.0-0 libpangoft2-1.0-0` (Linux) |
| Docker: no space left | Run `docker system prune` to clean up |
| Azure 502 on first deploy | Normal — wait 2 min for container cold start, then refresh |
| LLM not enriching threats | Check `ANTHROPIC_API_KEY` is set; visit `/api/health` to confirm `llm_configured: true` |

---

## Claude AI Enhancement (Optional)

When `ANTHROPIC_API_KEY` is set, the threat engine upgrades from heuristic to AI-powered analysis:

- **Deeper threat reasoning** — Claude analyzes your specific architecture, not just generic rules
- **Smarter trust boundary inference** — understands your system context
- **Richer mitigations** — tailored to your stack and components

Get an API key at **https://console.anthropic.com** (pay-per-use, ~$0.001 per analysis at current Haiku prices).

To add the key after deployment:
```bash
# Local
export ANTHROPIC_API_KEY=sk-ant-xxxx && python app.py

# Docker
echo "ANTHROPIC_API_KEY=sk-ant-xxxx" >> .env && docker compose up -d

# Azure
az webapp config appsettings set -n <app-name> -g <rg> --settings ANTHROPIC_API_KEY="sk-ant-xxxx"
```

---

## Contributing

Issues and PRs welcome. Key areas:

- 🔌 Additional methodology support (DREAD, MITRE ATT&CK)
- 🗄️ PostgreSQL backend option (production-grade persistence)
- 🔔 Slack/Teams/Jira integration for threat tracking
- 📱 Mobile-friendly responsive UI
- 🧪 Expanded test coverage

---

## License

MIT License — free for personal and commercial use.

---

## Security Notes

- Change `INITIAL_ADMIN_PASSWORD` immediately after first login
- Generate a fresh `JWT_SECRET` for each environment (dev/staging/prod)
- Never commit `.env` files — they are gitignored
- The `ANTHROPIC_API_KEY` is processed server-side only — never exposed to the browser
- All state changes are recorded in the audit log (`/api/audit-log`)

---

<div align="center">

Built with FastAPI · SQLite · Claude AI · Azure

**[⬆ Back to top](#)**

</div>
