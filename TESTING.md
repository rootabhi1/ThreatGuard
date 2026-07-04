# 🧪 ThreatGuard — Complete Step-by-Step Testing Guide

Three ways to run ThreatGuard locally, from zero to a fully working threat model in under 10 minutes.

---

## ✅ Prerequisites Checklist

Run these commands to verify your environment before starting:

```bash
git --version          # need 2.x+
python3 --version      # need 3.11+
pip --version          # need 21+
docker --version       # need 20+ (for Docker method)
docker compose version # need v2+ (for Docker method)
curl --version         # for smoke tests
```

If anything is missing:
- **Git**: https://git-scm.com
- **Python 3.11+**: https://python.org/downloads
- **Docker Desktop**: https://docker.com/products/docker-desktop (includes Compose v2)

---

## 📥 Step 1 — Get the Code

```bash
# Clone the repo
git clone https://github.com/rootabhi1/Automated-Threat-Modelling.git
cd Automated-Threat-Modelling

# Extract the application source
unzip threat-modeler.zip
cd threat-modeler
```

Your directory should now look like:
```
threat-modeler/
├── app.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── auth/
├── db/
├── threat_engine/
├── static/
├── templates/
├── tests/
└── deploy/azure/
```

---

## 🔑 Step 2 — Prepare Your Environment File

```bash
# Copy the example file
cp .env.example .env
```

Now edit `.env` — fill in these three **required** values:

```env
INITIAL_ADMIN_EMAIL=admin@yourcompany.com
INITIAL_ADMIN_PASSWORD=ChangeMe123!
JWT_SECRET=<generate one with the command below>
```

**Generate a secure JWT secret:**
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
# Output example: Xk2p9...  (copy and paste into .env)
```

**Optional — Claude AI enrichment:**
```env
ANTHROPIC_API_KEY=sk-ant-xxxx   # get free at console.anthropic.com
```
> Without the API key the app still works — it uses rule-based STRIDE/DREAD/PASTA/LINDDUN analysis.

---

## 🐳 METHOD 1 — Docker (Recommended)

> **Best for**: Production-like testing, no Python setup, zero environment issues.
> **Time**: ~3 minutes first run (image download + build), ~15 seconds thereafter.

### Step-by-step

```bash
# Make sure Docker Desktop is running (check system tray icon)

# Build the image and start the container
docker compose up --build

# You'll see logs like:
#   threat-modeler  | INFO:     Started server process
#   threat-modeler  | INFO:     Uvicorn running on http://0.0.0.0:8000
```

Open your browser: **http://localhost:8000**

### Common Docker commands

```bash
# Run in background (detached mode)
docker compose up -d

# Check container is healthy
docker compose ps
# Expected: threat-modeler   running (healthy)

# Live log stream
docker compose logs -f

# Stop the container
docker compose down

# Rebuild after code changes
docker compose up --build --force-recreate -d

# Open a shell inside the container (for debugging)
docker exec -it threat-modeler bash

# Verify health endpoint
curl http://localhost:8000/api/health
# Expected: {"status":"ok","llm_available":true}  (or false if no API key)

# Check persistent data survived restart
docker compose down && docker compose up -d
# Your threat models should still be there
```

### Changing the port

Edit `docker-compose.yml`:
```yaml
ports:
  - "8080:8000"   # now accessible at http://localhost:8080
```

---

## 🐍 METHOD 2 — Python (Local / Development)

> **Best for**: Code editing, hot-reloading, running tests.
> **Time**: ~2 minutes first run.

```bash
# 1. Create virtual environment
python3 -m venv venv

# 2. Activate it
source venv/bin/activate          # macOS / Linux
# OR:
venv\Scripts\activate             # Windows (PowerShell)
# OR:
venv\Scripts\activate.bat         # Windows (CMD)

# Confirm activation (you should see (venv) in your prompt)
which python   # should point to venv/bin/python

# 3. Install dependencies
pip install -r requirements.txt

# 4. Load env vars
export $(cat .env | grep -v '^#' | xargs)   # macOS / Linux
# Windows PowerShell:
# Get-Content .env | ForEach-Object { if ($_ -notmatch '^#') { $k,$v = $_ -split '=',2; [System.Environment]::SetEnvironmentVariable($k,$v) } }

# 5. Run
python app.py
```

Open your browser: **http://127.0.0.1:8000**

> The server restarts automatically if you edit source files (uses uvicorn reload mode).

---

## 📋 METHOD 3 — Shell Script (Quickest Local Run)

A `run.sh` script is bundled in the zip for macOS/Linux:

```bash
# Make it executable
chmod +x run.sh

# Edit it to set your own admin credentials (open in any editor)
nano run.sh

# Run
./run.sh
```

This sets all env vars and starts the server in one step.

---

## 🧪 Step 3 — Full Walkthrough: Test Every Feature

### 3.1 Log In as Admin

1. Open **http://localhost:8000**
2. Enter your `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD`
3. Click **Log In**
4. You should land on the **Dashboard** ✅

### 3.2 Create a Release *(Admin → Releases → + New Release)*

Fill in:
```
Name:        v2.0
Description: Second major release — auth overhaul
Status:      in_progress
```
Click **Create Release** ✅

### 3.3 Create a Feature *(Admin → Features → + New Feature)*

Fill in:
```
Release:     v2.0
Name:        User Authentication Flow
Description: Login, registration, JWT, OAuth, session management
```
Click **Create Feature** ✅

### 3.4 Register a User Account *(optional — test RBAC)*

1. Log out (top-right menu)
2. Click **Register**
3. Fill in name, email, and password
4. Log back in as admin — you should see the new user in **Admin → Users**
5. You can promote them to **management** or leave as **user**

### 3.5 Create a Threat Model *(Dashboard → + New Threat Model)*

1. Click **+ New Threat Model** on the dashboard
2. Fill in the name: `Auth Service v2 — Login & Session`
3. Select Feature: `User Authentication Flow`
4. Choose methodologies: ✅ **STRIDE** ✅ **DREAD**
5. Enable **Claude AI Enhancement** if you have an API key
6. Paste this system description into the text box:

```
A user logs in via the React web app which sends credentials to the FastAPI
backend. The backend validates against PostgreSQL and issues a JWT token.
Redis caches session data. An OAuth provider handles social login.
Admins access a separate admin panel behind VPN.
```

7. Click **Create & Analyze** ✅

### 3.6 Review the Threat Table

After analysis completes (~5–15 seconds), you'll see:
- A table of threats grouped by STRIDE category
- Each threat has: ID, category, description, affected component, severity (Critical/High/Medium/Low), DREAD score, and current status
- If AI was enabled: context-specific threat reasoning and richer mitigations

**Expected output for the sample description:**
- ~10–14 threats total
- 2–3 Critical (credential stuffing, SQLi, privilege escalation)
- 4–6 High (DoS, info disclosure, CSRF)
- 3–4 Medium (token issues, cache poisoning)

### 3.7 Update Threat Status

For each threat you can cycle the status:
```
open → in_progress → mitigated
                  → accepted_risk
                  → false_positive
```

Click the status badge on any row and select the new status. Changes are logged in the audit trail.

### 3.8 View the Data Flow Diagram

Click **View DFD** (or the diagram tab) — you'll see an auto-generated SVG data flow diagram showing:
- Your extracted components as labelled nodes
- Data flows as directed arrows
- Trust boundaries as dashed zone boxes (Internet / DMZ / App / Data zones)

### 3.9 Export a Report

Click **Export** and choose format:

| Format | Best for |
|--------|---------|
| **PDF** | Sharing with stakeholders, printing |
| **HTML** | Full interactive report in browser |
| **Markdown** | Version-controlled docs, Confluence |

```bash
# You can also export via API:
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/threat-models/1/report/pdf \
  -o threat_report.pdf
```

### 3.10 Check the Audit Log *(Admin only)*

Admin → Audit Log — every action is recorded:
- User logins and logouts
- Threat model creation and analysis
- Status changes per threat
- User role changes

---

## 🔌 Step 4 — Test the REST API Directly

The app ships with interactive Swagger docs at **http://localhost:8000/docs**

### Quick API test with curl

```bash
# 1. Login and get a token
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"ChangeMe123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token: ${TOKEN:0:30}..."

# 2. Check health + AI status
curl -s http://localhost:8000/api/health | python3 -m json.tool

# 3. List your threat models
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/threat-models | python3 -m json.tool

# 4. Extract components from text (no auth required)
curl -s -X POST http://localhost:8000/api/extract-from-text \
  -H "Content-Type: application/json" \
  -d '{"text":"React frontend calls FastAPI backend which queries PostgreSQL. Redis handles caching."}' \
  | python3 -m json.tool

# 5. Create a release
curl -s -X POST http://localhost:8000/api/releases \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"v3.0","description":"Next release","status":"planned"}' \
  | python3 -m json.tool
```

---

## 🧬 Step 5 — Run the Test Suite

```bash
# Activate venv first
source venv/bin/activate

# Run all tests
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_api.py -v
python -m pytest tests/test_rbac.py -v
python -m pytest tests/test_trust_boundaries.py -v

# Run smoke test (requires server to be running on port 8765)
chmod +x tests/smoke_test.sh
./tests/smoke_test.sh

# Windows smoke test (PowerShell)
# .\tests\smoke_test.ps1
```

Expected output:
```
tests/test_api.py::test_health PASSED
tests/test_api.py::test_register_and_login PASSED
tests/test_rbac.py::test_user_cannot_access_admin PASSED
tests/test_trust_boundaries.py::test_internet_zone_detection PASSED
...
```

---

## 🐛 Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError` | venv not active or deps missing | `source venv/bin/activate && pip install -r requirements.txt` |
| `JWT_SECRET not set` | Missing env var | `export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")` |
| Port 8000 in use | Another process using it | `export PORT=8080` then restart |
| `Admin account not created` | Missing INITIAL_ vars | Set `INITIAL_ADMIN_EMAIL` + `INITIAL_ADMIN_PASSWORD` before first run |
| `PDF export fails` | Missing system libs | `sudo apt-get install libpango-1.0-0 libpangoft2-1.0-0` (Linux/Docker already includes this) |
| `AI not enriching threats` | API key missing or wrong | Check `ANTHROPIC_API_KEY` in `.env`; verify with `curl localhost:8000/api/health` |
| Docker: `permission denied` on `./data` | Volume mount permission | `mkdir -p data uploads && chmod 755 data uploads` |
| Docker: container exits immediately | Bad env vars | `docker compose logs threat-modeler` — check for missing JWT_SECRET |
| Azure 502 on first deploy | Cold container start | Wait 2–3 min; normal behaviour for App Service B1 |
| `sqlite3.OperationalError: database is locked` | Multiple processes | Only one instance should run per SQLite DB |

---

## 📁 Project Structure

```
threat-modeler/
├── app.py                          # FastAPI app — all HTTP routes (25K lines)
├── requirements.txt                # Python deps (fastapi, uvicorn, anthropic, etc.)
├── Dockerfile                      # Docker image (python:3.12-slim)
├── docker-compose.yml              # One-command deployment
├── .env.example                    # Environment variable template
├── run.sh                          # Quick local run script
│
├── auth/                           # JWT + RBAC layer
│   ├── auth.py                     # Token creation, login, register
│   ├── deps.py                     # FastAPI dependency injection
│   └── permissions.py              # Role → permission mapping
│
├── db/                             # Database layer (SQLite)
│   ├── __init__.py                 # init_db(), db_conn(), audit()
│   └── domain.py                   # CRUD: releases, features, threat models, threats
│
├── threat_engine/                  # Core analysis engine
│   ├── analyzer.py                 # Text extraction + threat rule application + Claude AI
│   ├── methodologies.py            # STRIDE / DREAD / PASTA / LINDDUN catalogs
│   ├── dfd.py                      # SVG data flow diagram renderer
│   ├── scoring.py                  # CVSS-inspired severity scoring
│   ├── trust_boundaries.py         # Auto-infer Internet/DMZ/App/Data zones
│   ├── report.py                   # Markdown + PDF export
│   └── html_report.py              # HTML report export
│
├── static/
│   ├── css/app.css
│   └── js/                         # Vanilla JS frontend
│       ├── app.js                  # Main app logic
│       ├── dashboard.js            # Dashboard view
│       ├── auth.js                 # Login/register
│       ├── admin.js                # Admin panel
│       ├── management.js           # Management view
│       └── dfd_editor.js           # DFD drag-and-drop editor
│
├── templates/                      # Jinja2 HTML templates
│   ├── _base.html / _shell.html
│   ├── login.html / register.html
│   ├── dashboard.html
│   ├── admin.html
│   └── management.html
│
├── tests/                          # pytest + shell smoke tests
│   ├── test_api.py
│   ├── test_rbac.py
│   ├── test_trust_boundaries.py
│   ├── test_exhaustive.py
│   ├── smoke_test.sh               # End-to-end HTTP smoke test
│   └── smoke_test.ps1              # Windows version
│
├── deploy/azure/                   # Azure deployment
│   ├── main.bicep                  # Infrastructure as Code
│   ├── deploy.sh                   # One-command Azure deploy
│   └── README.md                   # Azure + CI/CD setup guide
│
├── data/                           # SQLite DB lives here (gitignored)
└── uploads/                        # Uploaded files (gitignored)
```

---

## 🌐 Live Demo

Hosted on GitHub Pages (static demo — login screen only):
**https://rootabhi1.github.io/Automated-Threat-Modelling/**

For the full working app, use Docker or Python methods above.

---

## ⚠️ Security Reminders

- Change `INITIAL_ADMIN_PASSWORD` immediately after first login
- Generate a unique `JWT_SECRET` per environment (dev / staging / prod)
- Never commit `.env` to git — it is listed in `.gitignore`
- In production, restrict `CORS_ORIGINS` to your actual domain
- All state changes are written to the audit log at `/api/audit-log`

---

## ☁️ Deploy to Azure (Optional)

```bash
# Set required vars
export ANTHROPIC_API_KEY="sk-ant-..."
export LOCATION="eastus"
export RG="threat-modeler-rg"

# Run deploy script (~5–8 minutes)
chmod +x deploy/azure/deploy.sh
./deploy/azure/deploy.sh

# Prints your HTTPS URL at the end
# Cost: ~$18/month (App Service B1 + ACR Basic)
```

See `deploy/azure/README.md` for GitHub Actions CI/CD and custom domain setup.
