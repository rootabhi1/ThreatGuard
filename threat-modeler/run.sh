#!/usr/bin/env bash
# ThreatGuard — one-command local launcher.
# Creates a virtualenv, installs deps, sets DEV-ONLY defaults for required
# secrets if they aren't already set, and starts the app.
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "→ Creating virtual environment..."
  python3 -m venv .venv
fi
source .venv/bin/activate

echo "→ Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# ---------------------------------------------------------------------------
# DEV-ONLY defaults. These let `./run.sh` boot with no setup. NEVER use these
# in production — set your own JWT_SECRET and admin credentials there.
# ---------------------------------------------------------------------------
export JWT_SECRET="${JWT_SECRET:-$(python -c 'import secrets; print(secrets.token_urlsafe(48))')}"
export INITIAL_ADMIN_EMAIL="${INITIAL_ADMIN_EMAIL:-admin@example.com}"
export INITIAL_ADMIN_PASSWORD="${INITIAL_ADMIN_PASSWORD:-ChangeMe123!}"

echo ""
echo "===================================================="
echo "  ThreatGuard  →  http://127.0.0.1:8000"
echo "----------------------------------------------------"
echo "  Login (DEV defaults):"
echo "    email:    $INITIAL_ADMIN_EMAIL"
echo "    password: $INITIAL_ADMIN_PASSWORD"
if [ -n "$ANTHROPIC_API_KEY" ]; then
  echo "  LLM: Claude (ANTHROPIC_API_KEY set)"
elif [ -n "$OPENAI_API_KEY" ]; then
  echo "  LLM: OpenAI-compatible (OPENAI_API_KEY set)"
else
  echo "  LLM: disabled (rules-only). Set ANTHROPIC_API_KEY or OPENAI_API_KEY to enable."
fi
echo "  ⚠  DEV credentials — do not use in production."
echo "===================================================="
echo ""

python app.py
