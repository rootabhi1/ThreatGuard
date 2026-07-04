#!/usr/bin/env bash
# Threat Modeler — local launcher
set -e

cd "$(dirname "$0")"

# Set up virtual env on first run
if [ ! -d ".venv" ]; then
  echo "→ Creating virtual environment..."
  python3 -m venv .venv
fi

# Activate
source .venv/bin/activate

# Install / update deps
echo "→ Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Run
echo ""
echo "===================================================="
echo "  Threat Modeler"
echo "===================================================="
if [ -n "$ANTHROPIC_API_KEY" ]; then
  echo "  ✓ LLM enhancement: ENABLED"
else
  echo "  · LLM enhancement: disabled"
  echo "    (export ANTHROPIC_API_KEY=sk-... to enable)"
fi
echo "  → http://127.0.0.1:8000"
echo "===================================================="
echo ""

python app.py
