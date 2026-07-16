#!/usr/bin/env bash
# Rebuild the vendored Tailwind stylesheet (static/css/tailwind.css) from the
# templates + JS. Run after adding/removing Tailwind utility classes in the UI.
#
# Requires the Tailwind v3 CLI. If not installed locally, this uses npx.
set -euo pipefail
cd "$(dirname "$0")/.."
CLI="${TAILWIND_CLI:-npx --yes tailwindcss@3}"
$CLI -c tailwind.config.js -i tailwind.input.css -o static/css/tailwind.css --minify
echo "Built static/css/tailwind.css"
