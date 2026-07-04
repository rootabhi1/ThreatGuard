#!/usr/bin/env bash
# Smoke test — starts the server, hits real HTTP endpoints, tears down.
# Usage: ./tests/smoke_test.sh
set -e

cd "$(dirname "$0")/.."

# Use a separate test DB
export THREAT_MODELER_DB="/tmp/smoke_test_$$.db"
export JWT_SECRET="smoke-test-secret-do-not-use-dGVzdA=="
export INITIAL_ADMIN_EMAIL="admin@smoke.test"
export INITIAL_ADMIN_PASSWORD="SmokePass123!"
export PORT=8765
export HOST=127.0.0.1

# Cleanup old DB if present
rm -f "$THREAT_MODELER_DB"

echo "  Starting server on :$PORT..."
python3 app.py > /tmp/smoke_server.log 2>&1 &
SERVER_PID=$!

cleanup() {
    echo
    echo "  Stopping server (pid=$SERVER_PID)..."
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    rm -f "$THREAT_MODELER_DB"
}
trap cleanup EXIT

# Wait for server to come up
for i in $(seq 1 30); do
    if curl -sf "http://$HOST:$PORT/api/health" > /dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

if ! curl -sf "http://$HOST:$PORT/api/health" > /dev/null 2>&1; then
    echo "  ✗ Server failed to start"
    cat /tmp/smoke_server.log
    exit 1
fi
echo "  ✓ Server is up"

# Hit health
echo
echo "  → GET /api/health"
curl -s "http://$HOST:$PORT/api/health" | python3 -m json.tool

# Login as seeded admin
echo
echo "  → POST /api/auth/login (admin)"
LOGIN_RESPONSE=$(curl -s -X POST "http://$HOST:$PORT/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$INITIAL_ADMIN_EMAIL\",\"password\":\"$INITIAL_ADMIN_PASSWORD\"}")
echo "$LOGIN_RESPONSE" | python3 -m json.tool | head -30

ADMIN_TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")
echo "  Got admin access token: ${ADMIN_TOKEN:0:30}..."

# /me endpoint
echo
echo "  → GET /api/auth/me"
curl -s "http://$HOST:$PORT/api/auth/me" -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool

# Create a release as admin
echo
echo "  → POST /api/releases"
RELEASE=$(curl -s -X POST "http://$HOST:$PORT/api/releases" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"Smoke Test Release","description":"Test","status":"planned"}')
echo "$RELEASE" | python3 -m json.tool
RELEASE_ID=$(echo "$RELEASE" | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")

# Create a feature
echo
echo "  → POST /api/features"
FEATURE=$(curl -s -X POST "http://$HOST:$PORT/api/features" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"release_id\":$RELEASE_ID,\"name\":\"Smoke Feature\",\"description\":\"\"}")
echo "$FEATURE" | python3 -m json.tool
FEATURE_ID=$(echo "$FEATURE" | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")

# Self-register a regular user
echo
echo "  → POST /api/auth/register (alice)"
ALICE=$(curl -s -X POST "http://$HOST:$PORT/api/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"alice@smoke.test","password":"AlicePass123!","full_name":"Alice"}')
echo "$ALICE" | python3 -m json.tool | head -12
ALICE_TOKEN=$(echo "$ALICE" | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")

# Alice should NOT be able to create a release
echo
echo "  → POST /api/releases as alice (should be 403)"
ALICE_RELEASE_ATTEMPT=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://$HOST:$PORT/api/releases" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"Hacker Release","description":""}')
echo "  Status: $ALICE_RELEASE_ATTEMPT"
if [ "$ALICE_RELEASE_ATTEMPT" != "403" ]; then
    echo "  ✗ FAIL — expected 403, got $ALICE_RELEASE_ATTEMPT"
    exit 1
fi
echo "  ✓ User correctly denied"

# Grant alice access to the feature so she can create a TM there
echo
echo "  → PUT /api/users/.../feature-access (admin grants alice access)"
ALICE_ID=$(echo "$ALICE" | python3 -c "import json,sys;print(json.load(sys.stdin)['user']['id'])")
curl -s -X PUT "http://$HOST:$PORT/api/users/$ALICE_ID/feature-access" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"feature_ids\":[$FEATURE_ID]}" | python3 -m json.tool

# Alice creates a threat model
echo
echo "  → POST /api/threat-models as alice"
TM=$(curl -s -X POST "http://$HOST:$PORT/api/threat-models" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"feature_id\":$FEATURE_ID,\"name\":\"Alice TM\",\"description\":\"\",\"system\":{\"name\":\"X\",\"components\":[{\"id\":\"c1\",\"name\":\"User\",\"type\":\"external_entity\"},{\"id\":\"c2\",\"name\":\"Web\",\"type\":\"webapp\"}],\"data_flows\":[{\"id\":\"f1\",\"from\":\"c1\",\"to\":\"c2\",\"data\":\"creds\",\"encrypted\":false,\"auth\":\"none\"}],\"trust_boundaries\":[]},\"methodologies\":[\"stride\"]}")
echo "$TM" | python3 -m json.tool | head -10
TM_ID=$(echo "$TM" | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")

# Run analysis
echo
echo "  → POST /api/threat-models/$TM_ID/analyze"
ANALYSIS=$(curl -s -X POST "http://$HOST:$PORT/api/threat-models/$TM_ID/analyze" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"methodologies":["stride"]}')
THREAT_COUNT=$(echo "$ANALYSIS" | python3 -c "import json,sys;print(json.load(sys.stdin)['summary']['total'])")
echo "  Got $THREAT_COUNT threats"

# Generate a report
echo
echo "  → GET /api/threat-models/$TM_ID/report/markdown"
curl -s "http://$HOST:$PORT/api/threat-models/$TM_ID/report/markdown" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -o /tmp/smoke_report.md
echo "  Report size: $(wc -c < /tmp/smoke_report.md) bytes"
if grep -q '<svg' /tmp/smoke_report.md; then
    echo "  ✓ DFD inline SVG present in markdown"
else
    echo "  ✗ DFD missing in markdown!"
    exit 1
fi

# Try a bogus endpoint
echo
echo "  → GET /api/threat-models/99999 (should be 404)"
NOT_FOUND=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://$HOST:$PORT/api/threat-models/99999" \
    -H "Authorization: Bearer $ALICE_TOKEN")
echo "  Status: $NOT_FOUND"

# Verify audit log captured everything
echo
echo "  → GET /api/audit-log"
AUDIT_COUNT=$(curl -s "http://$HOST:$PORT/api/audit-log?limit=100" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    | python3 -c "import json,sys;print(len(json.load(sys.stdin)))")
echo "  Audit log entries: $AUDIT_COUNT"

# Alice can't read the audit log
echo
echo "  → GET /api/audit-log as alice (should be 403)"
ALICE_AUDIT=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://$HOST:$PORT/api/audit-log" \
    -H "Authorization: Bearer $ALICE_TOKEN")
echo "  Status: $ALICE_AUDIT"
if [ "$ALICE_AUDIT" != "403" ]; then
    echo "  ✗ FAIL — alice should be denied audit log"
    exit 1
fi

echo
echo "════════════════════════════════════════════════════"
echo "  ✓ ALL SMOKE TESTS PASSED"
echo "════════════════════════════════════════════════════"
