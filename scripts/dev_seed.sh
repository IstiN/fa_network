#!/usr/bin/env bash
# Dev seed: ready-made network + channels for UI development, no JWT needed
# beyond the mock dev login. Idempotent — safe to run against a running
# local server (mock_users.json is re-read on change).
#
# Usage: go run ./cmd/server &  →  ./scripts/dev_seed.sh
set -euo pipefail
BASE="${1:-http://localhost:8080}"

if [ ! -f mock_users.json ]; then
  printf '[{"login":"dev","password":"devpass","name":"Dev User"}]' > mock_users.json
  echo "wrote mock_users.json (dev/devpass)"
  sleep 1 # let the server re-read the users file
fi

TOKEN=$(curl -sf -X POST "$BASE/api/dev/login" \
  -H 'Content-Type: application/json' \
  -d '{"login":"dev","password":"devpass"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

# Network (409 = already seeded, fine)
NET=$(curl -s -X POST "$BASE/api/networks" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"dev-net","password":"dev-password"}')
NET_ID=$(echo "$NET" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('network',{}).get('id') or d.get('id',''))")
if [ -z "$NET_ID" ]; then
  # already exists — join with the password to discover the id
  NET_ID=$(curl -s -X POST "$BASE/api/networks/dev-net/join" \
    -H 'Content-Type: application/json' \
    -d '{"password":"dev-password","displayName":"seed"}' | python3 -c "import json,sys; print(json.load(sys.stdin).get('network',{}).get('id',''))")
fi

curl -sf -o /dev/null -X POST "$BASE/api/networks/$NET_ID/channels" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"general"}' || true
curl -sf -o /dev/null -X POST "$BASE/api/networks/$NET_ID/channels" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"showcase","public":true}' || true

echo ""
echo "Seed ready:"
echo "  network id/name : $NET_ID (dev-net)"
echo "  password        : dev-password"
echo "  authed token    : via POST $BASE/api/dev/login (dev/devpass)"
echo "  guest join      : POST $BASE/api/networks/$NET_ID/join {\"password\":\"dev-password\",\"displayName\":\"you\"}"
