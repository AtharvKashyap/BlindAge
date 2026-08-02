#!/usr/bin/env bash
# Dev-only chain demo: anvil + deploy + anchor the dev registry via the timelock.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v anvil >/dev/null || { echo "install Foundry first: brew install foundry"; exit 1; }
(cd registry/contracts && forge build)
anvil --port 8545 --silent &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null || true' EXIT
sleep 1

# publish.py deploys the stack, anchors config/dev/registry.json via the
# timelock, and prints the addresses as a JSON line on stdout. Capture it so we
# can hand the anchor address to the transparency log server.
ADDRS=$(.venv/bin/python -m blindage.registry_chain.publish)
echo "$ADDRS"
ANCHOR=$(echo "$ADDRS" | .venv/bin/python -c "import json,sys; print(json.load(sys.stdin)['anchor'])")
export BLINDAGE_ANCHOR="$ANCHOR"
export BLINDAGE_RPC="http://127.0.0.1:8545"

echo "Anchored config/dev/registry.json on local anvil (anchor: $ANCHOR)."
cat <<EOF

--- Transparency layer (public trust history only; no identity data) ---

Start the transparency log server (serves ordered AnchorUpdated events):

  BLINDAGE_ANCHOR=$ANCHOR BLINDAGE_RPC=$BLINDAGE_RPC \\
    .venv/bin/uvicorn --port 8800 --factory demo_support:log_app
  # then:  curl -s http://127.0.0.1:8800/log | python -m json.tool

Start the registry mirror (in another terminal):

  .venv/bin/uvicorn --port 8080 --factory demo_support:mirror_app

Run the independent auditor (mirror <-> chain consistency; fails closed):

  .venv/bin/python -m blindage.transparency.auditor \\
    --mirror http://127.0.0.1:8080 --rpc $BLINDAGE_RPC --contract $ANCHOR

A tampered mirror or an unreachable dependency makes the auditor exit non-zero
with a distinct reason. See docs/governance-ceremony.md for the governance and
separation-of-duties model that these tools externally verify.

Ctrl-C to stop anvil.
EOF
wait
