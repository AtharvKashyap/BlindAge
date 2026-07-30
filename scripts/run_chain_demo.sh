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
.venv/bin/python -m blindage.registry_chain.publish
echo "Anchored config/dev/registry.json on local anvil (addresses above). Ctrl-C to stop."
wait
