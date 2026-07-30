#!/usr/bin/env bash
# Contract test gate. Exits 0 with a notice when Foundry is absent so core CI
# stays green; runs the full contract + chain-integration suite when present.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v forge >/dev/null 2>&1; then
  echo "forge not installed — skipping contract tests (install: brew install foundry)"
  exit 0
fi
if [ ! -d registry/contracts/lib/openzeppelin-contracts ]; then
  (cd registry/contracts && forge install OpenZeppelin/openzeppelin-contracts --no-git)
fi
(cd registry/contracts && forge build && forge test)
# tests/chain/ arrives in Task 3; run it only once it exists.
if [ -d tests/chain ]; then
  .venv/bin/pytest -q tests/chain
fi
echo "contract checks passed"
