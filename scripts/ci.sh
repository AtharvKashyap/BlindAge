#!/usr/bin/env bash
# scripts/ci.sh — the CI gate. Privacy tests are product requirements [MOD-6]:
# any failure OR any unexpected xpass fails the build.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-.venv/bin/python}
"$PY" -m pytest -q --tb=short
./scripts/test_extension.sh
# Contract gate: full run when Foundry is installed, otherwise a green no-op
# notice (see scripts/test_contracts.sh) so core CI stays portable.
./scripts/test_contracts.sh
