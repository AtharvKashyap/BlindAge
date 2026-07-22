#!/usr/bin/env bash
# scripts/ci.sh — the CI gate. Privacy tests are product requirements [MOD-6]:
# any failure OR any unexpected xpass fails the build.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-.venv/bin/python}
"$PY" -m pytest -q --tb=short
./scripts/test_extension.sh
