#!/usr/bin/env bash
# scripts/test_extension.sh — Node unit tests for the extension core + static parse checks.
set -euo pipefail
cd "$(dirname "$0")/.."
node --test tests/extension/*.test.mjs
node -e "JSON.parse(require('fs').readFileSync('extension/manifest.json','utf8'))"
for f in extension/content.js extension/popup.js extension/background.js extension/core/*.js; do node --check "$f"; done
echo "extension checks passed"
