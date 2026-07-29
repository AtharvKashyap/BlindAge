#!/usr/bin/env bash
# scripts/run_browser_demo.sh — issuer (OIDC mode) + example site + dev IdP for
# manual browser-extension testing. TEST ONLY: the IdP is simulated.
set -euo pipefail
cd "$(dirname "$0")/.."

PY=.venv/bin/python

echo "==> Generating dev issuer material"
$PY scripts/generate_test_issuer.py --out config/dev

echo "==> Starting dev IdP (:8600), issuer in OIDC mode (:8400), example site (:8500), registry mirror (:8700)"
$PY -m uvicorn --port 8600 --factory demo_support:idp_app &
IDP_PID=$!
$PY -m uvicorn --port 8700 --factory demo_support:mirror_app &
MIRROR_PID=$!
BLINDAGE_PROOFING=oidc $PY -m uvicorn --port 8400 --factory demo_support:issuer_app &
ISSUER_PID=$!
$PY -m uvicorn --port 8500 --factory demo_support:site_app &
SITE_PID=$!
trap 'kill $IDP_PID $MIRROR_PID $ISSUER_PID $SITE_PID 2>/dev/null || true' EXIT

echo
echo "Registry root public key (paste into the extension's Trust card):"
cat config/dev/root_public_key.txt

cat <<'EOF'

Browser demo running (Ctrl-C stops everything):
  1. Load the extension (chrome://extensions -> Load unpacked -> extension/).
  2. Popup -> Trust: registry http://localhost:8700 + the root key printed above -> Save & refresh.
  3. Popup -> Get tokens -> "Enroll & get tokens" (issuer http://localhost:8400).
  4. The issuer redirects to the SIMULATED dev IdP -- pick a persona.
  5. Reopen the popup: "Enrolled - 5 tokens ready."
  6. Visit http://localhost:8500/protected and Allow once.

Tokens auto-top-up when below 2 on popup open.
EOF
wait
