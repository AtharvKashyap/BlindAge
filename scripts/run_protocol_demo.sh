#!/usr/bin/env bash
# scripts/run_protocol_demo.sh — end-to-end BlindAge Phase 1 demo (mock crypto).
set -euo pipefail
cd "$(dirname "$0")/.."

PY=.venv/bin/python
export BLINDAGE_WALLET_PASSPHRASE=demo-passphrase
DEMO_DIR=$(mktemp -d)
VAULT="$DEMO_DIR/vault.blindage"

echo "==> Generating dev issuer material"
$PY scripts/generate_test_issuer.py --out config/dev

echo "==> Starting issuer (:8400) and example site (:8500)"
$PY -m uvicorn --port 8400 --factory demo_support:issuer_app &
ISSUER_PID=$!
$PY -m uvicorn --port 8500 --factory demo_support:site_app &
SITE_PID=$!
trap 'kill $ISSUER_PID $SITE_PID 2>/dev/null || true; rm -rf "$DEMO_DIR"' EXIT
sleep 2

echo "==> Enrolling (test DOB 2000-01-01) and minting 5 AGE_OVER_18 tokens"
$PY -m blindage.wallet.cli enroll --issuer http://localhost:8400 \
    --test-dob 2000-01-01 --vault "$VAULT"
$PY -m blindage.wallet.cli mint --issuer http://localhost:8400 \
    --claim AGE_OVER_18 --assurance AAL2 --epoch 2026-Q3 --count 5 --vault "$VAULT"
$PY -m blindage.wallet.cli tokens --vault "$VAULT"

echo "==> Requesting challenge from age-gated site"
curl -sf -X POST http://localhost:8500/api/challenge > "$DEMO_DIR/challenge.json"

echo "==> Proving AGE_OVER_18 (one token, domain-bound)"
$PY -m blindage.wallet.cli prove --challenge-file "$DEMO_DIR/challenge.json" \
    --out "$DEMO_DIR/presentation.json" --vault "$VAULT"

echo "==> Redeeming presentation"
curl -sf -X POST http://localhost:8500/api/redeem \
    -H 'Content-Type: application/json' \
    --data @"$DEMO_DIR/presentation.json" && echo && echo "ACCESS GRANTED"

echo "==> Replaying the same presentation (must be rejected)"
if curl -sf -X POST http://localhost:8500/api/redeem \
    -H 'Content-Type: application/json' \
    --data @"$DEMO_DIR/presentation.json"; then
  echo "ERROR: replay was accepted"; exit 1
else
  echo "Replay correctly rejected."
fi

echo "==> Demo complete."
