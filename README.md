# BlindAge

**Prove that you are old enough without proving who you are.**

Privacy-preserving age verification: a trusted issuer verifies a user's age
once and issues unlinkable, single-use anonymous age tokens. Websites learn
only whether the user satisfies a threshold (e.g. `AGE_OVER_18`) — never
identity. The issuer never learns where tokens are used.

> **Status: Phase 3 (blind signatures — double anonymity is live).** The
> wallet blinds token messages (RFC 9474 RSABSSA); the issuer signs values
> it cannot read; websites verify standard RSA-PSS signatures. The issuer
> can no longer link issuance to redemption — the property this project
> exists for. Conformance is proven against RFC 9474 official test
> vectors. Still not production-ready: Python's big-int math is not
> constant-time (see docs/decisions.md), assurance proofing is simulated,
> and while a Phase 4 presentation-only browser extension now exists (it
> presents pre-minted tokens; it does not mint in the browser), there is
> still no in-browser minting. Do not deploy.
>
> BlindAge provides privacy-preserving age *assurance*, not perfect age
> *enforcement* — it cannot fully prevent voluntary token sharing. The honest
> comparison is not "BlindAge vs perfect verification" but "BlindAge vs every
> website collecting government identity documents."

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest                       # full suite
./scripts/run_protocol_demo.sh         # end-to-end demo: enroll → mint → prove → redeem → replay-reject
```

## Browser extension (Phase 4)

A presentation-only Chrome extension (Manifest V3, vanilla JS, no build step). It
detects a site's age gate, shows a consent prompt, presents one stored anonymous
token, and marks it spent. It performs no cryptography — tokens are minted by the
Python wallet and imported.

```bash
.venv/bin/python scripts/generate_test_issuer.py
export BLINDAGE_WALLET_PASSPHRASE=demo
.venv/bin/python -m uvicorn --port 8400 --factory demo_support:issuer_app &
.venv/bin/python -m uvicorn --port 8500 --factory demo_support:site_app &
.venv/bin/python -m blindage.wallet.cli enroll --issuer http://localhost:8400 --test-dob 2000-01-01 --vault /tmp/w.blindage
.venv/bin/python -m blindage.wallet.cli mint   --issuer http://localhost:8400 --claim AGE_OVER_18 --assurance AAL2 --epoch 2026-Q3 --count 5 --vault /tmp/w.blindage
.venv/bin/python -m blindage.wallet.cli export --out /tmp/tokens.json --vault /tmp/w.blindage
```

Then load `extension/` unpacked (chrome://extensions → Developer mode → Load
unpacked), paste `/tmp/tokens.json` into the popup's Import box, open
`http://localhost:8500/protected`, click the BlindAge icon, and "Allow once".

## Documents

- `docs/superpowers/specs/2026-07-21-blindage-design.md` — authoritative design spec
- `CLAUDE.md` — project constitution (non-negotiable privacy/crypto rules)
- `docs/superpowers/plans/2026-07-21-phase1-foundation.md` — Phase 1 plan

## Troubleshooting

- **macOS: `import blindage` fails outside the repo root.** The editable-install
  `.pth` file in `.venv/lib/python*/site-packages/` can intermittently pick up
  the hidden (`UF_HIDDEN`) flag on this platform, and Python 3.13 skips hidden
  `.pth` files at startup, breaking the editable install for scripts run from
  other working directories. Fix with:

  ```bash
  chflags nohidden .venv/lib/python*/site-packages/*.pth
  ```
