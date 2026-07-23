# BlindAge

**Prove that you are old enough without proving who you are.**

Privacy-preserving age verification: a trusted issuer verifies a user's age
once and issues unlinkable, single-use anonymous age tokens. Websites learn
only whether the user satisfies a threshold (e.g. `AGE_OVER_18`) — never
identity. The issuer never learns where tokens are used.

> **Status: Phase 6 (self-service onboarding).** The wallet blinds token
> messages (RFC 9474 RSABSSA); the issuer signs values it cannot read;
> websites verify standard RSA-PSS signatures. The issuer can no longer link
> issuance to redemption — the property this project exists for. Conformance
> is proven against RFC 9474 official test vectors. The browser extension now
> onboards a user end-to-end: pick an issuer, enroll on the issuer's own page,
> and the extension auto-mints a batch of anonymous tokens in-browser via a
> pure-JS RFC 9474 port (blind/unblind/verify only; it POSTs only blinded
> messages, preserving double anonymity). Identity never enters the extension —
> the enrollment page hands back only an opaque enrollment id. The Python CLI
> still mints and export/import still works, now optional. Still not
> production-ready: neither Python's big-int math nor JS BigInt is constant-time
> (see docs/decisions.md) — the production gate is a WASM build of an audited
> implementation — and the enrollment DOB form is a **TEST-ONLY placeholder**
> that asserts an age with no real proofing (Phase 7 replaces it with a real
> OIDC/mDL identity check). Do not deploy.
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

## Browser extension (Phase 4–6)

A Chrome extension (Manifest V3, vanilla JS, no build step). It detects a site's
age gate, shows a consent prompt, presents one stored anonymous token, and marks
it spent.

Since Phase 6 the extension onboards a user **self-service, no CLI needed**. In
the popup's "Get tokens" card, enter the issuer URL (default
`http://localhost:8400`) and click "Enroll & get tokens". The extension opens the
issuer's own `/enroll` page; you fill in a date of birth there and, on success,
the page hands the extension nothing but an opaque enrollment id. The extension
then auto-mints a batch of `AGE_OVER_18` tokens (epoch auto-selected from the
issuer's newest matching well-known key) and remembers the issuer, so later
top-ups need no re-enrollment. Minting uses a pure-JS port of RFC 9474 RSABSSA:
the extension only blinds/unblinds/verifies (it never generates keys or signs)
and POSTs only blinded messages, so the issuer still cannot link issuance to
redemption. Identity (the DOB) flows only from the enrollment page to the issuer
on the issuer's own origin — it never enters the extension.

> **The enrollment DOB form is a TEST-ONLY placeholder.** It asserts a date of
> birth with no real identity proofing; Phase 7 replaces it with a real OIDC/mDL
> age check on the issuer. **Not for deployment:** JS BigInt is not
> constant-time, so the production gate is a WASM build of an audited
> implementation (see docs/decisions.md); the port is vector-gated against RFC
> 9474 Appendix A only.

To run the demo issuer and a protected site locally:

```bash
.venv/bin/python scripts/generate_test_issuer.py
export BLINDAGE_WALLET_PASSPHRASE=demo
.venv/bin/python -m uvicorn --port 8400 --factory demo_support:issuer_app &
.venv/bin/python -m uvicorn --port 8500 --factory demo_support:site_app &
```

Then load `extension/` unpacked (chrome://extensions → Developer mode → Load
unpacked). In the popup, click "Enroll & get tokens", complete the issuer's
enroll page, and your inventory fills. Open `http://localhost:8500/protected`,
click the BlindAge icon, and "Allow once".

The Python CLI wallet still mints, and `blindage export`/import into the popup's
Import box still works — now **optional** (mainly for testing):

```bash
.venv/bin/python -m blindage.wallet.cli enroll --issuer http://localhost:8400 --test-dob 2000-01-01 --vault /tmp/w.blindage
.venv/bin/python -m blindage.wallet.cli mint   --issuer http://localhost:8400 --claim AGE_OVER_18 --assurance AAL2 --epoch 2026-Q3 --count 5 --vault /tmp/w.blindage
.venv/bin/python -m blindage.wallet.cli export --out /tmp/tokens.json --vault /tmp/w.blindage
```

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
