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
> and there is no browser extension yet. Do not deploy.
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
