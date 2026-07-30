# BlindAge

**Prove that you are old enough without proving who you are.**

Privacy-preserving age verification: a trusted issuer verifies a user's age
once and issues unlinkable, single-use anonymous age tokens. Websites learn
only whether the user satisfies a threshold (e.g. `AGE_OVER_18`) — never
identity. The issuer never learns where tokens are used.

> **Status: Phase 9 (blockchain registry anchor slice) complete; the
> everyday-user track (through Phase 8) is complete.** The wallet blinds token
> messages (RFC 9474 RSABSSA); the issuer signs values it cannot read;
> websites verify standard RSA-PSS signatures. The issuer can no longer link
> issuance to redemption — the property this project exists for. Conformance
> is proven against RFC 9474 official test vectors. The browser extension
> onboards a user end-to-end: pick an issuer, enroll on the issuer's own page,
> and the extension auto-mints a batch of anonymous tokens in-browser via a
> pure-JS RFC 9474 port (blind/unblind/verify only; it POSTs only blinded
> messages, preserving double anonymity). Identity never enters the extension —
> the enrollment page hands back only an opaque enrollment id. Enrollment now
> runs a pluggable proofing adapter: the default `TestDobProofing` (age asserted
> via a DOB form, TEST-ONLY) or `OidcProofing`, a real OIDC Authorization Code +
> PKCE flow with fail-closed RS256-only ID-token validation, and enrollments
> expire after 365 days. The Python CLI still mints and export/import still
> works, now optional. Still not production-ready: neither Python's big-int math
> nor JS BigInt is constant-time (see docs/decisions.md) — the production gate is
> a WASM build of an audited implementation — and the bundled dev IdP is
> **SIMULATED / TEST-ONLY** (it verifies nothing); real proofing means pointing
> `OidcConfig` at a real IdP. Do not deploy.
>
> Since Phase 8 the extension trusts only **registry-approved issuers**: it
> downloads a signed trust registry, verifies the root Ed25519 signature over
> canonical JSON *locally* (vector-gated like the RFC 9474 port), rejects
> rollbacks, caches the result, and is **fail-closed** — with no verified
> registry it enrolls and mints nothing. Enrollment and minting are additionally
> gated on an exact issuer + key match against the registry. Inventory
> auto-tops-up (mint a batch of 5 when a claim drops below 2) on popup open. The
> registry trust anchor in the extension is still a **manually pasted dev root
> key**. Phase 9 adds an on-chain anchor (see below) that fixes the freeze/
> rollback limitation at the root for parties that check it, but only on **local
> anvil** — no testnet or mainnet deployment exists and the extension is
> unchanged this phase. Do not deploy.
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

## Browser extension (Phase 4–8)

A Chrome extension (Manifest V3, vanilla JS, no build step). It detects a site's
age gate, shows a consent prompt, presents one stored anonymous token, and marks
it spent.

Since Phase 6 the extension onboards a user **self-service, no CLI needed**. In
the popup's "Get tokens" card, enter the issuer URL (default
`http://localhost:8400`) and click "Enroll & get tokens". The extension opens the
issuer's own `/enroll` page. What happens there depends on the issuer's proofing
mode: in test mode (`TestDobProofing`, the default) you fill in a date of birth;
in OIDC mode (`OidcProofing`) the issuer redirects you to an OpenID Connect
identity provider, you authenticate (Authorization Code + PKCE), and the issuer
validates the returned ID token (RS256 only, fail-closed) to read your birthdate.
Either way, on success the page hands the extension nothing but an opaque
enrollment id. The extension then auto-mints a batch of `AGE_OVER_18` tokens
(epoch auto-selected from the issuer's newest matching well-known key) and
remembers the issuer, so later top-ups need no re-enrollment (until the
enrollment expires — 365 days). Minting uses a pure-JS port of RFC 9474 RSABSSA:
the extension only blinds/unblinds/verifies (it never generates keys or signs)
and POSTs only blinded messages, so the issuer still cannot link issuance to
redemption. Identity (the DOB / OIDC claims) flows only to the issuer on the
issuer's own origin — it never enters the extension.

Since Phase 8 the extension is **registry-gated**. In the popup's **Trust** card
you enter a registry URL and the root Ed25519 public key, then "Save & refresh".
The extension downloads the signed registry, verifies the root signature over
canonical JSON entirely in-browser (Web Crypto Ed25519; the canonicalization is
vector-gated exactly like the RFC 9474 port), rejects a registry older than the
one it has cached (rollback protection), and caches the verified result. Trust is
**fail-closed**: with no configured/verified registry the extension enrolls and
mints nothing, and the "Get tokens" issuer dropdown is populated *only* from the
registry (each issuer's `endpoint` field). Enrollment and minting are gated on an
exact issuer + signing-key match against the registry, so a token can only be
minted under a key the registry currently approves.

Inventory **auto-tops-up**: when the popup opens, any claim with fewer than 2
tokens triggers a mint of a fresh batch of 5. Top-up runs only on popup open (not
on a timer or at redemption) so that minting never correlates in time with a
redemption — preserving the issuance↔redemption unlinkability the project exists
for. The extension's registry trust anchor is a manually pasted dev root key and
the mirror is a dev convenience; Phase 9 (below) adds an on-chain anchor that the
mirror and verifier SDK check, but the extension is unchanged this phase. This
completes the **everyday-user track**: prove age once, then one-click anonymous
presentations everywhere, with issuer trust sourced from a signed registry.

> **The bundled dev IdP is SIMULATED / TEST-ONLY.** It verifies no real identity
> documents — it just lets you pick a persona (or type any DOB) and mints a
> matching ID token with a fresh random `sub` per authorization. Real production
> proofing means pointing `OidcConfig` at a real IdP — that is configuration, not
> a code change. The `TestDobProofing` DOB form likewise asserts an age with no
> proofing. **Not for deployment:** JS BigInt is not constant-time, so the
> production gate is a WASM build of an audited implementation (see
> docs/decisions.md); the port is vector-gated against RFC 9474 Appendix A only.

The one-command browser demo runs the issuer in OIDC mode against the simulated
dev IdP, the example site, and the dev registry mirror:

```bash
./scripts/run_browser_demo.sh   # dev IdP :8600 + issuer (OIDC) :8400 + site :8500 + registry mirror :8700
```

It prints the registry root public key. Load `extension/` unpacked
(chrome://extensions → Developer mode → Load unpacked). First, in the popup's
**Trust** card, enter registry `http://localhost:8700` and paste the printed root
key, then "Save & refresh" (without this the extension is fail-closed and mints
nothing). Then click "Enroll & get tokens"; the issuer redirects you to the
simulated dev IdP, where you pick a persona; your inventory then fills. Open
`http://localhost:8500/protected`, click the BlindAge icon, and "Allow once".
Tokens auto-top-up when a claim drops below 2 on popup open.

To run a plain test-mode issuer (DOB form, no IdP) and a protected site instead:

```bash
.venv/bin/python scripts/generate_test_issuer.py
export BLINDAGE_WALLET_PASSPHRASE=demo
.venv/bin/python -m uvicorn --port 8400 --factory demo_support:issuer_app &
.venv/bin/python -m uvicorn --port 8500 --factory demo_support:site_app &
```

The Python CLI wallet still mints, and `blindage export`/import into the popup's
Import box still works — now **optional** (mainly for testing). The CLI
`--test-dob` path (and the Phase 6 DOB form) work only against **test-mode**
issuers (`TestDobProofing`); an OIDC-mode issuer rejects asserted enrollment
(`POST /v1/enrollment`) with 403 and requires the browser `/enroll` flow:

```bash
.venv/bin/python -m blindage.wallet.cli enroll --issuer http://localhost:8400 --test-dob 2000-01-01 --vault /tmp/w.blindage
.venv/bin/python -m blindage.wallet.cli mint   --issuer http://localhost:8400 --claim AGE_OVER_18 --assurance AAL2 --epoch 2026-Q3 --count 5 --vault /tmp/w.blindage
.venv/bin/python -m blindage.wallet.cli export --out /tmp/tokens.json --vault /tmp/w.blindage
```

## Blockchain anchor (Phase 9)

The signed registry solves *who to trust*, but the Phase 8 mirror still serves
the last-verified copy when it is unreachable — an attacker who can block the
mirror can **freeze** clients on a stale (still validly signed) registry so
revocations do not propagate. Phase 9 fixes this at the root with an on-chain
anchor.

`RegistryAnchor` (`registry/contracts/src/RegistryAnchor.sol`, Solidity) stores
**only** the `keccak256` of the registry document's canonical JSON, its
`generated_at`, a monotonic `version`, and `updated_at`, plus an `AnchorUpdated`
event — never any identity, token, redemption, domain, or fingerprint data, not
even hashed (constitution rule 3, enforced by an ABI privacy test). The contract
enforces on-chain rollback protection (`version` and `generated_at` must strictly
increase) independent of any client cache. Updates flow **only** through an
OpenZeppelin `TimelockController` — the anchor rejects any other caller.

Parties that opt in check the anchor and fail closed on a mismatch: the registry
mirror returns **503** if the served bytes do not hash to the on-chain pin, and
the Python verifier SDK's `TrustRegistry.load(..., anchor=...)` raises
`RegistryError`. Both cache the on-chain read so redemption never triggers a
per-request chain query. This mitigates the freeze/rollback limitation at the
root — but **only for parties that check the anchor** (mirror operators, verifier
SDK opt-in). The browser extension is **unchanged this phase**: it still trusts
its manually pasted dev root key.

Honest framing: this is **local anvil only**. There is **no testnet or mainnet
deployment**; the demo uses a **short dev timelock delay** (1 s, versus days in
production) and a hardcoded anvil dev key. It is a working slice, not a shippable
trust root. Deferred to later trust-track work: a transparency-log server +
auditor (the `AnchorUpdated` events are its data source), a `RevocationRoots`
contract, a multi-sig proposer ceremony, and an extension→RPC path.

Requires Foundry and `web3.py` (`pip install -e ".[dev]"` includes web3;
contract deps under `registry/contracts/{lib,out,cache}` are gitignored and
auto-installed by the test script):

```bash
brew install foundry            # forge + anvil + cast
./scripts/run_chain_demo.sh     # anvil + deploy anchor stack + timelocked publish of the dev registry
./scripts/test_contracts.sh     # forge build + forge test + tests/chain integration suite
```

`scripts/test_contracts.sh` is also wired into `scripts/ci.sh`; when Foundry is
absent it prints a notice and exits 0, so core CI stays green on any machine.

## Documents

- `docs/superpowers/specs/2026-07-21-blindage-design.md` — authoritative design spec
- `CLAUDE.md` — project constitution (non-negotiable privacy/crypto rules)
- `docs/superpowers/plans/2026-07-21-phase1-foundation.md` — Phase 1 plan

## Known limitations (pre-deployment)

Beyond the not-for-deployment crypto gates above, the OIDC proofing adapter has
two hardening items deferred before production:

- **JWKS is cached per-process.** The issuer fetches the IdP's signing keys once
  and reuses them; IdP key rotation needs refetch-on-`kid`-miss before production.
- **Multi-audience ID tokens are not `azp`-checked.** Tokens whose `aud` is an
  array are accepted without verifying the authorized party (`azp`) claim.

## Troubleshooting

- **macOS: `import blindage` fails outside the repo root.** The editable-install
  `.pth` file in `.venv/lib/python*/site-packages/` can intermittently pick up
  the hidden (`UF_HIDDEN`) flag on this platform, and Python 3.13 skips hidden
  `.pth` files at startup, breaking the editable install for scripts run from
  other working directories. Fix with:

  ```bash
  chflags nohidden .venv/lib/python*/site-packages/*.pth
  ```
