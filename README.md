# BlindAge

**Prove that you are old enough without proving who you are.**

Privacy-preserving age verification: a trusted issuer verifies a user's age
once and issues unlinkable, single-use anonymous age tokens. Websites learn
only whether the user satisfies a threshold (e.g. `AGE_OVER_18`) — never
identity. The issuer never learns where tokens are used.

> **Status: Phase 12 (transparency + governance) complete; Phase 11 (hybrid
> post-quantum trust layer), Phase 10 (selective-disclosure verifiable
> credentials), Phase 9 (blockchain registry anchor slice), and the
> everyday-user track (through Phase 8) are complete.** Phase 12 makes the
> on-chain trust root **externally verifiable**: a transparency log server
> serves the anchor's ordered update history and an independent auditor
> cross-checks mirror ↔ chain, both fail-closed — see
> [transparency & governance](#transparency--governance-phase-12) below. The
> chain *is* the log (no second source of truth, no server key to compromise);
> a separate `RevocationRoots` contract was consciously dropped (registry
> status + epoch expiry cover revocation at this scale — see
> [`docs/decisions.md`](docs/decisions.md)).
> Phase 11 adds a second, **post-quantum** signature (ML-DSA-65) over the trust
> registry alongside the classical Ed25519 root signature, with downgrade-
> protected policy modes — see [hybrid PQC](#hybrid-post-quantum-trust-layer-phase-11)
> below. This hardens the **long-lived root of trust** against a future quantum
> adversary; only the registry trust layer is hybrid — BlindAge is **not** a
> "quantum-safe system." Phase 10 adds a second, reusable-credential
> mode (BBS selective disclosure) alongside the blind-token path — see
> [VC mode](#selective-disclosure-vc-mode-phase-10) below. **VC issuance is NOT
> blind:** the issuer sees the claims it signs; unlinkability comes from
> randomized presentation-time proofs, not from issuance. The blind-token path
> below stays blind even at issuance. The two modes are compared honestly in
> [`docs/vc-vs-tokens.md`](docs/vc-vs-tokens.md). The wallet blinds token
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
trust root. The transparency-log server + auditor and the governance
separation-of-duties model that this slice deferred have since landed in
[Phase 12](#transparency--governance-phase-12); an extension→RPC path (which
would also carry the pinned PQ root into the extension) remains open.

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

## Selective-disclosure VC mode (Phase 10)

Alongside single-use blind tokens, BlindAge offers a **reusable** age credential
using BBS selective-disclosure signatures. The issuer signs one multi-claim
credential once; the wallet then produces unlimited fresh, unlinkable
presentations, each revealing only the one threshold a site asks for.

> **VC issuance is NOT blind.** Unlike the token path (where the issuer signs a
> blinded nonce it cannot read), the BBS issuer signs a **cleartext** message
> vector and sees every claim it grants (`[issuer_id, assurance, epoch, *claims]`).
> Privacy comes from **randomized selective-disclosure proofs at presentation
> time** — two presentations of the same credential share no correlatable bytes,
> and hidden claims and the credential signature never appear in a presentation
> (CI-blocking: `tests/privacy/test_vc_unlinkability.py`). This is a deliberate
> trade-off: reusability in exchange for non-blind issuance. The full honest
> comparison — issuance blindness, reuse, revocation, and what a colluding
> issuer + site learns in each mode — is in
> [`docs/vc-vs-tokens.md`](docs/vc-vs-tokens.md).

The BBS crypto (`blindage/crypto/bbs.py`) is implemented from
`draft-irtf-cfrg-bbs-signatures` on `py_ecc`'s reviewed BLS12-381 primitives and
gated byte-for-byte by the official CFRG test vectors (25 fixtures). It is **not
constant-time** and is dev-only; production is gated on an audited native BBS
implementation, exactly like the pure-Python RSABSSA (see `docs/decisions.md`).

Run it end-to-end. The issuer issues credentials under `vc_signing` keys, and the
example site exposes `/protected-vc` plus `/api/redeem-vc`:

```bash
# 1. Fetch a reusable credential for an existing enrollment (see enroll above):
.venv/bin/python -m blindage.wallet.cli vc-get \
    --issuer http://localhost:8400 --vault /tmp/w.blindage

# 2. Get a challenge from the site, then build a domain-bound presentation.
#    The credential is reusable — repeat this step per site visit with a fresh
#    challenge and each presentation is unlinkable to the last:
.venv/bin/python -m blindage.wallet.cli vc-prove \
    --issuer http://localhost:8400 \
    --challenge-file /tmp/challenge.json --out /tmp/vc-presentation.json \
    --vault /tmp/w.blindage
```

The verifier SDK's `verify_vc_presentation` checks the BBS proof against the
issuer public key it looks up **in the registry** (never a value carried by the
presentation, never a live issuer callback), reconstructs the disclosed messages,
and enforces the domain binding + one-time challenge. Open `/protected-vc` on the
example site for the in-browser version of the same flow.

## Hybrid post-quantum trust layer (Phase 11)

The registry is the system's **long-lived root of trust**: a forged future
registry re-roots trust for everything downstream. That makes it the one place a
"harvest-now, forge-later" quantum adversary does real damage — so it is the first
(and, this phase, only) place BlindAge signs with a post-quantum algorithm.
Alongside the classical Ed25519 root signature (`registry.sig`), the generator now
emits a second signature, **ML-DSA-65** (FIPS 204;
`registry.sig.mldsa`), over the same canonical registry JSON, and publishes an
ML-DSA root public key (`root_public_key_mldsa.txt`).

Unlike the RSABSSA and BBS ports, **the ML-DSA primitive itself is native and
reviewed** — `cryptography` 49's OpenSSL-backed `MLDSA65` KeyGen/Sign/Verify. There
is **no dev-only "not constant-time" caveat on ML-DSA**; the only hand-written code
is the downgrade-protection policy state machine, which has no secret-dependent
arithmetic. Private keys are stored as the 32-byte FIPS 204 **seed**.

`TrustRegistry.load(...)` takes a `RegistryPolicy` plus the ML-DSA signature path
and pinned ML-DSA root key:

| Policy | PQ root pinned? | Behavior |
| --- | --- | --- |
| `classical-only` | — | Verify Ed25519 only; PQ signature ignored. |
| `hybrid-preferred` | no | Verify Ed25519 only (client has no PQ root yet). |
| `hybrid-preferred` | **yes** | **Identical to `hybrid-required`** — PQ signature must be present and valid. |
| `hybrid-required` | yes | Ed25519 **and** ML-DSA must both verify. |
| `hybrid-required` | no PQ root configured | **Deny** — refuses to run without a PQ root. |

The critical row is `hybrid-preferred` **with a pinned PQ root == `hybrid-required`**.
"Preferred" only softens behavior for a client that has no PQ root key configured
yet (early rollout); it never means "check the PQ signature if it happens to be
there." That weaker reading is the classic **downgrade hole**: an adversary who can
forge only the classical signature (the post-quantum threat) would just delete
`registry.sig.mldsa` and force a fallback to the signature it can forge. Once a
client holds the PQ root, a missing or broken ML-DSA signature is therefore a hard
deny — stripping never helps. Pinned by `test_downgrade_strip_attack_denied` and the
file-level `test_missing_pq_file_denies_when_needed`.

Run `hybrid-required` against the dev registry (the browser demo already generates
both keys and the mirror already serves `/registry.sig.mldsa`):

```python
from pathlib import Path
from blindage.registry import RegistryPolicy
from blindage.registry.store import TrustRegistry

dev = Path("config/dev")
reg = TrustRegistry.load(
    dev / "registry.json",
    dev / "registry.sig",
    (dev / "root_public_key.txt").read_text().strip(),
    mldsa_signature_path=dev / "registry.sig.mldsa",
    mldsa_root_public_key_b64=(dev / "root_public_key_mldsa.txt").read_text().strip(),
    policy=RegistryPolicy.HYBRID_REQUIRED,
)  # raises RegistryError if the ML-DSA signature is missing, stripped, or invalid
```

`scripts/run_browser_demo.sh` prints both the Ed25519 and the ML-DSA-65 root public
keys (the latter flagged hybrid-capable-clients-only).

**Sizes and timings.** ML-DSA-65 is much larger than Ed25519 but still negligible
in absolute terms for a per-registry-publish operation. Signature and public-key
sizes (bytes), and 50-iteration mean sign/verify time over the dev registry dict:

| Algorithm | Public key | Signature | Sign (mean) | Verify (mean) |
| --- | ---: | ---: | ---: | ---: |
| Ed25519 (classical) | 32 B | 64 B | ~0.23 ms | ~0.24 ms |
| ML-DSA-65 (post-quantum) | 1952 B | 3309 B | ~7.4 ms | ~1.0 ms |

(ML-DSA private keys are stored as a 32-byte seed. `sign_registry_mldsa` re-expands
the key from that seed on each call, so signing time is dominated by key expansion,
not the signature — irrelevant for a signing operation that runs once per registry
publish. Figures from `cryptography`/OpenSSL on the dev machine; treat as
order-of-magnitude.)

**What stays classical, and why (this phase, deliberately):**

- **The browser extension** still verifies the registry with **Ed25519 only** (Web
  Crypto). Propagating the pinned ML-DSA root to the extension is deferred
  trust-track work.
- **The issuer well-known document** and the **token / VC presentation paths** are
  unchanged — short-lived, single-use artifacts, not the long-lived trust root.
- **The on-chain anchor needs no PQ change.** It commits to the registry with a
  **keccak256 hash**, not a signature. A quantum adversary gains at most a quadratic
  (Grover) speedup on 256-bit preimage search — still infeasible — so the hash
  anchor is already post-quantum-adequate. Adding a PQ signature there would harden
  nothing.

Because only the registry trust layer is hybrid, **BlindAge is not a "quantum-safe
system"** — it is a system whose root of trust is hybrid-signed. See
`docs/decisions.md` (2026-08-02) for the full rationale.

## Transparency & governance (Phase 12)

The on-chain anchor (Phase 9) fixes trust *at the root* — but a root that only its
operators can inspect is asking to be trusted, not proving it deserves to be.
Phase 12 makes the anchor **externally verifiable** and documents the governance
that authorizes changes to it.

**The chain is the log.** There is no separate append-only log with its own key
and storage — the `RegistryAnchor`'s `AnchorUpdated` events already give the two
things a transparency log must provide: **ordering** (block order) and
**immutability** (the on-chain monotonic-`version` / strictly-increasing-
`generated_at` checks), over **public trust data only** (constitution rule 3 — a
keccak hash + `generated_at` + version, never identity). So the log server holds
**no state and no key**; if it dies, the same history is reconstructable straight
from the chain. Building a second source of truth would only add a key to
compromise and a log that can disagree with the chain. A `RevocationRoots`
contract was **consciously dropped** for the same YAGNI reason — registry
`status` + epoch expiry already express revocation at this scale; see
[`docs/decisions.md`](docs/decisions.md) (2026-08-02) for the revisit trigger
(per-token / per-batch revocation).

**Transparency log server** — a stateless, cached view over the events
(`blindage/transparency/app.py`). `GET /log` returns the ordered history; on any
RPC trouble it **fails closed with 503** rather than serving a partial or stale
answer as if complete:

```bash
# run_chain_demo.sh prints the deployed anchor address; then:
BLINDAGE_ANCHOR=<anchor> BLINDAGE_RPC=http://127.0.0.1:8545 \
  .venv/bin/uvicorn --port 8800 --factory demo_support:log_app
curl -s http://127.0.0.1:8800/log | python -m json.tool
```

**Independent auditor** — a CLI that re-derives the history from the chain and
cross-checks it against the registry mirror
(`blindage/transparency/auditor.py`). It verifies four things: the on-chain head
is reachable, the event history has no version/`generated_at` rollback, the head
matches the last logged event, and the mirror's served `registry.json` hashes to
the head anchor. Any unreachable dependency or inconsistency is a **FAIL with a
distinct problem string** (an auditor that skips is an auditor that lies), and it
carries **cron/CI exit codes** — `0` on PASS, non-zero on FAIL:

```bash
.venv/bin/python -m blindage.transparency.auditor \
  --mirror http://127.0.0.1:8080 --rpc http://127.0.0.1:8545 --contract <anchor>
# PASS (head version N)   -> exit 0
# FAIL: - <distinct reason>  -> exit 1
```

**Governance.** [`docs/governance-ceremony.md`](docs/governance-ceremony.md)
documents how registry-anchor updates are authorized, delayed, executed, and
externally verified: OpenZeppelin `TimelockController` roles (proposer / executor
/ admin) enforce **separation of duties** — a proposer can queue but not land, an
executor can land only a matured operation but queue nothing — proven on-chain in
`tests/chain/test_anchor_integration.py`. Governance touches only *which public
registry the world treats as canonical*; it never touches double anonymity, and
the worst a fully-compromised governance set can do is publish a bad *public*
registry — exactly what the transparency log and auditor exist to catch.

**Honest framing.** This is **dev-scale**: the auditor's `get_logs(from_block=0)`
re-reads the whole history each run (fine for anvil, not a mainnet-length chain),
and it is only as independent as the RPC endpoint it queries — the *same*
production gate that already applies to `AnchorClient` (add chain-id +
contract-code verification, and cross-check independent RPC providers, before any
non-dev deployment). `run_chain_demo.sh` wires the whole layer end-to-end.

The full trust story now chains: a **signed registry** (Ed25519 + hybrid ML-DSA
root over canonical JSON) → served by an **anchor-checked mirror** (503 on
hash/monotonicity mismatch) → committed to an **on-chain anchor** (timelocked,
monotonic, hash-only) → made auditable by a **transparency log + independent
auditor**. Each link fails closed, and every link past the registry carries
**public trust data only**.

## Documents

- `docs/roadmap.md` — phase status and target project tree
- `docs/decisions.md` — crypto/architecture decision log
- `docs/vc-vs-tokens.md` — honest comparison of the blind-token and VC modes
- `docs/governance-ceremony.md` — registry-anchor governance, separation of
  duties, and external verification

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
