# BlindAge Decision Log

## 2026-07-22 — RFC 9474 implementation: from-spec on `cryptography`

**Decision:** Implement RSABSSA-SHA384-PSS-Deterministic (RFC 9474) in
`blindage/crypto/rsabssa.py` directly from the spec, on top of the
`cryptography` package, rather than adopting a third-party library.

**Why:** Research (2026-07-22) found no maintained, RFC-9474-conformant
Python library on PyPI (all candidate names 404; the `privacypass` package
implements a different primitive). Existing Python code is research-grade
and unpackaged. Non-Python options (Cloudflare CIRCL/Go, jedisct1's Rust/C
libraries) would add cross-language build friction unjustifiable at dev
stage.

**How the "never hand-roll a primitive" rule is honored:** the primitives
remain reviewed code — RSA keygen and final RSA-PSS verification are
OpenSSL via `cryptography`; modular exponentiation is CPython big-int
`pow()`. What is hand-written is protocol-level: EMSA-PSS encoding
(RFC 8017 §9.1.1) and blind/unblind arithmetic (RFC 9474 §4), both gated
byte-for-byte by RFC 9474 Appendix A official test vectors
(`tests/unit/test_rsabssa_vectors.py`).

**Known limitation:** Python big-int arithmetic is not constant-time; the
issuer's BlindSign leaks timing. Acceptable for local development only.

**Production path (pre-deployment gate):** wrap jedisct1's audited Rust
crate `blind-rsa-signatures` (an RFC 9474 author) via PyO3/maturin behind
the same `blind/blind_sign/finalize` interface, or use Cloudflare CIRCL as
an issuer-side sidecar. Tracked in docs/roadmap.md.

## 2026-07-22 — Default verifier policy is blind-algorithm-only

**Decision:** `VerifierPolicy.allowed_algorithms` defaults to
`["rsabssa-sha384-pss-deterministic"]` — the blind algorithm only. `ed25519`
and `mock-hmac-sha256` remain fully supported but must be named explicitly by
an operator who consciously wants them.

**Why:** ed25519 issuance is not blind — the issuer sees the token nonce at
signing, so ed25519 tokens are *signed but linkable*. If a default verifier
accepted ed25519, an operator could provision non-blind keys and pass
verification while silently failing the double-anonymity property that is the
whole point of the system (constitution rule #1). Making the default
blind-only means unlinkability holds unless someone opts out on purpose.

**Effect:** the dev generator, shared test fixtures, and the example site all
use rsabssa keys, so the delivered default path is double-anonymous
end-to-end. Non-blind algorithms stay available for interop/testing via an
explicit `allowed_algorithms` list.

## 2026-07-22 — In-extension blind minting: pure-JS RSABSSA (Approach A)

**Decision:** Port RSABSSA-SHA384-PSS-Deterministic (RFC 9474) to pure JavaScript in the
extension so it can mint tokens in-browser, gated byte-for-byte by the same official
RFC 9474 Appendix A test vectors used for the Python implementation.

**Why:** For a browser-extension-only everyday tool the extension must blind + mint itself
(not depend on the CLI + manual export/import). This mirrors the Python decision (implement
from spec, prove against Appendix A vectors) — no new toolchain, and checkable against the
existing reference implementation + committed vectors.

**Known limitation:** JS `BigInt` arithmetic is not constant-time (parallel to the Python
caveat). Acceptable for the dev-stage tool.

**Production path (pre-deployment gate):** replace the pure-JS RSABSSA with a WASM build of
an audited native implementation, mirroring the Python PyO3/native-wrap gate.

## 2026-08-02 — BBS selective-disclosure VCs: from CFRG draft on `py_ecc`

**Decision:** Implement BBS signatures (KeyGen / Sign / Verify / ProofGen /
ProofVerify, ciphersuite `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`) from
`draft-irtf-cfrg-bbs-signatures` directly, on top of the `py_ecc` package, in
`blindage/crypto/bbs.py` — rather than adopting a third-party BBS library.

**Why:** Research (2026-08-02) found no maintained, reviewed BBS package on PyPI
implementing the current CFRG draft ciphersuite. `py_ecc` (Ethereum Foundation)
is a reviewed, widely-used implementation of the BLS12-381 curve, pairing,
hash-to-curve, and point (de)compression — exactly the primitive layer BBS
needs. Building only the BBS *protocol* layer (generator derivation,
hash-to-scalar, domain calculation, CoreSign/CoreVerify, and the
proof-generation/verification glue) on top of it keeps every elliptic-curve and
pairing operation in reviewed code. This mirrors the RSABSSA from-spec precedent
(2026-07-22): don't hand-roll a primitive; hand-write only the protocol glue and
gate it byte-for-byte against official vectors.

**How the "never hand-roll a primitive" rule is honored:** curve arithmetic,
pairings, hash-to-curve, and (de)compression are all `py_ecc`. What is
hand-written is BBS protocol-level, and it is gated by the official CFRG test
vectors (`tests/vectors/bbs_bls12381_sha256.json`): **25 official fixtures — 10
Sign/Verify + 15 ProofGen/ProofVerify — all passing** (`tests/unit/test_bbs_sign.py`,
`test_bbs_proof.py`, `test_bbs_vector_file.py`). If a vector fails, the
implementation is wrong, never the vector.

**Not blind by design:** BBS Sign is *not* a blind signature. The issuer sees the
full message vector it signs (issuer_id, assurance, epoch, and every eligible
claim). Unlinkability comes from randomized selective-disclosure *proofs* at
presentation time, not from issuance. This is a deliberate, documented trade-off
against the blind-token path — see `docs/vc-vs-tokens.md`. It does not weaken the
token path; VC mode is an additional, reusable-credential option.

**Known limitation:** this pure-Python BBS is **not constant-time** — `py_ecc`
scalar multiplication and this module's modular arithmetic both leak timing.
Suitable for development, testing, and protocol validation only.

**Production path (pre-deployment gate):** replace the pure-Python BBS primitives
with an audited, constant-time native BBS implementation (e.g. a Rust crate wrapped
via PyO3/maturin, or a WASM build) behind the same
`bbs_sign/bbs_verify/bbs_proof_gen/bbs_proof_verify` interface — the same
production gate that applies to the pure-Python RSABSSA. Tracked in
docs/roadmap.md.

## 2026-08-02 — ML-DSA-65 via cryptography/OpenSSL (hybrid trust layer)

**Decision:** Add a second, post-quantum signature over the trust registry —
ML-DSA-65 (FIPS 204, the standardized Dilithium) alongside the existing Ed25519
root signature — using `cryptography` 49's `MLDSA65` primitives (OpenSSL-backed),
in `blindage/registry/signing.py`. A `RegistryPolicy` enum
(`classical-only` / `hybrid-preferred` / `hybrid-required`) selects how strictly
the PQ signature is enforced at load time.

**Why this is different from every prior crypto decision:** for once the primitive
itself is **native and reviewed** — ML-DSA KeyGen/Sign/Verify are OpenSSL through
`cryptography`, not hand-written protocol glue on top of a primitive. There is **no
dev-only "not constant-time" caveat on ML-DSA** the way there is on the pure-Python
RSABSSA and BBS. The only hand-written code is the policy/downgrade state machine
(`verify_registry_hybrid`), which contains no secret-dependent arithmetic. No
Appendix-A-style byte-for-byte vector gate is needed for the primitive because we
are not implementing the primitive; the tests gate the *policy semantics* instead.

**Seed-based key storage:** private keys are stored as the 32-byte ML-DSA seed
(`private_bytes_raw()` on `MLDSA65PrivateKey`, restored via `from_seed_bytes`), not
the ~4 KB expanded secret key. The seed is the canonical FIPS 204 storage form and
keeps the dev key files small. Consequence noted below in the perf figures: each
`sign_registry_mldsa` re-expands the key from the seed, so signing is dominated by
key expansion, not the signature itself.

**Why the trust layer first (spec §7):** the registry is the one place where a
"harvest-now, decrypt/forge-later" adversary does real long-term damage — a forged
future registry re-roots trust for the whole system. Tokens and presentations are
short-lived and single-use, and the on-chain anchor is a **hash** commitment
(keccak256), which a quantum adversary does not threaten (Grover gives at most a
quadratic speedup on preimage search, still infeasible for 256-bit; no PQ change to
the anchor is warranted). So hybrid signing is applied where it matters — the
long-lived root of trust — and deliberately *not* spread into the token path,
extension crypto, or issuer well-known yet.

**Downgrade protection — the strict `preferred == required-when-pinned` rule:**
`hybrid-preferred` behaves **identically to `hybrid-required` whenever the client
has a pinned ML-DSA root key.** "Preferred" only softens behavior for a client that
has *no* PQ root key configured yet (early rollout); it never means "verify the PQ
signature if present, shrug if it's missing." That weaker reading is the classic
downgrade hole: if a stripped PQ signature were silently accepted by a client that
*does* hold the PQ root, an attacker who can forge only the classical Ed25519
signature (the post-quantum threat model) simply deletes `registry.sig.mldsa` and
the client falls back to the signature the attacker can forge. Enforcing
preferred-with-a-pinned-key == required closes that: once you hold the PQ root, a
missing or broken PQ signature is a hard deny (`HybridVerificationError`), so
stripping never helps. `classical-only` skips the PQ check entirely (no PQ root
pinned); `hybrid-required` additionally denies when no PQ root is configured at all.
All rows are pinned by tests including `test_downgrade_strip_attack_denied`.

**What stays classical (deliberately, this phase):** the browser extension's
in-browser registry verification (Web Crypto Ed25519 only), the issuer well-known
document, and the token/VC presentation paths. These are tracked as remaining
trust-track/PQC work, not shipped here. BlindAge is therefore **not** a
"quantum-safe system" — only the **registry trust layer** is hybrid. Claiming more
would violate the honest-framing rule.

**No production gate on the primitive** (unlike RSABSSA/BBS): the ML-DSA
implementation is already OpenSSL. The remaining production considerations are
operational, not cryptographic — a real multi-sig key-generation ceremony for the
ML-DSA root and propagating the pinned PQ root to the extension — and are tracked
in docs/roadmap.md.

## 2026-08-02 — Transparency = chain events; RevocationRoots dropped

**Decision:** Build the transparency layer as a thin, stateless view over the
on-chain `RegistryAnchor`'s `AnchorUpdated` events — **the chain is the log** —
rather than as a separate append-only log with its own signing key and storage.
The transparency log server (`blindage/transparency/app.py`) caches and serves
the ordered event history; the independent auditor
(`blindage/transparency/auditor.py`) re-derives that history from the chain and
checks it against the mirror. **Do not** build a `RevocationRoots` contract this
phase (or a separate Merkle transparency tree); registry `status` + epoch expiry
already cover revocation at this scale.

**Why chain-is-the-log:** a second, independently-stored log would be a second
source of truth that can disagree with the chain — and its signing key is one
more thing to compromise or lose. The `RegistryAnchor` already gives, for free,
exactly what a transparency log must provide: **ordering** and **immutability**
(block order + the monotonic-`version` / strictly-increasing-`generated_at`
on-chain checks) over **public trust data only** (constitution rule 3 — the
anchor holds a keccak hash + `generated_at` + version, never identity). So the
log server holds **no state and no key**; if it dies, the auditor and any client
can reconstruct the same history straight from the chain. There is nothing new to
compromise. Fail-closed is cheap and mandatory: on any RPC trouble the server
returns **503** rather than a partial or stale answer, and the auditor turns any
unreachable dependency or inconsistency into a **FAIL with a distinct problem
string** (an auditor that skips is an auditor that lies).

**Independence is bounded by the RPC endpoint.** The auditor is only as
independent as the RPC node it queries — the *same* production gate that already
applies to `AnchorClient` (add chain-id + contract-code verification, and in
practice cross-check independent RPC providers, before any non-dev deployment).
It is dev-scale today: `get_logs(from_block=0)` reads the whole history each run
(fine for anvil, not for a mainnet-length chain), and there is no testnet/mainnet
deployment.

**Why RevocationRoots was consciously dropped (YAGNI):** at the current scale,
revocation is already expressed by the signed registry itself — an issuer or key
is revoked by flipping its `status` in the registry (whose new version is then
anchored and made monotonic on-chain) and, for time-boxed trust, by **epoch
expiry** on the partitioned keys. A dedicated `RevocationRoots` contract earns
its complexity only when we need **per-token or per-batch revocation** — a
revocation granularity finer than "revoke this issuer/key in the next registry
version." We do not, so building it now would be speculative machinery. **Revisit
trigger:** a concrete requirement for per-token / per-batch revocation (e.g. a
compromised-token blocklist that must propagate faster than a registry publish).
Until then, registry status + epochs are the revocation mechanism and this is not
a gap.
