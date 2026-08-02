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
