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
