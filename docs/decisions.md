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
