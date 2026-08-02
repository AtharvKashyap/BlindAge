# Two modes: blind tokens vs. selective-disclosure VCs

BlindAge ships two ways for a user to prove an age threshold to a website. They
share the same trust layer (registry-approved issuer keys, epoch-based rotation,
domain-bound presentations) and both keep the verifier from learning identity.
They differ in **where the unlinkability comes from** and therefore in what a
colluding issuer and site could learn. Neither is strictly better; they trade off
issuance privacy against reusability.

This document is deliberately honest about the trade-offs (constitution rule 9).
The headline caveat, up front:

> **VC issuance is NOT blind.** When the issuer signs a BBS age credential it
> sees the full set of claims it is signing (issuer id, assurance level, epoch,
> and every age threshold the user is eligible for). Unlinkability is provided by
> randomized selective-disclosure *proofs at presentation time*, not by hiding
> anything at issuance. The blind-token path, by contrast, is blind even at
> issuance — the issuer signs a value it cannot read.

## Side-by-side

| Property | Blind tokens (RSABSSA, Phases 3–8) | Selective-disclosure VCs (BBS, Phase 10) |
| --- | --- | --- |
| **Issuance blindness** | **Blind.** The wallet blinds a random nonce; the issuer signs bytes it cannot read (RFC 9474). The issuer never sees the token value. | **NOT blind.** The issuer signs a cleartext message vector `[issuer_id, assurance, epoch, *claims]` and sees every claim it grants. |
| **What one issuance yields** | One single-use token for one claim/assurance/epoch. | One reusable credential carrying *all* claims the user is eligible for. |
| **Reuse** | Single-use. Each token is redeemable once; the verifier stores `SHA-256(nonce)` and rejects repeats. Inventory must be topped up (mint more). | Reusable. The same credential produces unlimited fresh presentations; no top-up, no per-use issuer contact. |
| **Presentation unlinkability** | Yes — two redemptions use two *disjoint* token values, so there is nothing to correlate. | Yes — two presentations of the same credential are randomized BBS proofs sharing no correlatable bytes (pinned by `tests/privacy/test_vc_unlinkability.py`). |
| **What the site receives** | An unblinded token (random nonce + issuer signature) inside a domain-bound presentation. | A randomized proof revealing only `[issuer_id, assurance, epoch, required_claim]` plus the domain binding; hidden claims and the credential signature never appear. |
| **Claim binding** | By **which issuer key signs** (key partitioning). The claim is derived from the registry key→claim binding, never from a user-controlled field. | By the BBS message vector under a `vc_signing` key; the disclosed messages are checked against the registry-looked-up key. Still no user-controlled claim field is trusted. |
| **Revocation** | Epoch-based key rotation; verifier drops keys for retired epochs. | Epoch-based, identically — the epoch is a signed, disclosed message. |
| **Issuer callback at redemption** | None. Verifier validates against cached registry keys only. | None. Verifier validates the BBS proof against the registry-looked-up public key only. |
| **Domain binding** | Per-redemption: audience + fresh one-time challenge + timestamp. | Identical: the domain binding is the BBS `presentation_header`, so a proof is valid only for its challenge. |

## What a colluding issuer + site learns

The double-anonymity property (constitution rule 1) is that the verifier never
learns identity and the issuer never learns the destination or redemption. Both
modes uphold that. The honest difference is what **collusion** — an issuer and a
site pooling what each legitimately sees — could reconstruct.

- **Blind tokens.** The issuer saw only *blinded* messages at issuance, so it has
  no token value to match against. The site saw an unblinded token it cannot tie
  back to any issuance event. Colluding, they still cannot link a redemption to
  the person who enrolled: there is no shared value. Issuance is unlinkable to
  redemption by construction — the property this project exists for.

- **Selective-disclosure VCs.** The issuer knows the exact **claim set it signed**
  for a given enrollment (it is not blind), but at presentation time it sees
  **nothing** — no callback, no proof, no timing. The site sees only a randomized
  proof and the four disclosed metadata messages. Colluding, they can correlate at
  the granularity of *the disclosed attributes* (issuer, assurance, epoch, the one
  revealed claim) — the same coarse bucket the site would learn anyway — but the
  randomized proof carries no stable credential id and no signature bytes, so two
  presentations cannot be linked to each other or back to the issuance record via
  the credential. The residual exposure relative to blind tokens is that the
  issuer *knows the claim menu it granted* to an enrollment; it just cannot see
  that menu being exercised.

In short: tokens are blind at issuance *and* unlinkable at presentation; VCs are
**not** blind at issuance but are unlinkable at presentation. Choose tokens when
issuance privacy matters most; choose VCs when you want a reusable credential and
can accept that the issuer knows which thresholds it granted.

## Security scope / not for deployment

The BBS implementation (`blindage/crypto/bbs.py`) is a from-draft implementation
on top of `py_ecc`'s reviewed BLS12-381 primitives, gated byte-for-byte by the
official CFRG test vectors (25 fixtures: 10 Sign/Verify + 15 ProofGen/ProofVerify;
see `docs/decisions.md`). It is **not constant-time** — both `py_ecc` scalar
multiplication and this module's modular arithmetic leak timing — and is suitable
for development, testing, and protocol validation only.

**Production gate:** replace the pure-Python BBS primitives with an audited,
constant-time native BBS implementation (a Rust crate via PyO3/maturin, or a WASM
build) behind the same `bbs_sign/bbs_verify/bbs_proof_gen/bbs_proof_verify`
interface — the same gate that applies to the pure-Python RSABSSA. Tracked in
`docs/roadmap.md`.
