# Zero-Knowledge Age-Comparison Proofs as a Third BlindAge Proof Mode

**Status:** research survey / not a commitment. **Research as of 2026-08.**
**Author scope:** exploratory. Nothing here is scheduled; it evaluates whether a ZK
proof mode is worth a Phase-N experiment. Every load-bearing claim is cited with a URL.
Speculation is marked **[speculation]**. This document does not claim ZK "solves
everything" — it names hard parts as honestly as the wins.

---

## 1. Problem statement, in BlindAge's terms

BlindAge today has two proof modes behind the `TokenSigner`/`TokenVerifier` abstraction
(`blindage/crypto/`):

- **RFC 9474 blind single-use tokens (Phase 3).** The blind-signed message is a random
  nonce. The *claim* (`AGE_OVER_18`, assurance, epoch) is bound by **which issuer key
  signs** — key partitioning — never by a field inside the signed payload (constitution
  rule 2). The verifier reads the claim from the registry's key→claim binding.
- **BBS selective-disclosure reusable credentials** (`blindage/crypto/bbs.py`). One
  credential, multiple unlinkable presentations, disclose a subset of signed attributes.

Both modes share a structural limit: **the set of provable statements is fixed at issuance
as pre-computed boolean claims.** `AGE_OVER_18` exists because an issuer key was
provisioned to mean exactly that. Supporting `AGE_OVER_21`, `AGE_OVER_16`, or
`AGE_BETWEEN_13_AND_17` means minting more keys (blind mode) or signing more attribute
booleans (BBS mode). The thresholds a verifier can ask for are enumerable — and, in the
blind mode, *which key signed* is itself a small information leak about the claim
structure the wallet holds.

**What a ZK mode adds.** The issuer signs (or commits to) the **date of birth once**. The
wallet then proves, per presentation, an arbitrary **predicate over the signed DOB** —
`today - dob >= threshold` — in zero knowledge, revealing neither the DOB, the exact age,
nor necessarily *which threshold* was asked. A single credential covers **any** threshold
and any range/comparison predicate (`over 18`, `over 21`, `13 <= age < 18`) without
re-issuance and without pre-enumerated claim booleans. This is the promise ZK offers over
both existing modes:

1. **Predicates over signed data, not pre-issued booleans.** `age >= t` for any `t`,
   evaluated at proof time against a live date.
2. **One credential, unbounded threshold set.** No key-per-claim provisioning; no
   attribute-per-threshold at issuance.
3. **Predicate/threshold hiding.** With care, the proof can hide even *which* comparison
   was satisfied, revealing only a single verifier-chosen boolean — reducing the
   claim-structure leakage inherent in key partitioning. **[speculation on how far this
   is worth pushing — see §6.]**

This is genuinely new expressiveness. It is also the most complex crypto BlindAge would
carry, and it directly stresses constitution rule 4 (never hand-roll primitives) because
no reviewed *pure-Python* proving stack exists (§5).

---

## 2. Candidate proof systems (2026 maturity assessment)

### 2a. General-purpose SNARK toolchains

**circom + snarkjs (Groth16).** The most-documented age-over-18 tutorials use exactly this
stack: an arithmetic circuit over a birthdate, Groth16 proof, ~200-byte constant-size
proof, millisecond verification. Trade-off: **per-circuit trusted setup** (a
circuit-specific structured reference string / "powers of tau" + phase-2 ceremony), and
Groth16 is not transparent. Mature, widely deployed, well-tooled, but the trusted setup is
a governance liability for BlindAge.
Sources: [circom+snarkjs age-proof guide](https://medium.com/@ancilartech/zero-knowledge-proofs-demystified-a-practical-code-guide-for-developers-3f94682a852b),
[circom/snarkjs docs](https://github.com/miguelis/circom-documentation/blob/master/generating-zero-knowledge-proofs/circom-and-snarkjs.md).

**Noir + Barretenberg (UltraHonk).** Higher-level Rust-like DSL, browser/client-side
proving, UltraHonk backend. Reported **5–50× faster proving than Groth16** on the same
hardware with **log-scaling proof size** (vs. Groth16's constant size), at higher on-chain
verify cost — irrelevant here since our verifier is an off-chain website backend. No
per-circuit toxic-waste ceremony of the Groth16 kind (UltraHonk uses a universal/updatable
setup). Actively maturing, "Noir Beta" targets stable browser proving.
Sources: [ZKP benchmarking (Groth16 vs UltraHonk)](https://blog.base.dev/benchmarking-zkp-systems),
[Announcing Noir Beta](https://aztec.network/blog/announcing-noir-beta-stabler-faster-zk-applications-in-the-browser).

### 2b. ZK-over-existing-credentials (the most relevant class)

This class is the closest fit: it proves statements about **already-issued, conventionally
signed credentials** (mDL / ISO 18013-5, JWT, W3C VC) without re-issuing them in a
ZK-native format. This matters because it lets the *issuer keep an unmodified signing
process* while the *wallet* does the ZK work.

**Google Longfellow ZK / libzk ("Anonymous Credentials from ECDSA", Frigo & Shelat,
eprint 2024/2010).** Proves that attributes inside an ISO 18013-5 mdoc (e.g.
`age_over_18 == true`, or a predicate over signed fields) are validly issuer-signed,
**without changing issuer processes or requiring non-standard assumptions.** Proof system:
**sumcheck + Ligero + MPC-in-the-head**, built **from a collision-resistant hash only** —
**transparent, no trusted setup, no common reference string.** Reported ECDSA proof
generation ~**60 ms**; full mdoc presentation ZK proof ~**1.2 s** on mobile for certain
credential sizes (per Dec-2024 coverage; the current eprint reports faster optimized
figures — ~20 ms ECDSA, a few hundred ms mdoc — so treat 1.2 s as a conservative upper
bound). Specified in **draft-google-cfrg-libzk** (individual CFRG-stream draft,
Informational, early — v00/01/02); a libzk test vector shows a **3180-byte** proof for a simple circuit
(real mdoc proofs are larger — **[speculation: tens of KB]**, not stated in sources found).
EU Digital Identity Wallet has a Swift binding for age verification. Currently undergoing
two independent academic/industry security reviews.
Sources: [google/longfellow-zk](https://github.com/google/longfellow-zk),
[draft-google-cfrg-libzk-00](https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-00),
[Biometric Update coverage](https://www.biometricupdate.com/202412/google-researchers-build-zero-knowledge-proof-scheme-with-mdocs),
[EUDIW Swift binding](https://github.com/eu-digital-identity-wallet/av-lib-ios-longfellow-zkp),
[Longfellow site](https://google.github.io/longfellow-zk/).

**Microsoft Crescent (eprint 2024/2013).** Wraps existing **JWT and mDL** credentials with
ZK. Groth16-based, split into a one-time on-device **Prepare** phase and a fast
per-presentation **Show** phase; reported **tens-of-milliseconds** show/verify after setup.
Explicitly targets **unlinkable** presentations ("fresh and unlinkable presentation
proof"). Trade-off: Groth16 ⇒ **per-circuit trusted setup** (`run_setup.sh`). Open-sourced
Aug 2025 with a browser-extension sample client and web verifier — architecturally the
closest public prototype to BlindAge's extension + backend-verifier split.
Sources: [microsoft/crescent-credentials](https://github.com/microsoft/crescent-credentials),
[Crescent paper (eprint 2024/2013)](https://eprint.iacr.org/2024/2013.pdf),
[Biometric Update coverage](https://www.biometricupdate.com/202508/microsoft-introduces-zkps-with-unlinkability-to-preserve-digital-id-privacy).

**Vega (eprint 2025/2094).** Newer "low-latency ZK over existing credentials" work in the
same lineage; noted for completeness, not yet assessed in depth here.
Source: [Vega (eprint 2025/2094)](https://eprint.iacr.org/2025/2094.pdf).

### 2c. Anonymous-credential range/predicate proofs (no general circuit)

**BBS / BBS+ predicate extensions.** BlindAge already runs BBS selective disclosure.
Predicate proofs ("prove `age > t` without revealing DOB") are demonstrated by some
vendors (Trinsic: `>,<,>=,<=`; Evernym: `>`), but **standardized JSON-LD BBS ZKP predicate
support is incomplete** — common implementations still lack general `>`/`<`/`=` predicates.
So BBS predicates are *partially* mature: real, but not yet a stable, spec-backed range
system.
Sources: [selective-disclosure predicate overview (Meeco)](https://github.com/Meeco/docs/blob/main/concepts/selective-disclosure.md),
[Hypersign selective disclosure + age ZKP](https://hypersign.id/platform/selective-disclosure).

**Bulletproofs range proofs over Pedersen commitments.** Purpose-built for `v ∈ [0, 2^n)`
range statements. **No trusted setup**, log-size proofs, additively-homomorphic Pedersen
commitments. Verification is **linear** in range-bit-length (heavier than SNARK verify,
but fine for a website backend at these sizes). This is the natural primitive for a
*commit-and-prove* design where the issuer signs a commitment to the DOB and the wallet
proves a range in ZK **outside** an expensive signature-verification circuit (§4).
Sources: [Bulletproofs paper (Stanford)](https://web.stanford.edu/~buenz/pubs/bulletproofs.pdf),
[Building on Bulletproofs (Cathie Yun)](https://cathieyun.medium.com/building-on-bulletproofs-2faa58af0ba8).

**CFRG sigma-protocols draft.** IRTF/CFRG is standardizing interactive sigma proofs
covering discrete-log relations, ElGamal, **Pedersen commitments, and range proofs** —
useful building blocks if BlindAge takes the commit-and-prove route.
Source: [draft-irtf-cfrg-sigma-protocols](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/).

### Maturity snapshot

| System | Trusted setup | Proof size | Verify | Fit for BlindAge |
|---|---|---|---|---|
| circom/snarkjs Groth16 | Per-circuit (toxic waste) | ~constant, ~200 B | ms | High tooling, setup is a governance cost |
| Noir/UltraHonk | Universal/updatable | log-scaling | ms | Good DSL, browser proving, maturing |
| Longfellow/libzk | **None (transparent)** | KB-scale (3180 B simple; larger real) | sub-second target | **Best fit** — mdoc-native, no setup, CFRG track |
| Crescent | Per-circuit (Groth16) | small | tens of ms | Closest public prototype; setup cost |
| Bulletproofs | **None** | log-size | linear | Best commit-and-prove range primitive |
| BBS+ predicates | None | small | ms | Reuses our BBS; predicate spec immature |

---

## 3. Trusted setup, proof size, verify time — what matters for our verifier

BlindAge's verifier is a **website backend** (`blindage/verifier/`), not a smart contract,
so:

- **On-chain gas cost is irrelevant.** This deletes Groth16's main advantage (tiny
  constant proofs for cheap on-chain verify) and neutralizes UltraHonk/Bulletproofs' main
  disadvantage (larger proofs / heavier verify). We should optimize for **prover time on a
  modest client, absence of trusted setup, and auditability** — not proof bytes.
- **Trusted setup is a governance liability, not just a nuisance.** A per-circuit Groth16
  ceremony adds a trusted-setup artifact to a project whose entire trust story
  (constitution rules 1, 3, 7) is "minimize what must be trusted." A **transparent**
  system (Longfellow/libzk, Bulletproofs, UltraHonk's updatable setup) aligns far better
  with the registry-and-transparency posture BlindAge already takes.
- **Realistic numbers to design against** (from sources found): full mdoc ZK presentation
  ~**1.2 s** prover on mobile (Longfellow); ECDSA sub-proof ~**60 ms**; Crescent Show/verify
  **tens of ms** after a one-time prepare; libzk simple-circuit proof **3180 B**. Real
  DOB-predicate proofs sit between these — **[speculation: a few hundred ms to ~1 s prover,
  low-tens-of-KB proof, single-digit-to-tens-of-ms verify]**, to be measured, not assumed.

---

## 4. Integration sketch for BlindAge

Target: a third mode behind the existing `TokenSigner`/`TokenVerifier` abstraction and the
registry key→claim binding — **not** a protocol fork.

**Enrollment (issuer, once).** The issuer verifies DOB as it already does, then instead of
(or alongside) minting an `AGE_OVER_18` blind token, it **signs a credential binding the
DOB** in a ZK-friendly form. Two composable options:

- *Commit-and-prove.* Issuer signs a **Pedersen commitment** `C = dob·H + r·G` (plus
  metadata) with a signature scheme whose message can be a committed value. **BBS is
  attractive here** because BBS messages are already committable group elements and
  BlindAge already ships BBS — the wallet could prove a range predicate over the committed
  DOB with Bulletproofs/sigma range proofs **outside** an expensive
  signature-in-circuit. This keeps the hard "verify a signature inside a circuit" problem
  out of the SNARK.
- *ZK-over-signature.* Issuer signs the DOB with a conventional scheme (ECDSA/mdoc-style);
  the wallet proves signature validity **inside** the circuit (Longfellow/Crescent model).
  More general, heavier, but reuses standard issuer signing unchanged.

**Presentation (wallet).** The wallet computes, in ZK, `today - dob >= threshold`, where
`today` and `threshold` are **public inputs bound into the proof**, and binds the proof to
BlindAge's existing **domain-binding envelope**: verifier audience + fresh one-time
challenge + timestamp (constitution rule 6). The presentation stays
destination-independent; binding lives in the envelope, exactly as today.

**Verification (verifier).** Backend checks the proof against the **issuer public key from
the cached registry** (constitution rule 7 — no issuer callback), confirms the domain
binding and challenge freshness, and — for single-use semantics (rule 5) — stores
`SHA-256(nonce)` / a presentation-unique tag in the replay cache (`replay_cache.py`).

### Hard parts (stated honestly)

1. **Date math in-circuit.** `today - dob >= threshold` sounds trivial but calendar
   arithmetic (leap years, month lengths, "has the birthday occurred this year") is
   awkward in arithmetic circuits. The standard trick is to compare **canonicalized
   integer dates** (e.g. `YYYYMMDD` or epoch-days) so the predicate reduces to one integer
   comparison / range check — pushes complexity to canonicalization at enrollment.
2. **Signature-in-circuit vs. commit-and-prove.** Verifying an issuer signature *inside*
   the circuit is the expensive part (this is exactly what Longfellow's specialized ECDSA
   circuits and Crescent's Groth16 circuits spend their budget on). Commit-and-prove with
   BBS + a range proof avoids it but requires the issuer to sign commitments — a real
   enrollment-protocol change.
3. **`today` freshness.** The proof is only as honest as the `today` bound into it. The
   verifier must supply/agree the current date (naturally: it is part of the challenge
   envelope) so a wallet can't prove against a stale favorable date.
4. **Revocation.** ZK credentials are long-lived (that is the point — one credential, many
   thresholds), which reintroduces the revocation problem the single-use blind tokens
   sidestep. Options: short credential epochs (re-enroll), or an accumulator / allowlist
   proven in ZK — but **any per-user revocation structure risks re-linking** and must be
   checked against constitution rules 1 and 3 before adoption.
5. **Unlinkability of repeated presentations.** Must be verified, not assumed: naive reuse
   of the same commitment/proof randomness across sites can link. Crescent's fresh-proof
   design and BBS's per-presentation randomization are the models to follow.

---

## 5. Recommended next experiment — the PoC recipe

**Honest answer to "can this be a reviewed-library pure-Python PoC?": No, not end-to-end.**
Constitution rule 4 forbids hand-rolling primitives, and **there is no reviewed,
production-grade pure-Python ZK *proving* library** for circuit-SNARKs today. `py_ecc` is
an EC primitive library, not a proving system; Python Bulletproofs implementations exist
but are unaudited demos. So a rule-4-compliant PoC must **drive a vetted external
toolchain** and keep Python as orchestration/FFI glue — exactly the pattern already
planned for RSABSSA productionization (PyO3-wrap an audited Rust crate; see
`docs/decisions.md`).
Sources: [ZKP frameworks survey (2025)](https://arxiv.org/pdf/2502.07063),
[SoK: understanding zk-SNARKs](https://arxiv.org/pdf/2502.02387).

**Recommended PoC:**

- **Toolchain:** **Noir + Barretenberg** for the circuit, driven from Python via subprocess
  or a thin FFI wrapper (Noir is the most ergonomic reviewed DSL with browser-capable
  proving, matching BlindAge's presentation-only extension). **Alternative to evaluate in
  parallel:** wrap **Longfellow/libzk** (C++), since it is mdoc-native, **transparent
  (no trusted setup)**, with an individual CFRG-stream draft (not yet WG-adopted) — the
  best long-term fit even if a heavier PoC.
- **Minimal statement:** prove `today - dob >= 18y` where `dob` is a **private** input,
  `today` and the threshold are **public** inputs, over **canonicalized integer dates**.
  Bind the proof to a dummy domain-challenge public input to prove the envelope-binding
  path works. **Deliberately skip signature-in-circuit in v0** — assume a committed/trusted
  DOB — to isolate the date-predicate circuit first.
- **What it proves:** that `age >= threshold` predicates over a private DOB are
  expressible, that proof/verify times are acceptable for a website backend, and that
  domain-binding composes as a public input.
- **What it does NOT prove:** issuer-signature-in-circuit, revocation, unlinkability across
  presentations, or registry key→claim integration. Those are v1+.
- **Estimated effort [speculation]:** ~1–2 weeks for the date-predicate circuit + Python
  harness + benchmarks; **+several weeks** to add credential-signature verification and
  registry integration. Signature-in-circuit and revocation are the real cost, not the
  comparison.

---

## 6. Constitution alignment

**Strengthens:**

- **Rule 1 (double anonymity)** and **Rule 2 (nonce-only signed message).** ZK is the
  strongest possible version of rule 2's spirit: the verifier learns a *predicate result*,
  provably nothing else — not DOB, not exact age, potentially not even the threshold set.
  It reduces the claim-structure leakage that key partitioning inherently carries.
- **Rule 6 (domain-bound presentations).** `today`, audience, and challenge become explicit
  ZK public inputs — binding becomes cryptographically enforced, not merely enveloped.
- **Rule 7 (no issuer callback).** Verification is against cached registry keys; ZK verify
  is inherently offline. Fully compatible.
- **Rule 9 (honest framing).** ZK still cannot stop *voluntary credential sharing*; it
  changes what is disclosed, not who holds the credential. No overclaim.

**Challenges / tensions:**

- **Rule 4 (reviewed crypto only).** The sharpest tension. No reviewed pure-Python proving
  stack exists (§5); adoption *requires* taking a dependency on an external audited
  toolchain (Noir/bb, libzk) and wrapping it — and Longfellow/Crescent are **still under
  security review** as of 2026-08. This mode cannot ship until its proving library clears
  the same "audited native implementation" bar Phase 3 set for RSABSSA.
- **Rule 5 (single-use).** ZK credentials are deliberately long-lived and multi-use, which
  *reintroduces revocation* (see §4 hard part 4). Single-use semantics must be layered on
  top (per-presentation nonce in the replay cache) rather than coming for free.
- **Rule 3 (no personal data on-chain).** Any ZK **revocation** mechanism (accumulators,
  status lists) must be scrutinized so it stores no per-user data on the registry, not even
  hashed — the same bar all registry data already meets.
- **Rule 8 (refuse over-disclosure).** A predicate-hiding proof could let a verifier request
  an *unexpected* predicate the user didn't intend to answer; the consent UI must show the
  exact predicate and threshold being proven, or the flexibility becomes an over-disclosure
  vector. **[speculation: predicate-hiding may be more risk than benefit for BlindAge and
  should be scoped out of v1.]**

---

## 7. Bottom line

ZK age-comparison proofs are a **real and now-practical** third mode: they express
predicates the blind-token and BBS modes cannot, from a single credential covering any
threshold, with sub-second prover times reported in 2026-era mdoc-native systems. The
**transparent, mdoc-native lineage (Longfellow/libzk, on the CFRG track)** fits BlindAge's
trust posture best; **commit-and-prove with BBS + Bulletproofs range proofs** is the
lowest-risk integration because it avoids signature-in-circuit and reuses primitives
already in the tree. The honest blockers are **no reviewed pure-Python proving library**
(rule 4 forces an audited-native dependency, still under external review for the leading
candidates), **revocation of long-lived credentials** (rule 5 tension), and **in-circuit
date/signature complexity**. Recommended first step is a **narrow, non-shipping PoC** of
the date-predicate circuit (Noir + Python harness) to measure feasibility before any
protocol commitment.

*End of survey — research as of 2026-08. Sources are linked inline; performance figures are
quoted from those sources and re-benchmarking is required before any of them are treated as
BlindAge design constraints.*
