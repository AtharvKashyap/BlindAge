# Post-Quantum Anonymous Credentials — a survey for BlindAge's credential core

**Status:** research survey, not a decision. Research as of **2026-08**.
**Scope:** the *credential core* (blind issuance + unlinkable single-use tokens),
**not** the trust layer, which is already hybrid ML-DSA-65 + Ed25519 as of Phase 11.
**Author's caveat:** this is a fast-moving field. Every load-bearing claim below is
cited with a URL. Statements not backed by a cited source are marked *[speculation]*.
Numbers quoted from papers/blogs are reproduced as reported by those sources and have
not been independently reproduced.

---

## 0. Where BlindAge stands today, and the gap

BlindAge's credential core rests on two classical, quantum-broken primitives:

- **RFC 9474 RSABSSA** blind signatures (RSA; broken by Shor's algorithm).
- **BBS on BLS12-381** (pairing / discrete-log; broken by Shor).

The **trust layer** (registry keys, transparency roots, rotation/revocation
attestations) is already hybrid PQC. The **credential core is not** — this survey is
about closing exactly that gap, and only that gap.

NIST finalized the building blocks a PQ credential core would sit on: **ML-KEM
(FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)** in Aug 2024, with **FN-DSA
(Falcon, FIPS 206) forthcoming**. But those are *plain* signatures/KEMs. There is **no
standardized PQ blind signature, PQ anonymous credential, or PQ group signature** —
these remain research primitives.
Sources: [NIST PQC standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards),
[NIST PQC road ahead, Moody 2025](https://csrc.nist.gov/csrc/media/Presentations/2025/nist-pqc-the-road-ahead/images-media/rwcpqc-march2025-moody.pdf).

---

## 1. Threat model: how much quantum risk does the credential core actually carry?

"**Harvest now, decrypt later**" (HNDL) is the strategy of recording ciphertext/
transcripts today and breaking them once a cryptographically-relevant quantum computer
(CRQC) exists. Bulk-collection infrastructure to do this at scale already exists.
Source: [Wikipedia: Harvest now, decrypt later](https://en.wikipedia.org/wiki/Harvest_now,_decrypt_later),
[Keyfactor HNDL](https://www.keyfactor.com/education-center/what-is-harvest-now-decrypt-later/).

For BlindAge specifically, the credential core has **two distinct quantum exposures**,
and they are not equally severe:

### 1a. Forgeability of the signing key (the *smaller* long-term risk for the core)

A CRQC recovers the issuer's RSA/BLS **private key**, after which an attacker can mint
tokens at will. But BlindAge tokens are **single-use** and **short-epoch**: a token is
bound to a signing key that is rotated and eventually revoked, and the verifier only
accepts keys the registry currently marks live. A forged token is only useful *while
its key is still honored*. So key-forgery risk is bounded by epoch length, **provided
the trust layer that governs key validity is itself PQ-safe — which it already is.**
The relevant analogue of "trust now, forge later" (TNFL — signatures made today under
RSA/ECC become forgeable once a CRQC exists) is largely absorbed by the hybrid trust
layer for *trust* attestations, but **not** for the token signatures themselves.
Source: [HNDL/TNFL framing](https://arxiv.org/pdf/2511.15272).

**Assessment:** for a live CRQC in year *N*, epochs and revocation limit forgery to
keys still valid at *N*. This is a real but *bounded and forward-dated* risk. It argues
for shorter epochs, not for an emergency core rewrite. *[This is my assessment of
BlindAge's design, not a cited external claim.]*

### 1b. Retroactive de-anonymization / unlinkability collapse (the *product-critical* risk)

This is the one that matters, because **unlinkability is the product** (double
anonymity, CLAUDE.md rule 1). The concern: if an adversary records issuance transcripts
(blinded message, issuer response) **and** redemption transcripts (presentation
envelopes) today, could a future CRQC **link** a redemption back to the issuance that
minted it — retroactively de-anonymizing a user long after the fact?

- HNDL is explicitly understood in the literature as enabling **retroactive
  de-anonymization**: archive all protocol communications now, break them later, then
  "link them to their past submissions."
  Source: [QADR, arXiv 2511.15272](https://arxiv.org/pdf/2511.15272).
- Whether *BlindAge's* blinding actually leaks a link under a CRQC depends on the
  blinding's **information-theoretic vs. computational** unlinkability. RSABSSA blinding
  (RFC 9474) is unlinkable because the blinding factor `r` is uniformly random and the
  unblinding is a perfect multiplicative mask — the issuer's view is statistically
  independent of the final token. A CRQC does **not** retroactively break an
  *information-theoretically* hidden relation; it breaks things that were only
  *computationally* hidden. *[This is the key technical question and it is
  scheme-specific — it must be checked per primitive, not assumed. Marked as the
  central open question, not a settled result.]*

**Assessment / action item:** BlindAge should **explicitly document, per primitive,
whether unlinkability is statistical or computational.** If RSABSSA and BBS blinding are
statistically unlinkable against the issuer's transcript view, then recorded issuance
transcripts do **not** become a retroactive de-anonymization vector under a CRQC, and
1b collapses to "protect the transport/encryption layer" (already PQ via the KEM story).
If any part of the presentation binding relies on *computational* hiding of a
user-identifying value, that part **is** HNDL-exposed and is the priority to migrate.
This distinction should be resolved before prioritizing a core rewrite. *[speculation
until verified against each scheme's proof]*

**Bottom line on threat model:** the credential core's quantum urgency is **lower** than
a naive "RSA is broken, panic" reading suggests — single-use + short-epoch + a PQ trust
layer bound most of it — *conditional on* unlinkability being statistical. The trust
layer was correctly prioritized first. The core migration is a **watch-and-stage**
problem, not a fire drill, but the statistical-vs-computational unlinkability audit is
worth doing now because it is cheap and it tells us how much time we actually have.

---

## 2. PQ blind signatures — the direct RSABSSA replacement

Lattice blind signatures have improved by roughly an order of magnitude in size since
2022, but remain far heavier than RSABSSA (whose tokens are a few hundred bytes).

| Work | Approach | Rounds | Signature size | Notes / caveats |
|---|---|---|---|---|
| Agrawal et al., CCS 2022 | Standard assumptions | 2 (round-optimal) | ~100 KB | Unbounded signatures, standard assumptions. [DOI](https://dl.acm.org/doi/abs/10.1145/3548606.3560650) |
| del Pino–Katsumata, CRYPTO 2022 | Trapdoor sampling | 2 | ~45 KB @ 109-bit core-SVP | [DOI](https://dl.acm.org/doi/10.1007/978-3-031-15979-4_11) |
| "Short, Efficient, Round-Optimal", CCS 2023 | Ring/Module-SIS/LWE + NTRU | 2 | ~20 KB | [DOI](https://dl.acm.org/doi/10.1145/3576915.3616613) |
| Blinding hash-and-sign, ePrint 2025/895 | Blind *any* PQ hash-and-sign | — | ~22 KB | Standard lattice assumptions (SIS/LWE/NTRU). [PDF](https://eprint.iacr.org/2025/895.pdf) |
| Threshold blind, ePrint 2025/1566 | Threshold lattice blind sig | 2 | 1.4×–2.5× non-threshold | First PQ threshold blind; interactive-SIS variant. [ePrint](https://eprint.iacr.org/2025/1566) |

**Older lineage** (Blaze / BlindOR) established the multi-round paradigm but had large
sizes / non-optimal rounds; the 2022–2025 round-optimal lattice works supersede them for
new designs. A readable 2025 overview of the RSA→lattice arc is
["A Gentle Introduction to Blind Signatures"](https://arxiv.org/pdf/2509.02189).

**Non-lattice direction — VOLE-in-the-Head (VOLEitH):** blind signatures from the
**MAYO** multivariate scheme are reported at **~7.5 KB with sign/verify under 50 ms** —
the most attractive size/speed point cited — but this is a *blind signature only*, "not
a full AC system, not peer-reviewed."
Source: [Cloudflare, "Policy, privacy and post-quantum: anonymous credentials for
everyone"](https://blog.cloudflare.com/pq-anonymous-credentials/).

**Standardization:** none. NIST's advanced-crypto track and IETF have **no** PQ blind
signature standard; a 2022 NIST statement quoted by Cloudflare called efficient PQ
solutions "basically non-existent," and while 2024–2025 lattice/MPCitH work is real
progress, nothing is standardized.
Sources: [Cloudflare blog](https://blog.cloudflare.com/pq-anonymous-credentials/),
[NIST road ahead](https://csrc.nist.gov/csrc/media/Presentations/2025/nist-pqc-the-road-ahead/images-media/rwcpqc-march2025-moody.pdf).

**Relevance to BlindAge:** a blind signature is the *closest structural swap* for
RSABSSA — same "blind → sign → unblind → single-use token" shape, same key-partitioning
claim binding. A 7–22 KB token is 30–100× larger than an RSABSSA token but still fits an
export/import file and a presentation envelope. This is the **most drop-in** PQ path.

---

## 3. PQ anonymous credentials, group signatures, and BBS-analogues

Beyond a bare blind signature, the richer "credential with efficient ZK protocols"
family (BBS-style: prove possession of a signature over hidden attributes) has a
lattice line and several alternative approaches.

### 3a. Lattice "signature with efficient protocols" (the BBS-analogue line)

- **Jeudy–Roux-Langlois–Sanders, CRYPTO 2023** — "Lattice Signature with Efficient
  Protocols, Application to Anonymous Credentials." The reference lattice AC framework;
  a signature designed to compose with ZK proofs, instantiable over standard or
  structured lattices, with large but *practical-for-the-first-time* performance.
  [Springer](https://link.springer.com/chapter/10.1007/978-3-031-38545-2_12),
  [ePrint 2022/509](https://eprint.iacr.org/2022/509). A companion "Framework for
  Practical Anonymous Credentials from Lattices" appeared at the same venue
  ([Springer](https://link.springer.com/chapter/10.1007/978-3-031-38545-2_13)).
- **Argo–Güneysu–Jeudy–Land, "Practical Post-Quantum Signatures for Privacy," CCS
  2024** — hash-and-sign-with-aborts, *fully implemented*. As summarized by Cloudflare:
  credentials with attribute proofs **under 80 KB**, signatures **under 7 KB**, **<400 ms
  issuance / <500 ms showing**, proof-of-knowledge-of-signature **~40 KB, prover <1 s**.
  This is currently the **best implemented** lattice AC trade-off.
  [ePrint 2024/131](https://eprint.iacr.org/2024/131.pdf),
  [ACM](https://dl.acm.org/doi/10.1145/3658644.3670297),
  numbers via [Cloudflare](https://blog.cloudflare.com/pq-anonymous-credentials/).
- **Post-Quantum Traceable Anonymous Credentials from Lattices** (2026, IACR CiC) —
  adds accountable de-anonymization on top of the Jeudy et al. line via a new
  commitment trapdoor. Traceability is a *feature BlindAge deliberately does not want*
  (double anonymity), but the construction advances the underlying AC machinery.
  [IACR CiC](https://cic.iacr.org/p/2/4/12).
- **Issuer-hiding** ([ACM 2025](https://dl.acm.org/doi/10.1145/3733820.3764678)) and
  **blocklistable / BLAC for circuits**
  ([Springer 2024](https://link.springer.com/chapter/10.1007/978-981-96-0957-4_5))
  lattice ACs exist — relevant if BlindAge ever wants issuer-hiding or revocation-by-
  blocklist, but not needed for the core token.

### 3b. Generic composition: PQ signature + general-purpose ZK (STARK-wrapped)

Prove in zero-knowledge that you hold a valid PQ signature (ML-DSA / SLH-DSA) over a
hidden nonce. This is the "zkSNARK/zkSTARK-wrapped hash-or-lattice signature" approach.

- Cloudflare's 2023 generic construction (ML-DSA + general ZK): **112 KB signatures,
  660 ms** at the balanced parameter set; a faster variant **300 ms / 173 KB**.
  [Cloudflare blog](https://blog.cloudflare.com/pq-anonymous-credentials/),
  [ePrint 2023/414](https://eprint.iacr.org/2023/414).
- **zkDilithium** (STARK-friendly Dilithium2) for a PQ Privacy Pass: token sizes
  **85–175 KB**, generation **0.3–5 s**, ~115-bit proof security.
  [ePrint 2023/414](https://eprint.iacr.org/2023/414).
- Proving a **SLH-DSA / SPHINCS+ hash-signature in ZK** (many hash calls) is possible
  in principle but the constraint count is enormous; STARKs are the natural fit because
  they are hash-based (no trusted setup, plausibly PQ), but prover cost is high and
  ZK-friendly-hash standardization (Poseidon et al.) is unsettled.
  Sources: [zk-STARK PQ posture](https://www.sciencedirect.com/science/article/abs/pii/S1383762126002523),
  [Cloudflare's call for standardized ZK-friendly hashes](https://blog.cloudflare.com/pq-anonymous-credentials/),
  [zk-creds (classical precedent)](https://www.cs.umd.edu/~imiers/pdf/zkcreds.pdf).

### 3c. MPC-in-the-head / VOLEitH signatures

Symmetric-key / MPCitH signatures (Picnic lineage, and newer VOLEitH such as FAEST,
EPID-from-VOLEitH) rely only on hash/block-cipher assumptions — attractive for
*conservative* PQ security. VOLEitH blind signatures look small/fast (§2) but a full AC
system in this framework does **not yet exist**.
Sources: [PQ ZK from symmetric primitives, ePrint 2017/279](https://eprint.iacr.org/2017/279.pdf),
[EPID from VOLEitH](https://link.springer.com/chapter/10.1007/978-3-032-32560-0_1),
[Cloudflare](https://blog.cloudflare.com/pq-anonymous-credentials/).

### Maturity snapshot (as of 2026-08)

- **Most implemented / best trade-off today:** lattice hash-and-sign-with-aborts (CCS
  2024) — <80 KB creds, <7 KB sigs, sub-second ops. Still "likely needs a significant
  speedup for real-time" per Cloudflare.
- **Smallest/fastest but least complete:** VOLEitH-from-MAYO blind sig (~7.5 KB, <50 ms)
  — not a full AC, not peer-reviewed.
- **Most flexible but heaviest:** generic ML-DSA + ZK (112–175 KB, 0.3–5 s).
- **State-of-the-art AC with private verification:** ~48 KB sigs but **hundreds of KB of
  ZK at issuance, ~20 s to generate / ~10 s to verify** — impractical for real-time.
  Source: [Cloudflare blog](https://blog.cloudflare.com/pq-anonymous-credentials/).

---

## 4. Pragmatic bridge strategies

1. **Hybrid classical + PQ credentials.** Sign/prove under *both* a classical (RSABSSA/
   BBS) and a PQ scheme so a token is valid only if both hold; unlinkability must be
   preserved by the weaker-hiding of the two. This mirrors the trust layer's existing
   ML-DSA-65 + Ed25519 hybrid and is the lowest-regret path. *[BlindAge-specific
   recommendation; hybrid signatures generally are standard practice — see NIST guidance.]*
2. **Shorten epochs to bound exposure.** Directly shrinks the §1a forgery window and, if
   presentation binding has any computational-hiding component, shrinks the §1b window
   too. Cheap, reversible, no new crypto. *[BlindAge-specific.]*
3. **ZK-over-PQ-commitments.** Keep tokens as commitments and prove statements in a
   PQ-plausible ZK system (STARK / VOLEitH), decoupling "what is signed" from "what is
   revealed." This is the generic-composition path (§3b) and the direction Privacy
   Pass PQ work is exploring.
4. **What the standards communities are signaling:**
   - **IETF Privacy Pass** — Architecture is RFC 9576 (2024); active drafts for
     **Anonymous Rate-Limited Credentials (ARC)** and **Anonymous Credit Tokens (ACT)**,
     but **no PQ variants yet**, and per-origin rate-limiting has no PQ solution.
     Sources: [ARC draft](https://datatracker.ietf.org/doc/draft-yun-cfrg-arc/),
     [Cloudflare blog](https://blog.cloudflare.com/pq-anonymous-credentials/).
   - **EU Digital Identity Wallet** launches 2026 **without** quantum-safe credentials;
     its Architecture Reference Framework names anonymous credentials as the correct
     long-term anti-linkability tool but current proposals lack PQ security.
     Source: [Cloudflare blog](https://blog.cloudflare.com/pq-anonymous-credentials/).
   - **W3C VC / ISO mDL** communities are producing "towards PQ VC" work (upgrading
     issued VCs by binding claims to issuer-signed PQ commitments) but nothing final.
     Sources: [Towards PQ Verifiable Credentials](https://dl.acm.org/doi/fullHtml/10.1145/3664476.3669932),
     [PQ ZK VC lifecycle](https://arxiv.org/pdf/2603.07974).
   - **NIST** — no advanced-primitive (blind sig / AC / group sig) standardization track
     is close to output; the message is "deploy ML-KEM/ML-DSA/SLH-DSA now, advanced
     privacy primitives are still research."
     Source: [NIST road ahead](https://csrc.nist.gov/csrc/media/Presentations/2025/nist-pqc-the-road-ahead/images-media/rwcpqc-march2025-moody.pdf).

---

## 5. Recommendation for BlindAge — a staged adoption path

BlindAge should **not** migrate the credential core now. It should **watch, instrument,
and prototype**, in stages:

**Stage 0 — do now (cheap, no new crypto):**
- Write the **statistical-vs-computational unlinkability audit** (§1b) for RSABSSA and
  BBS. This determines whether HNDL retroactive de-anonymization is even a threat and
  how much time we have. Record the answer in `docs/decisions.md`.
- Confirm epochs are as short as UX allows; document epoch length as a security
  parameter that bounds §1a.
- Keep the trust layer hybrid (already done, Phase 11).

**Stage 1 — watch (ongoing):** track four triggers. **Act when any fires:**
- A **standardized or IETF-adopted** PQ blind signature / anonymous credential appears
  (today: none).
- A **reviewed, maintained implementation** (audited library, not paper code) of a PQ
  blind sig or AC ships (today: none — see §6).
- Credible CRQC timeline estimates move materially inside BlindAge's data-retention /
  epoch horizon.
- The unlinkability audit (Stage 0) concludes any hiding is *computational* — that turns
  §1b from hypothetical into active and moves migration up.

**Stage 2 — first experiment (prototype, non-shipping):** behind the existing
`TokenSigner`/`TokenVerifier` abstraction, add a **PQ blind signature** implementation
(the closest structural swap for RSABSSA, §2) — most likely a lattice round-optimal
scheme (20 KB class) or VOLEitH-from-MAYO (7.5 KB) if a usable implementation emerges.
Measure: token size in the export file, presentation-envelope size, issuance/redemption
latency, and — critically — that unlinkability tests still pass. This validates that the
abstraction can carry a PQ primitive without protocol changes (consistent with the
"upgrade the implementation, not the protocol" convention).

**Stage 3 — hybrid pilot:** dual classical+PQ tokens (§4.1) in a test epoch, mirroring
the trust-layer hybrid, before any classical retirement.

**Honest note on production readiness:** as of **2026-08**, verified by the searches
behind this survey, **no production-ready, independently reviewed PQ anonymous-credential
or PQ blind-signature library exists.** The best artifacts are research implementations
tied to individual papers (CCS 2024 lattice AC; Cloudflare's zkDilithium prototypes;
VOLEitH proofs of concept). This mirrors exactly the situation BlindAge already
documented for RFC 9474 in 2026-07 (no maintained conformant library → from-spec with
vector gating), only worse: there is not even a stable spec to conform to.
Source: [Cloudflare blog](https://blog.cloudflare.com/pq-anonymous-credentials/),
[decisions.md, 2026-07-22](../decisions.md).

---

## 6. Constitution alignment — rule 4 ("reviewed crypto libraries only")

CLAUDE.md rule 4: *"Reviewed crypto libraries only — never hand-roll a primitive."* This
rule is the single hardest constraint on PQ-AC adoption, and it is worth stating plainly:

- **The gap between paper and reviewed code is the blocker, not the math.** Every PQ-AC/
  blind-sig construction in §2–§3 exists as a paper plus, at best, a research prototype.
  Rule 4 forbids shipping any of them in their current form — not because they are
  wrong, but because they are unreviewed.
- **The building blocks *are* reviewed.** ML-KEM/ML-DSA/SLH-DSA/FN-DSA are NIST-
  standardized with audited implementations. A PQ credential core that is *only* a ZK
  proof composed over these standardized signatures keeps the **primitive** reviewed and
  makes only the **protocol/ZK-circuit layer** new — exactly the split BlindAge already
  accepted for RSABSSA (reviewed RSA/PSS via `cryptography`; hand-written, vector-gated
  protocol arithmetic). Generic composition (§3b) is therefore the most rule-4-friendly
  *architecture*, even though it is the heaviest.
- **A vector-gating discipline is the bridge.** When BlindAge eventually implements a PQ
  primitive from spec, it should reuse the RFC 9474 playbook: implement from an
  authoritative spec, gate byte-for-byte against official test vectors, isolate the
  primitive behind the crypto abstraction, and flag any non-constant-time arithmetic as
  dev-only with a pre-deployment native-library gate. The precedent is in
  [decisions.md, 2026-07-22](../decisions.md).
- **Do not adopt a PQ-AC primitive into production until a maintained, audited
  implementation exists** — matching the standing production gate already recorded for
  RSABSSA (replace pure-Python with an audited native crate before deployment).

**Net:** rule 4 doesn't just permit the watch-and-stage recommendation of §5 — it
*requires* it. Shipping today's PQ-AC research code would violate rule 4; the honest path
is to prototype behind the abstraction, keep primitives standardized where possible, and
wait for reviewed implementations before any production adoption.

---

## Sources (primary)

- Cloudflare, "Policy, privacy and post-quantum: anonymous credentials for everyone" (2025) — https://blog.cloudflare.com/pq-anonymous-credentials/
- Argo, Güneysu, Jeudy, Land, "Practical Post-Quantum Signatures for Privacy," CCS 2024 — https://eprint.iacr.org/2024/131.pdf
- Jeudy, Roux-Langlois, Sanders, "Lattice Signature with Efficient Protocols," CRYPTO 2023 — https://eprint.iacr.org/2022/509
- "Post-Quantum Privacy Pass via PQ Anonymous Credentials" (zkDilithium) — https://eprint.iacr.org/2023/414
- "Blinding Post-Quantum Hash-and-Sign Signatures," ePrint 2025/895 — https://eprint.iacr.org/2025/895.pdf
- "Lattice-Based Threshold Blind Signatures," ePrint 2025/1566 — https://eprint.iacr.org/2025/1566
- "Post-Quantum Traceable Anonymous Credentials from Lattices," IACR CiC 2026 — https://cic.iacr.org/p/2/4/12
- "A Gentle Introduction to Blind Signatures," arXiv 2509.02189 — https://arxiv.org/pdf/2509.02189
- QADR (HNDL retroactive de-anonymization), arXiv 2511.15272 — https://arxiv.org/pdf/2511.15272
- IETF ARC draft — https://datatracker.ietf.org/doc/draft-yun-cfrg-arc/
- NIST PQC standards (2024) — https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
- NIST "PQC: The Road Ahead," Moody 2025 — https://csrc.nist.gov/csrc/media/Presentations/2025/nist-pqc-the-road-ahead/images-media/rwcpqc-march2025-moody.pdf
- MDPI, "On Advances of Anonymous Credentials—From Traditional to Post-Quantum" (2025) — https://www.mdpi.com/2410-387X/9/1/8
