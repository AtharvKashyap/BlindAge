# BlindAge Roadmap and Target Project Tree

Phases:

1. **Foundation + non-crypto skeleton** — ✅ complete (mock HMAC tokens, end-to-end loop,
   signed local registry, verifier SDK, example site, CLI wallet, privacy/adversarial
   suites with 1 strict xfail documenting the linkability gap).
2. **Single-use signed random tokens** — ✅ complete (Ed25519 detached signatures behind
   the crypto abstraction, mock retained for unit tests via the algorithm factory,
   registry/well-known publish public keys only, global key-material uniqueness enforced,
   deterministic test vectors, privacy tests CI-blocking [MOD-6]). Issuer still sees
   token values; the 1 strict xfail remains until Phase 3.
3. **Blind signatures (RFC 9474 / RSABSSA)** [MOD-2] — ✅ complete (RSABSSA-SHA384-PSS-
   Deterministic implemented from-spec on `cryptography`, gated by RFC 9474 Appendix A
   official test vectors; issuance↔redemption unlinkability now holds — the former xfail
   unlinkability test is a permanent CI-blocking guarantee; verifier enforces an algorithm
   allowlist; decision log at `docs/decisions.md`).
4. **Browser extension** — ✅ complete (presentation-only Manifest V3 extension in
   vanilla JS, no build step; detects a site's age gate, consent UI, origin/expiry
   validation, token inventory; example site serves HTML age gates; `blindage export`
   feeds tokens in; extension core unit-tested under Node and wired into CI).
**Everyday-user track.**
Reprioritized to turn the demo into a self-service, extension-only tool: prove age once,
then one-click anonymous presentations everywhere.

5. **In-extension blind minting** — ✅ complete (RSABSSA-SHA384-PSS-Deterministic ported to
   pure JS [Approach A] in `extension/core/rsabssa.js` + `mint.js`, gated byte-for-byte by
   the committed RFC 9474 Appendix A vectors; a service-worker "mint" handler and a popup
   "Get tokens" card let the extension mint its own tokens — the extension does no key
   generation and no signing, only blind/unblind/verify, and POSTs only blinded messages.
   CLI `export`/import still works but is now optional. The Python-side issuer contract is
   pinned by `tests/integration/test_extension_mint_shape.py`. The JS RSABSSA is
   vector-gated but JS BigInt is not constant-time, so the WASM-of-audited-lib production
   gate is deferred — not for deployment).
6. **Self-service onboarding** — ✅ complete (extension "Get tokens" flow: choose issuer →
   enroll on the issuer's TEST-ONLY `/enroll` page → auto-mint a starter batch → store,
   all in-browser; a content-script bridge carries only the opaque enrollment id, the
   service worker validates it fail-closed [origin-checked, 10-min TTL, storage-persisted]
   and remembers enrolled issuers for no-re-proof top-up. Identity never enters the
   extension; minting still POSTs only blinded messages. The DOB form is a placeholder for
   Phase 7's real identity check).
7. **Real identity-proofing adapter** — ✅ complete (pluggable proofing on the issuer:
   `TestDobProofing` [default, DOB asserted, TEST-ONLY] or `OidcProofing`, a real OIDC
   Authorization Code + PKCE flow with fail-closed RS256-only ID-token validation [PyJWT];
   a bundled SIMULATED dev IdP [`blindage/dev_idp`, port 8600, persona login, random `sub`
   per authorization] drives the demo — it verifies nothing, so real proofing means
   pointing `OidcConfig` at a real IdP [config, not code]. Enrollment persists and expires
   after 365 days, enforced at issue [403 "enrollment expired"]; asserted enrollment is
   disabled in OIDC mode [403]; a CI-blocking privacy test pins the enrollment DB to exactly
   (enrollment_id, date_of_birth, expires_at). Demo: `BLINDAGE_PROOFING=oidc` +
   `scripts/run_browser_demo.sh`. Zero extension changes — the bridge contract is unchanged).
8. **Registry-sourced issuer trust + inventory/auto-top-up** — ✅ complete (the extension
   trusts only registry-approved issuers: it downloads a signed trust registry, verifies the
   root Ed25519 signature over canonical JSON in-browser [Web Crypto, vector-gated like the
   RFC 9474 port], rejects rollbacks, caches the result, and is fail-closed [no verified
   registry ⇒ no enroll, no mint]; enroll and mint are gated on an exact issuer + 5-field
   signing-key match, and the popup's issuer dropdown is populated only from the registry.
   Inventory auto-tops-up on popup open [mint 5 when a claim drops below 2] — popup-open only
   so minting never correlates in time with a redemption. A dev registry mirror
   [`blindage/registry_mirror`, raw passthrough] serves the signed artifact; the trust anchor
   is a manually pasted dev root key, so not for deployment — production anchoring is the
   blockchain-registry phase. Absorbs the former "signed registry distribution". This
   completes the everyday-user track).

**Trust/hardening track** (follows the everyday-user track):

9. **Blockchain registry anchor** — ✅ complete (anchor slice). An on-chain
   `RegistryAnchor` (Solidity/Foundry in `registry/contracts`) stores ONLY the
   keccak256 of the canonical registry JSON + `generated_at` + a monotonic `version`
   + `updated_at`, plus an `AnchorUpdated` event — never identity/token/redemption/
   domain data, not even hashed (rule 3, enforced by an ABI privacy test and on-chain
   strict-increase checks). Updates flow only through an OpenZeppelin
   `TimelockController`. Python primitives (`registry_keccak`, a cached `AnchorClient`),
   a deploy helper, and a timelocked publisher run on web3.py; `scripts/run_chain_demo.sh`
   drives the full flow. Opt-in parties fail closed on a mismatch — the registry mirror
   returns 503, the verifier SDK's `TrustRegistry.load(..., anchor=...)` raises
   `RegistryError` — both caching the chain read (no per-request query). This fixes the
   Phase 8 freeze/rollback limitation at the root, but **only for parties that check the
   anchor** (mirror operators, verifier SDK opt-in); the extension still trusts its
   pasted root key, unchanged this phase. **Local anvil only** — dev-short timelock delay
   (1s in tests/demo vs days in production), anvil dev key hardcoded in the demo, no
   testnet/mainnet deployment. `scripts/test_contracts.sh` (forge build/test + `tests/chain`)
   is wired into `scripts/ci.sh` and exits 0 with a notice when Foundry is absent.
   **Deferred to later trust-track work:** transparency-log server + auditor (the
   `AnchorUpdated` events are its data source), a `RevocationRoots` contract, a multi-sig
   proposer ceremony, and an extension→RPC path. Production gate: `AnchorClient` trusts
   whatever RPC endpoint it is given — add chain-id and contract-code verification before
   any non-dev deployment.
10. **Selective-disclosure verifiable credentials** — ✅ complete (a reusable VC mode
   using BBS signatures alongside the blind-token path. BBS KeyGen/Sign/Verify/ProofGen/
   ProofVerify [ciphersuite `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`] implemented from
   `draft-irtf-cfrg-bbs-signatures` on `py_ecc`'s reviewed BLS12-381 primitives, gated
   byte-for-byte by 25 official CFRG vectors [10 Sign/Verify + 15 ProofGen/ProofVerify].
   The issuer signs ONE multi-claim `AgeCredential` under a `vc_signing` key
   [`/v1/credentials/issue`]; the wallet [`vc-get`/`vc-prove`] produces unlimited fresh,
   randomized, domain-bound `VcPresentation`s each revealing only the requested threshold;
   the verifier [`verify_vc_presentation`] checks the proof against the registry-looked-up
   public key only [no value from the presentation, no live issuer callback] and enforces
   the one-time challenge; the example site adds `/protected-vc` + `/api/redeem-vc`.
   **Issuance is NOT blind** — the issuer sees the claims it signs; unlinkability is
   presentation-time only [randomized proofs sharing no correlatable bytes; hidden claims
   and the credential signature never appear], pinned CI-blocking by
   `tests/privacy/test_vc_unlinkability.py` and compared honestly in `docs/vc-vs-tokens.md`.
   Pure-Python BBS is **not constant-time** — dev-only; production gate is an audited native
   BBS impl [PyO3/WASM] behind the same interface, mirroring the RSABSSA gate. Decision log:
   `docs/decisions.md` [2026-08-02]).
11. **Hybrid post-quantum signatures** — ✅ complete (a second, post-quantum
   signature over the trust registry alongside the classical Ed25519 root. ML-DSA-65
   [FIPS 204] via `cryptography` 49 / OpenSSL — **native and reviewed**, no dev-only
   constant-time caveat on the primitive; 32-byte seed key storage; pub 1952 B / sig
   3309 B. A `RegistryPolicy` enum [`classical-only` / `hybrid-preferred` /
   `hybrid-required`] drives `verify_registry_hybrid` with **downgrade protection**:
   `hybrid-preferred` with a pinned PQ root behaves identically to `hybrid-required`,
   so stripping or breaking `registry.sig.mldsa` is always a hard deny once a client
   holds the PQ root [closes the classic downgrade hole; pinned by
   `test_downgrade_strip_attack_denied` + `test_missing_pq_file_denies_when_needed`].
   `TrustRegistry.load` gains hybrid kwargs; the generator emits `registry.sig.mldsa`
   + `root_public_key_mldsa.txt`; the mirror serves `/registry.sig.mldsa`; the browser
   demo prints both root keys. Applied to the **long-lived root of trust only** —
   the extension registry check [Ed25519/Web Crypto], issuer well-known, and token/VC
   paths stay classical, and the keccak256 on-chain anchor needs no PQ change [a hash,
   Grover-adequate at 256-bit]. **BlindAge is not a "quantum-safe system"** — only the
   registry trust layer is hybrid. Decision log: `docs/decisions.md` [2026-08-02]).
12. **Transparency + governance** — ✅ complete (the on-chain trust root made
   **externally verifiable**, plus the governance model documented. **The chain
   is the log:** a stateless, keyless transparency log server
   [`blindage/transparency/app.py`, `GET /log`] serves the `RegistryAnchor`'s
   ordered `AnchorUpdated` history — ordering + immutability come from the chain
   [block order + the on-chain monotonic-version / strictly-increasing-generated_at
   checks], public trust data only [rule 3]. It holds no state and no key and
   **fails closed [503]** on any RPC trouble rather than serve a partial/stale
   answer. An **independent auditor** [`blindage/transparency/auditor.py`, a CLI
   with cron/CI exit codes] re-derives that history from the chain and checks four
   things — head reachable, no history rollback, head == last logged event, mirror
   `registry.json` hashes to the head anchor — turning any unreachable dependency
   or inconsistency into a **FAIL with a distinct problem string** [PASS ⇒ exit 0,
   FAIL ⇒ exit 1]. Governance **separation of duties** on the OpenZeppelin
   `TimelockController` [proposer queues but cannot land; executor lands only a
   matured op but queues nothing] is proven on-chain in
   `tests/chain/test_anchor_integration.py` and documented in
   `docs/governance-ceremony.md`. `run_chain_demo.sh` wires log server + mirror +
   auditor end-to-end. **A `RevocationRoots` contract was consciously dropped** —
   registry `status` + epoch expiry cover revocation at this scale [YAGNI; revisit
   trigger = a per-token/per-batch revocation requirement], see `docs/decisions.md`
   [2026-08-02]. **Dev-scale:** `get_logs(from_block=0)` re-reads the whole history
   each run [anvil-only], and the auditor is only as independent as the RPC endpoint
   it queries — the same production gate as `AnchorClient` [chain-id + contract-code
   verification]. Decision log: `docs/decisions.md` [2026-08-02]).
- **Deferred trust-track items** (status): transparency-log server + auditor — ✅
  **done** (Phase 12); governance separation-of-duties ceremony — ✅ **done**
  (Phase 12, `docs/governance-ceremony.md`); `RevocationRoots` contract —
  **consciously dropped**, registry status + epochs cover revocation at this scale
  (see `docs/decisions.md` 2026-08-02 for the revisit trigger); **extension→RPC
  path — still open** (would also carry the pinned PQ root into the extension).
  Production gates still open: swap the pure-Python RSABSSA and BBS for audited
  native/WASM implementations, and add chain-id + contract-code verification to
  `AnchorClient` (and, for the auditor, cross-check independent RPC providers).
- **Research** (the only remaining track) — ZK age-comparison proofs; PQ anonymous
  credentials.

## Target directory tree (directories are created per phase [MOD-5])

```text
blindage/                    # Python package (Phase 1+)
  schemas/  crypto/  registry/  issuer/  wallet/  verifier/  example_site/
tests/                       # unit / integration / privacy / adversarial (Phase 1+)
scripts/                     # dev tooling + demo (Phase 1+)
config/dev/                  # generated dev keys/registry — gitignored (Phase 1+)
docs/                        # specs, plans, this roadmap; protocol.md + threat-model.md
                             # + privacy-model.md arrive with Phases 2-3
wallet/extension/            # Phase 4 (TypeScript + Vite, Manifest V3)
registry/offchain/           # registry-sourced trust phase (registry.json + sig, mirror, validator)
registry/contracts/          # blockchain-registry phase (IssuerRegistry, RevocationRoots, Transparency)
transparency/                # blockchain-registry phase (log server + auditor)
verifier/sdk/node/           # registry-sourced trust phase (Node verifier SDK)
wallet/mobile/               # later
physical_token_demo/         # optional low-assurance demo module (clearly labeled)
```

## Deferred follow-ups from Phase 1–2 reviews

- **Pre-deployment gate: swap pure-Python RSABSSA for audited native implementation**
  (PyO3/jedisct1) — see docs/decisions.md.
- Consider a domain-separation context prefix in `token_message()` before more key
  types exist (cheap defense-in-depth; not exploitable today).
- Decide consciously whether a claim hierarchy (over-21 satisfies over-18) is wanted;
  Phase 1 uses exact-match fail-closed semantics.
- Verifier decision flags on early deny are cosmetically misleading (`expired`/`revoked`
  defaults); consider tri-state.
- Multi-process deployments need a shared challenge store + shared replay cache (Phase 1
  ChallengeManager is in-memory, single-process).
- Cleanups: vault cleanup-branch test, PII test value-level (not just key-name) checks.
- Extension: in-browser blind minting now exists in pure JS (Phase 5, vector-gated); the
  remaining deferred swap is the WASM build of a reviewed/audited RFC 9474 impl (JS BigInt
  is not constant-time — production gate). TypeScript+Vite migration also still deferred.
- OIDC proofing (Phase 7) hardening before production: JWKS is cached per-process (needs
  refetch-on-`kid`-miss to survive IdP key rotation), multi-audience ID tokens are not
  `azp`-checked, and abandoned proofing sessions are never purged from the in-memory
  `ProofingSessionStore` (needs a sweep-on-create or size cap).
- The Phase 8 registry freeze/rollback limitation (a blocked mirror can pin clients on a
  stale-but-signed registry) is now mitigated **at the root** by the Phase 9 on-chain
  anchor — but only for parties that check it (mirror operators, verifier SDK opt-in). The
  extension still trusts its pasted root key (extension→RPC is deferred), and the anchor is
  local-anvil-only with no testnet/mainnet deployment. Remaining trust-track deferrals: a
  transparency-log server + auditor (consuming the `AnchorUpdated` events), a
  `RevocationRoots` contract, and a multi-sig proposer ceremony.
