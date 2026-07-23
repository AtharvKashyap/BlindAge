# BlindAge Roadmap and Target Project Tree

Phases (spec §14, `docs/superpowers/specs/2026-07-21-blindage-design.md`):

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
**Everyday-user track** (design: `docs/superpowers/specs/2026-07-22-everyday-user-design.md`).
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
7. **Real identity-proofing adapter** — OIDC/mDL age check on the issuer replacing
   `--test-dob`; enrollment persistence so top-up needs no re-proof.
8. **Registry-sourced issuer trust + inventory/auto-top-up** — the extension lists only
   registry-approved issuers (absorbs the former "signed registry distribution": download,
   root-signature verification, caching, rollback detection, revocation) and auto-mints
   when low.

**Trust/hardening track** (unchanged, follows the everyday-user track):
- **Blockchain registry** — issuer registry / revocation-root / transparency contracts,
   timelocked governance, mirrors. User data stays entirely off-chain.
- **Selective-disclosure verifiable credentials** — reusable VC mode, randomized
   presentations, no stable credential IDs.
- **Hybrid post-quantum signatures** — ML-DSA + Ed25519 on the trust layer, downgrade
   protection.
- **Research** — ZK age-comparison proofs; PQ anonymous credentials.

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
