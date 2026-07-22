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
3. **Blind signatures (RFC 9474 / RSABSSA)** [MOD-2] — issuance↔redemption unlinkability;
   the xfail unlinkability test must flip to passing (strict marker forces its removal).
4. **Browser extension** — TypeScript + Vite; consent UI, origin validation, token
   inventory.
5. **Signed registry distribution** — download, root-signature verification, caching,
   rollback detection, revocation handling (Phase 1 shipped only the local static file).
6. **Blockchain registry** — issuer registry / revocation-root / transparency contracts,
   timelocked governance, mirrors. User data stays entirely off-chain.
7. **Selective-disclosure verifiable credentials** — reusable VC mode, randomized
   presentations, no stable credential IDs.
8. **Hybrid post-quantum signatures** — ML-DSA + Ed25519 on the trust layer, downgrade
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
registry/offchain/           # Phase 5 (registry.json + sig, mirror, validator)
registry/contracts/          # Phase 6 (IssuerRegistry, RevocationRoots, Transparency)
transparency/                # Phase 6 (log server + auditor)
verifier/sdk/node/           # Phase 4-5 (Node verifier SDK)
wallet/mobile/               # later
physical_token_demo/         # optional low-assurance demo module (clearly labeled)
```

## Deferred follow-ups from Phase 1 reviews

- Decide consciously whether a claim hierarchy (over-21 satisfies over-18) is wanted;
  Phase 1 uses exact-match fail-closed semantics.
- Verifier decision flags on early deny are cosmetically misleading (`expired`/`revoked`
  defaults); consider tri-state.
- Multi-process deployments need a shared challenge store + shared replay cache (Phase 1
  ChallengeManager is in-memory, single-process).
- Cleanups: vault cleanup-branch test, PII test value-level (not just key-name) checks.
