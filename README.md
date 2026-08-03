# BlindAge

> Prove that you are old enough without proving who you are.

BlindAge is a privacy-preserving age-verification system for the web.

A trusted issuer verifies a user’s age once and issues anonymous credentials. Websites learn only whether the user meets a threshold such as `AGE_OVER_18`—not their name, birthdate, government ID, or identity-provider account.

The issuer does not learn where credentials are used, and websites do not receive a reusable identity.

---

## Why BlindAge

Most age-verification systems require users to repeatedly disclose sensitive identity information to websites or third-party verification companies.

BlindAge separates identity verification from credential presentation:

```text
Identity provider verifies age
            ↓
Issuer grants age credential
            ↓
User stores credential
            ↓
Website receives only AGE_OVER_18 = true
```

The goal is not perfect age enforcement.

The goal is to avoid turning every age-gated website into an identity checkpoint.

---

## Credential Modes

BlindAge supports two credential models.

### Blind Tokens

Single-use anonymous tokens based on RFC 9474 RSA blind signatures.

The wallet blinds token messages before sending them to the issuer. The issuer signs values it cannot read, so it cannot later link issuance to redemption.

```text
Wallet → blinded token → Issuer
Wallet ← blind signature ← Issuer

Wallet unblinds token
Website verifies token
Issuer is never contacted
```

Properties:

- blind issuance,
- unlinkable redemption,
- single-use replay protection,
- issuer cannot identify the final token.

### Selective-Disclosure Credentials

Reusable credentials based on BBS signatures.

The issuer signs a credential containing multiple age claims. The wallet later produces fresh randomized proofs that reveal only the requested threshold.

This mode is reusable, but issuance is not blind. The issuer sees the claims it signs.

See [`docs/vc-vs-tokens.md`](docs/vc-vs-tokens.md) for the full comparison.

---

## Browser Extension

BlindAge includes a Chrome Manifest V3 extension that:

- enrolls users with an approved issuer,
- mints blind tokens in-browser,
- stores anonymous credentials,
- detects supported age gates,
- asks for consent,
- presents one credential,
- rejects untrusted issuers,
- and automatically replenishes low token inventory.

Identity information never enters the extension.

Enrollment happens on the issuer’s own page through either:

- `TestDobProofing` for development, or
- OIDC Authorization Code + PKCE for real identity-provider integration.

The extension receives only an opaque enrollment ID.

---

## Trust Registry

BlindAge clients trust only registry-approved issuers and signing keys.

The registry is signed over canonical JSON and verified locally.

Clients fail closed when:

```text
Registry missing        → deny
Signature invalid       → deny
Registry rollback       → deny
Issuer unknown          → deny
Signing key mismatch    → deny
```

The extension never accepts a signing key supplied by the credential itself.

---

## Blockchain Anchor

A signed registry can still be frozen at an older valid version.

BlindAge includes a Solidity `RegistryAnchor` contract that stores only:

```text
keccak256(registry.json)
version
generated_at
updated_at
```

It stores no identities, tokens, redemptions, domains, or user data.

Registry updates must pass through an OpenZeppelin timelock, and the contract rejects version or timestamp rollback.

The current implementation runs only on local Anvil. It is not deployed to a public network.

---

## Hybrid Post-Quantum Trust

The registry can be signed with both:

```text
Ed25519
+
ML-DSA-65
```

Once a client has a pinned ML-DSA root key, the post-quantum signature becomes mandatory.

Removing it does not trigger a fallback to classical verification.

BlindAge does not claim to be fully quantum-safe. Only the long-lived registry trust root currently uses hybrid signatures.

---

## Transparency and Governance

The blockchain event history acts as the transparency log.

BlindAge includes:

- a stateless server that exposes ordered anchor updates,
- an independent auditor that reconstructs history from the chain,
- mirror-to-chain hash verification,
- rollback detection,
- and on-chain separation of proposer and executor roles.

The auditor fails with a non-zero exit code when the chain, mirror, or history cannot be verified.

---

## Architecture

```text
blindage/
├── crypto/          # RSABSSA, BBS, ML-DSA
├── issuer/          # Enrollment and credential issuance
├── wallet/          # CLI wallet and credential storage
├── verifier/        # Token and VC verification
├── registry/        # Signed trust registry and anchor client
└── transparency/    # Log server and independent auditor

extension/           # Chrome extension
registry/contracts/  # RegistryAnchor Solidity contract
docs/                # Decisions, roadmap, governance, comparisons
scripts/             # Demos and CI
tests/               # Crypto, privacy, registry, chain, governance
```

---

## Quick Start

```bash
git clone https://github.com/AtharvKashyap/BlindAge.git
cd BlindAge

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest
./scripts/run_protocol_demo.sh
```

The protocol demo runs:

```text
enroll → mint → unblind → prove → redeem → reject replay
```

---

## Browser Demo

```bash
./scripts/run_browser_demo.sh
```

This starts:

| Service | Address |
|---|---|
| Development IdP | `localhost:8600` |
| Issuer | `localhost:8400` |
| Protected site | `localhost:8500` |
| Registry mirror | `localhost:8700` |

Load `extension/` through `chrome://extensions`, configure the printed registry root key, enroll, and open the protected demo site.

The bundled identity provider and DOB proofing flow are simulations. They provide no real identity assurance.

---

## Testing and Evidence

BlindAge tests its privacy and trust claims directly.

The suite covers:

- RFC 9474 official vectors,
- CFRG BBS fixtures,
- blind issuance,
- token replay rejection,
- unlinkable VC presentations,
- registry signature validation,
- rollback rejection,
- issuer and key matching,
- post-quantum downgrade protection,
- anchor privacy,
- timelock enforcement,
- governance separation of duties,
- and chain-to-mirror transparency auditing.

Run everything with:

```bash
./scripts/ci.sh
```

---

## Production Status

BlindAge is a working research prototype.

**Do not deploy it in production.**

Major remaining gates include:

- audited constant-time cryptography,
- replacing Python big integers and JavaScript `BigInt`,
- production identity proofing,
- secure issuer key custody,
- OIDC key-rotation and `azp` validation,
- secure extension trust-anchor distribution,
- smart-contract review,
- independent privacy and security audits,
- and legal evaluation.

BlindAge has demonstrated the architecture.

It has not yet earned production trust.

---

## Documentation

- [`docs/roadmap.md`](docs/roadmap.md)
- [`docs/decisions.md`](docs/decisions.md)
- [`docs/vc-vs-tokens.md`](docs/vc-vs-tokens.md)
- [`docs/governance-ceremony.md`](docs/governance-ceremony.md)

---

## Principle

A website asking whether someone is over 18 does not need their passport.

A verification provider confirming someone’s age does not need their browsing history.

BlindAge proves the rule is satisfied without making identity the price of participation.
