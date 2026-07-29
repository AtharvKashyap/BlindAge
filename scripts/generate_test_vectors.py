"""Regenerate tests/vectors/ed25519_token_vectors.json (deterministic vectors).

Uses a FIXED private key (all 0x42 bytes) — test-vector material only, never a
real key. Run only when the token message format changes.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json

from blindage.crypto import Ed25519TokenSigner, b64u_encode
from blindage.crypto.ed25519 import Ed25519PrivateKey
from blindage.schemas import token_message

FIXED_PRIVATE = b"\x42" * 32
NONCES = ["dGVzdC1ub25jZS0x", "dGVzdC1ub25jZS0y", "dGVzdC1ub25jZS0z"]


def main() -> None:
    private_b64 = b64u_encode(FIXED_PRIVATE)
    public_b64 = b64u_encode(
        Ed25519PrivateKey.from_private_bytes(FIXED_PRIVATE)
        .public_key()
        .public_bytes_raw()
    )
    signer = Ed25519TokenSigner("vector-key", private_b64)
    cases = [
        {"nonce": n, "signature_b64": b64u_encode(signer.sign(token_message(n)))}
        for n in NONCES
    ]
    out = Path(__file__).resolve().parents[1] / "tests" / "vectors"
    out.mkdir(parents=True, exist_ok=True)
    (out / "ed25519_token_vectors.json").write_text(
        json.dumps(
            {
                "algorithm": "ed25519",
                "private_key_b64": private_b64,
                "public_key_b64": public_b64,
                "cases": cases,
            },
            indent=2,
        )
    )
    # Registry signing vector (fixed key, deterministic) — gates the JS
    # canonical-JSON + Ed25519 port byte-for-byte.
    from blindage.canonical import canonical_json_bytes
    from blindage.registry import sign_registry

    FIXED_ROOT_PRIVATE = b"\x24" * 32
    root_priv_b64 = b64u_encode(FIXED_ROOT_PRIVATE)
    root_pub_b64 = b64u_encode(
        Ed25519PrivateKey.from_private_bytes(FIXED_ROOT_PRIVATE)
        .public_key()
        .public_bytes_raw()
    )
    registry = {
        "version": "1.0",
        "generated_at": "2026-07-29T00:00:00Z",
        "issuers": [
            {
                "version": "1.0",
                "issuer_id": "did:web:issuer.test",
                "legal_name": "Vecteur Émetteur ✓",  # non-ASCII on purpose
                "jurisdiction": "US",
                "supported_claims": ["AGE_OVER_18"],
                "assurance_levels": ["AAL2"],
                "endpoint": "http://localhost:8400",
                "keys": [
                    {
                        "key_id": "vec-key-1",
                        "purpose": "token_signing",
                        "algorithm": "rsabssa-sha384-pss-deterministic",
                        "public_key": "dmVjLXB1YmxpYw",
                        "claim": "AGE_OVER_18",
                        "assurance_level": "AAL2",
                        "epoch": "2026-Q3",
                        "valid_from": "2026-07-01T00:00:00Z",
                        "valid_until": "2026-10-01T00:00:00Z",
                    }
                ],
                "status": "active",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            }
        ],
    }
    (out / "registry_signing.json").write_text(
        json.dumps(
            {
                "registry": registry,
                "canonical_hex": canonical_json_bytes(registry).hex(),
                "root_public_key_b64": root_pub_b64,
                "signature_b64": sign_registry(registry, root_priv_b64),
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    print("vectors written")


if __name__ == "__main__":
    main()
