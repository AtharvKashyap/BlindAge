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
    print("vectors written")


if __name__ == "__main__":
    main()
