import json
from pathlib import Path

from blindage.crypto import Ed25519TokenSigner, Ed25519TokenVerifier, b64u_decode
from blindage.schemas import token_message

VECTORS = json.loads(
    (Path(__file__).resolve().parents[1] / "vectors" / "ed25519_token_vectors.json").read_text()
)


def test_vectors_resign_identically():
    signer = Ed25519TokenSigner("vector-key", VECTORS["private_key_b64"])
    for case in VECTORS["cases"]:
        assert signer.sign(token_message(case["nonce"])) == b64u_decode(
            case["signature_b64"]
        )


def test_vectors_verify_with_public_key():
    verifier = Ed25519TokenVerifier("vector-key", VECTORS["public_key_b64"])
    for case in VECTORS["cases"]:
        assert verifier.verify(
            token_message(case["nonce"]), b64u_decode(case["signature_b64"])
        )


def test_vectors_are_distinct():
    signatures = [c["signature_b64"] for c in VECTORS["cases"]]
    assert len(set(signatures)) == len(signatures) == 3
