"""Ed25519 token signing (Phase 2).

Real asymmetric signatures: the issuer holds the private key; the registry
and well-known metadata publish only the public key. NOTE: issuance is still
NOT blind — the issuer sees token nonces at signing time. That documented
gap closes in Phase 3 (RFC 9474 blind signatures).
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from blindage.crypto.interface import b64u_decode, b64u_encode

ED25519_ALGORITHM = "ed25519"


def generate_token_keypair() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    return (
        b64u_encode(private.private_bytes_raw()),
        b64u_encode(private.public_key().public_bytes_raw()),
    )


class Ed25519TokenSigner:
    algorithm = ED25519_ALGORITHM

    def __init__(self, key_id: str, private_key_b64: str) -> None:
        self.key_id = key_id
        self._private = Ed25519PrivateKey.from_private_bytes(
            b64u_decode(private_key_b64)
        )

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)


class Ed25519TokenVerifier:
    algorithm = ED25519_ALGORITHM

    def __init__(self, key_id: str, public_key_b64: str) -> None:
        self.key_id = key_id
        self._public = Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64))

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public.verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False
