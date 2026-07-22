from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from blindage.canonical import canonical_json_bytes
from blindage.crypto import b64u_decode, b64u_encode


def generate_root_keypair() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    priv_raw = private.private_bytes_raw()
    pub_raw = private.public_key().public_bytes_raw()
    return b64u_encode(priv_raw), b64u_encode(pub_raw)


def sign_registry(registry_dict: dict, private_key_b64: str) -> str:
    private = Ed25519PrivateKey.from_private_bytes(b64u_decode(private_key_b64))
    return b64u_encode(private.sign(canonical_json_bytes(registry_dict)))


def verify_registry_signature(
    registry_dict: dict, signature_b64: str, public_key_b64: str
) -> bool:
    public = Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64))
    try:
        public.verify(b64u_decode(signature_b64), canonical_json_bytes(registry_dict))
        return True
    except InvalidSignature:
        return False
