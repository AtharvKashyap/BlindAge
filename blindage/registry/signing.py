import binascii
from enum import Enum

from cryptography.hazmat.primitives.asymmetric import mldsa
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
    try:
        public = Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64))
        public.verify(b64u_decode(signature_b64), canonical_json_bytes(registry_dict))
        return True
    except (InvalidSignature, binascii.Error, ValueError):
        return False


class HybridVerificationError(Exception):
    """A hybrid policy check failed. store.py re-raises as RegistryError."""


class RegistryPolicy(str, Enum):
    CLASSICAL_ONLY = "classical-only"
    HYBRID_PREFERRED = "hybrid-preferred"
    HYBRID_REQUIRED = "hybrid-required"


def generate_mldsa_keypair() -> tuple[str, str]:
    private = mldsa.MLDSA65PrivateKey.generate()
    seed = private.private_bytes_raw()  # 32-byte seed form (probed; pairs with from_seed_bytes)
    public = private.public_key().public_bytes_raw()
    return b64u_encode(seed), b64u_encode(public)


def sign_registry_mldsa(registry_dict: dict, seed_b64u: str) -> str:
    private = mldsa.MLDSA65PrivateKey.from_seed_bytes(b64u_decode(seed_b64u))
    return b64u_encode(private.sign(canonical_json_bytes(registry_dict)))


def verify_registry_mldsa(
    registry_dict: dict, signature_b64: str, public_key_b64: str
) -> bool:
    try:
        public = mldsa.MLDSA65PublicKey.from_public_bytes(b64u_decode(public_key_b64))
        public.verify(b64u_decode(signature_b64), canonical_json_bytes(registry_dict))
        return True
    except Exception:  # InvalidSignature, decode errors, size errors: fail closed
        return False


def verify_registry_hybrid(
    registry_dict: dict,
    ed_signature_b64: str,
    ed_public_key_b64: str,
    mldsa_signature_b64: str | None,
    mldsa_public_key_b64: str | None,
    policy: RegistryPolicy,
) -> None:
    """Enforce the Phase 11 hybrid semantics table. Raises on every deny row.

    Downgrade protection: HYBRID_PREFERRED with a pinned PQ key behaves exactly
    like HYBRID_REQUIRED — 'preferred' only softens behavior for clients that
    have no PQ root key yet, so stripping the PQ signature never helps.
    """
    if not verify_registry_signature(registry_dict, ed_signature_b64, ed_public_key_b64):
        raise HybridVerificationError("Ed25519 registry signature invalid")
    if policy is RegistryPolicy.CLASSICAL_ONLY:
        return
    pq_pinned = mldsa_public_key_b64 is not None
    if policy is RegistryPolicy.HYBRID_REQUIRED and not pq_pinned:
        raise HybridVerificationError("hybrid-required but no ML-DSA root key configured")
    if not pq_pinned:  # HYBRID_PREFERRED with nothing to check
        return
    if mldsa_signature_b64 is None:
        raise HybridVerificationError(
            "ML-DSA signature missing (possible downgrade attack)"
        )
    if not verify_registry_mldsa(registry_dict, mldsa_signature_b64, mldsa_public_key_b64):
        raise HybridVerificationError("ML-DSA registry signature invalid")
