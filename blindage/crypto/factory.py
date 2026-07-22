from blindage.crypto.ed25519 import ED25519_ALGORITHM, Ed25519TokenVerifier
from blindage.crypto.interface import TokenVerifier
from blindage.crypto.mock import MOCK_ALGORITHM, mock_verifier_from_public_key
from blindage.schemas import IssuerKey


class UnsupportedAlgorithmError(ValueError):
    pass


def verifier_from_issuer_key(key: IssuerKey) -> TokenVerifier:
    if key.algorithm == ED25519_ALGORITHM:
        return Ed25519TokenVerifier(key.key_id, key.public_key)
    if key.algorithm == MOCK_ALGORITHM:
        return mock_verifier_from_public_key(key.key_id, key.public_key)
    raise UnsupportedAlgorithmError(f"unsupported token algorithm: {key.algorithm!r}")
