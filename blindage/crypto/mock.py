"""INSECURE mock signing for Phase 1 ONLY.

HMAC-SHA256 with a shared secret. It is symmetric (the 'public key' IS the
secret), provides no blindness, and lets the issuer see and link every token
value. This is the documented Phase 1 privacy gap that Phase 3 (RFC 9474
blind signatures) closes. Never use outside local development and tests.
"""
import hashlib
import hmac

from blindage.crypto.interface import b64u_decode

MOCK_ALGORITHM = "mock-hmac-sha256"


class MockTokenSigner:
    algorithm = MOCK_ALGORITHM

    def __init__(self, key_id: str, secret: bytes) -> None:
        self.key_id = key_id
        self._secret = secret

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self._secret, message, hashlib.sha256).digest()


class MockTokenVerifier:
    algorithm = MOCK_ALGORITHM

    def __init__(self, key_id: str, secret: bytes) -> None:
        self.key_id = key_id
        self._secret = secret

    def verify(self, message: bytes, signature: bytes) -> bool:
        expected = hmac.new(self._secret, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


def mock_verifier_from_public_key(key_id: str, public_key_b64: str) -> MockTokenVerifier:
    # Mock mode only: the registry 'public_key' field carries the b64url secret.
    return MockTokenVerifier(key_id=key_id, secret=b64u_decode(public_key_b64))
