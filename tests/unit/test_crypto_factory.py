from datetime import datetime, timezone

import pytest

from blindage.crypto import (
    Ed25519TokenSigner,
    Ed25519TokenVerifier,
    MockTokenSigner,
    MockTokenVerifier,
    UnsupportedAlgorithmError,
    b64u_encode,
    generate_token_keypair,
    verifier_from_issuer_key,
)
from blindage.schemas import AgeClaim, AssuranceLevel, IssuerKey


def make_key(algorithm: str, public_key: str) -> IssuerKey:
    return IssuerKey(
        key_id="k1",
        purpose="token_signing",
        algorithm=algorithm,
        public_key=public_key,
        claim=AgeClaim.AGE_OVER_18,
        assurance_level=AssuranceLevel.AAL2,
        epoch="2026-Q3",
        valid_from=datetime(2026, 7, 1, tzinfo=timezone.utc),
        valid_until=datetime(2026, 10, 1, tzinfo=timezone.utc),
    )


def test_dispatches_ed25519():
    priv, pub = generate_token_keypair()
    verifier = verifier_from_issuer_key(make_key("ed25519", pub))
    assert isinstance(verifier, Ed25519TokenVerifier)
    sig = Ed25519TokenSigner("k1", priv).sign(b"m")
    assert verifier.verify(b"m", sig)


def test_dispatches_mock():
    secret = b"s" * 32
    verifier = verifier_from_issuer_key(
        make_key("mock-hmac-sha256", b64u_encode(secret))
    )
    assert isinstance(verifier, MockTokenVerifier)
    assert verifier.verify(b"m", MockTokenSigner("k1", secret).sign(b"m"))


def test_unknown_algorithm_raises_unsupported():
    with pytest.raises(UnsupportedAlgorithmError):
        verifier_from_issuer_key(make_key("rsa-4096", "cGs"))
    assert issubclass(UnsupportedAlgorithmError, ValueError)
