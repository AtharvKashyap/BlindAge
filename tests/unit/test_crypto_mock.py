from blindage.crypto import (
    MOCK_ALGORITHM,
    MockTokenSigner,
    MockTokenVerifier,
    b64u_decode,
    b64u_encode,
    mock_verifier_from_public_key,
)


def test_b64u_round_trip():
    raw = bytes(range(32))
    assert b64u_decode(b64u_encode(raw)) == raw
    assert "=" not in b64u_encode(raw)


def test_sign_verify_round_trip():
    signer = MockTokenSigner(key_id="k1", secret=b"s" * 32)
    verifier = MockTokenVerifier(key_id="k1", secret=b"s" * 32)
    sig = signer.sign(b"nonce-bytes")
    assert verifier.verify(b"nonce-bytes", sig)


def test_verify_rejects_wrong_message_and_wrong_key():
    signer = MockTokenSigner(key_id="k1", secret=b"s" * 32)
    sig = signer.sign(b"nonce-bytes")
    assert not MockTokenVerifier(key_id="k1", secret=b"s" * 32).verify(b"other", sig)
    assert not MockTokenVerifier(key_id="k1", secret=b"x" * 32).verify(b"nonce-bytes", sig)


def test_algorithm_label():
    assert MockTokenSigner(key_id="k1", secret=b"s" * 32).algorithm == MOCK_ALGORITHM


def test_verifier_from_registry_public_key_field():
    secret = b"q" * 32
    signer = MockTokenSigner(key_id="k1", secret=secret)
    verifier = mock_verifier_from_public_key("k1", b64u_encode(secret))
    assert verifier.verify(b"m", signer.sign(b"m"))
