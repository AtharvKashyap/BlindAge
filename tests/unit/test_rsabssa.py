import pytest

from blindage.crypto import (
    RSABSSA_ALGORITHM,
    BlindSignatureError,
    RsabssaTokenVerifier,
    TokenVerifier,
    blind,
    blind_sign,
    finalize,
    generate_blind_keypair,
)

# RSA keygen is slow — one module-level pair shared by all tests.
PRIV, PUB = generate_blind_keypair(2048)
OTHER_PRIV, OTHER_PUB = generate_blind_keypair(2048)


def run_protocol(message: bytes, priv: str = PRIV, pub: str = PUB) -> bytes:
    blinded, inv = blind(pub, message)
    blind_sig = blind_sign(priv, blinded)
    return finalize(pub, message, blind_sig, inv)


def test_full_blind_protocol_round_trip():
    sig = run_protocol(b"token-nonce-bytes")
    assert len(sig) == 256  # 2048-bit modulus
    assert RsabssaTokenVerifier("k1", PUB).verify(b"token-nonce-bytes", sig)


def test_blinded_message_differs_from_message_and_varies():
    b1, _ = blind(PUB, b"same-message")
    b2, _ = blind(PUB, b"same-message")
    assert b1 != b2  # fresh blinding factor every call
    assert b"same-message" not in b1


def test_finalize_rejects_wrong_key_signature():
    blinded, inv = blind(PUB, b"m")
    # Signing under the wrong key must fail somewhere in the chain: either
    # blind_sign rejects the blinded value as out-of-range (it was reduced mod
    # PUB's modulus, which exceeds OTHER's modulus ~half the time), or finalize
    # fails the PSS check. Both raise BlindSignatureError — wrap the whole chain.
    with pytest.raises(BlindSignatureError):
        wrong_blind_sig = blind_sign(OTHER_PRIV, blinded)
        finalize(PUB, b"m", wrong_blind_sig, inv)


def test_finalize_rejects_tampered_blind_sig():
    blinded, inv = blind(PUB, b"m")
    blind_sig = bytearray(blind_sign(PRIV, blinded))
    blind_sig[0] ^= 0xFF
    with pytest.raises(BlindSignatureError):
        finalize(PUB, b"m", bytes(blind_sig), inv)


def test_verifier_rejects_wrong_message_wrong_key_garbage():
    sig = run_protocol(b"m")
    v = RsabssaTokenVerifier("k1", PUB)
    assert not v.verify(b"other", sig)
    assert not RsabssaTokenVerifier("k1", OTHER_PUB).verify(b"m", sig)
    assert not v.verify(b"m", b"garbage")
    assert not v.verify(b"m", b"")


def test_signatures_unlinkable_to_blinded_values():
    # Run the same message through the full protocol twice, with two
    # independent blindings. RSA-PSS's random salt means the two final
    # signatures differ byte-for-byte even for an identical message, and
    # neither final signature equals the blind_sig the signer saw — so the
    # signer's view (blinded, blind_sig) cannot be trivially matched to the
    # unblinded output by simple equality. This does not itself prove
    # cryptographic unlinkability; it only asserts observable non-equality.
    blinded1, inv1 = blind(PUB, b"m")
    blind_sig1 = blind_sign(PRIV, blinded1)
    sig1 = finalize(PUB, b"m", blind_sig1, inv1)

    blinded2, inv2 = blind(PUB, b"m")
    blind_sig2 = blind_sign(PRIV, blinded2)
    sig2 = finalize(PUB, b"m", blind_sig2, inv2)

    verifier = RsabssaTokenVerifier("k1", PUB)
    assert verifier.verify(b"m", sig1)
    assert verifier.verify(b"m", sig2)
    assert sig1 != sig2
    assert sig1 != blind_sig1
    assert sig2 != blind_sig2


def test_verifier_protocol_conformance():
    v = RsabssaTokenVerifier("k1", PUB)
    assert v.algorithm == RSABSSA_ALGORITHM
    assert isinstance(v, TokenVerifier)


def test_blind_rejects_malformed_key_b64_as_blind_signature_error():
    with pytest.raises(BlindSignatureError):
        blind("!!!notb64", b"m")


def test_blind_sign_rejects_malformed_key_b64_as_blind_signature_error():
    with pytest.raises(BlindSignatureError):
        blind_sign("!!!", b"m")


def test_finalize_rejects_malformed_key_b64_as_blind_signature_error():
    with pytest.raises(BlindSignatureError):
        finalize("!!!", b"m", b"x", 1)


def test_verifier_init_rejects_malformed_key_b64_as_blind_signature_error():
    with pytest.raises(BlindSignatureError):
        RsabssaTokenVerifier("k", "!!!")


def test_verifier_verify_returns_false_not_raise_on_garbage_signature():
    v = RsabssaTokenVerifier("k1", PUB)
    assert v.verify(b"m", b"garbage") is False
