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
    wrong_blind_sig = blind_sign(OTHER_PRIV, blinded)
    with pytest.raises(BlindSignatureError):
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
    # What the signer sees (blinded, blind_sig) shares no bytes-substring
    # relationship with the final signature.
    blinded, inv = blind(PUB, b"m")
    blind_sig = blind_sign(PRIV, blinded)
    sig = finalize(PUB, b"m", blind_sig, inv)
    assert sig != blind_sig and sig not in blind_sig and blind_sig not in sig


def test_verifier_protocol_conformance():
    v = RsabssaTokenVerifier("k1", PUB)
    assert v.algorithm == RSABSSA_ALGORITHM
    assert isinstance(v, TokenVerifier)
