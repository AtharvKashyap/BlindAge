from blindage.crypto import (
    ED25519_ALGORITHM,
    Ed25519TokenSigner,
    Ed25519TokenVerifier,
    TokenSigner,
    TokenVerifier,
    generate_token_keypair,
)


def test_keypair_generation_shapes():
    priv, pub = generate_token_keypair()
    assert priv != pub
    assert "=" not in priv and "=" not in pub


def test_sign_verify_round_trip():
    priv, pub = generate_token_keypair()
    signer = Ed25519TokenSigner(key_id="k1", private_key_b64=priv)
    verifier = Ed25519TokenVerifier(key_id="k1", public_key_b64=pub)
    sig = signer.sign(b"nonce-bytes")
    assert len(sig) == 64
    assert verifier.verify(b"nonce-bytes", sig)


def test_verify_rejects_wrong_message_wrong_key_and_garbage():
    priv, pub = generate_token_keypair()
    _, other_pub = generate_token_keypair()
    signer = Ed25519TokenSigner(key_id="k1", private_key_b64=priv)
    sig = signer.sign(b"m")
    assert not Ed25519TokenVerifier("k1", pub).verify(b"other", sig)
    assert not Ed25519TokenVerifier("k1", other_pub).verify(b"m", sig)
    assert not Ed25519TokenVerifier("k1", pub).verify(b"m", b"garbage")
    assert not Ed25519TokenVerifier("k1", pub).verify(b"m", b"")


def test_signing_is_deterministic():
    # Ed25519 (RFC 8032) is deterministic — same key + message => same signature.
    priv, _ = generate_token_keypair()
    signer = Ed25519TokenSigner(key_id="k1", private_key_b64=priv)
    assert signer.sign(b"m") == signer.sign(b"m")


def test_algorithm_label_and_protocol_conformance():
    priv, pub = generate_token_keypair()
    signer = Ed25519TokenSigner(key_id="k1", private_key_b64=priv)
    verifier = Ed25519TokenVerifier(key_id="k1", public_key_b64=pub)
    assert signer.algorithm == ED25519_ALGORITHM == verifier.algorithm
    assert isinstance(signer, TokenSigner)
    assert isinstance(verifier, TokenVerifier)
