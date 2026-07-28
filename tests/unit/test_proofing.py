import time
from datetime import date, datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from blindage.issuer.proofing import (
    ProofingError, ProofingSessionStore, code_challenge_s256, validate_id_token,
)

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True) | {
    "kid": "k1", "use": "sig", "alg": "RS256",
}
JWKS = {"keys": [JWK]}
ISS, AUD, NONCE = "http://idp.test", "blindage-issuer", "n-123"


def make_token(overrides=None, *, key=PEM, alg="RS256", kid="k1"):
    claims = {
        "iss": ISS, "sub": "s-1", "aud": AUD, "nonce": NONCE, "birthdate": "2000-01-01",
        "iat": datetime.now(timezone.utc), "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    claims.update(overrides or {})
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def test_pkce_challenge_matches_rfc7636_vector():
    # RFC 7636 Appendix B official test vector.
    assert code_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == \
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_session_store_is_single_use_and_expires():
    store = ProofingSessionStore(ttl_seconds=600)
    s = store.create(now=1000.0)
    assert len(s.state) >= 32 and len(s.verifier) >= 43
    assert store.consume(s.state, now=1100.0) is not None
    assert store.consume(s.state, now=1100.0) is None      # single-use
    s2 = store.create(now=1000.0)
    assert store.consume(s2.state, now=1601.0) is None     # expired
    assert store.consume("unknown", now=1000.0) is None


def test_valid_token_yields_birthdate():
    assert validate_id_token(make_token(), JWKS, issuer=ISS, audience=AUD, nonce=NONCE) \
        == date(2000, 1, 1)


@pytest.mark.parametrize("bad", [
    make_token({"iss": "http://evil.test"}),
    make_token({"aud": "someone-else"}),
    make_token({"exp": datetime.now(timezone.utc) - timedelta(minutes=1)}),
    make_token({"nonce": "wrong"}),
    make_token({"birthdate": None}),
    make_token({"birthdate": "not-a-date"}),
    make_token(kid="unknown-kid"),
])
def test_defective_tokens_rejected(bad):
    with pytest.raises(ProofingError):
        validate_id_token(bad, JWKS, issuer=ISS, audience=AUD, nonce=NONCE)


def test_hs256_and_wrong_key_rejected():
    hs = jwt.encode({"iss": ISS, "aud": AUD}, "secret", algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(ProofingError):
        validate_id_token(hs, JWKS, issuer=ISS, audience=AUD, nonce=NONCE)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(ProofingError):
        validate_id_token(
            make_token(key=other_pem), JWKS, issuer=ISS, audience=AUD, nonce=NONCE
        )
