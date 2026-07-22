import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from blindage.crypto import (
    RsabssaTokenVerifier,
    b64u_decode,
    b64u_encode,
    generate_blind_keypair,
)
from blindage.issuer.app import create_app
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.storage import EnrollmentStore
from blindage.schemas import (
    AgeClaim,
    AssuranceLevel,
    VerifierChallenge,
    token_message,
)
from blindage.wallet.client import WalletError, build_presentation, enroll, mint
from blindage.wallet.vault import StoredToken, VaultData


@pytest.fixture()
def http() -> TestClient:
    key_store = IssuerKeyStore(
        [
            {
                "key_id": "dev-AGE_OVER_18-AAL2-2026-Q3",
                "secret_b64": b64u_encode(b"e" * 32),
                "claim": "AGE_OVER_18",
                "assurance_level": "AAL2",
                "epoch": "2026-Q3",
                "valid_until": "2026-10-01T00:00:00Z",
            }
        ]
    )
    app = create_app(key_store, EnrollmentStore(":memory:"))
    return TestClient(app)


def make_challenge(**overrides) -> VerifierChallenge:
    now = datetime.now(timezone.utc)
    data = dict(
        challenge_id="11111111-1111-1111-1111-111111111111",
        required_claim=AgeClaim.AGE_OVER_18,
        minimum_assurance_level=AssuranceLevel.AAL2,
        audience="example.test",
        challenge="Y2hhbGxlbmdl",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    data.update(overrides)
    return VerifierChallenge(**data)


def test_enroll_and_mint_returns_verified_tokens(http):
    eid = enroll(http, "2000-01-01")
    tokens = mint(http, eid, AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2, "2026-Q3", 5)
    assert len(tokens) == 5
    assert len({t.nonce for t in tokens}) == 5  # all nonces fresh and distinct
    assert all(t.issuer_key_id == "dev-AGE_OVER_18-AAL2-2026-Q3" for t in tokens)


def test_mint_ineligible_claim_raises(http):
    eid = enroll(http, "2010-01-01")  # 16 years old
    with pytest.raises(WalletError):
        mint(http, eid, AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2, "2026-Q3", 1)


def test_build_presentation_selects_and_spends_token(http):
    eid = enroll(http, "2000-01-01")
    tokens = mint(http, eid, AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2, "2026-Q3", 2)
    data = VaultData(tokens=[StoredToken(token=t) for t in tokens])
    challenge = make_challenge()
    p = build_presentation(data, challenge)
    assert p.required_claim == AgeClaim.AGE_OVER_18
    assert p.domain_binding.audience == "example.test"
    assert p.domain_binding.challenge_id == challenge.challenge_id
    assert sum(1 for t in data.tokens if t.spent) == 1
    assert p.token.nonce in {t.token.nonce for t in data.tokens if t.spent}


def test_build_presentation_no_tokens_raises():
    with pytest.raises(WalletError, match="no unspent token"):
        build_presentation(VaultData(), make_challenge())


def test_build_presentation_expired_challenge_raises(http):
    eid = enroll(http, "2000-01-01")
    tokens = mint(http, eid, AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2, "2026-Q3", 1)
    data = VaultData(tokens=[StoredToken(token=t) for t in tokens])
    old = datetime.now(timezone.utc) - timedelta(minutes=10)
    with pytest.raises(WalletError, match="challenge expired"):
        build_presentation(
            data, make_challenge(issued_at=old, expires_at=old + timedelta(minutes=5))
        )


RSA_PRIV, RSA_PUB = generate_blind_keypair(2048)


@pytest.fixture()
def blind_http():
    key_store = IssuerKeyStore(
        [
            {
                "key_id": "dev-AGE_OVER_18-AAL2-2026-Q4",
                "algorithm": "rsabssa-sha384-pss-deterministic",
                "private_key_b64": RSA_PRIV,
                "public_key_b64": RSA_PUB,
                "claim": "AGE_OVER_18",
                "assurance_level": "AAL2",
                "epoch": "2026-Q4",
                "valid_until": "2027-01-01T00:00:00Z",
            }
        ]
    )
    app = create_app(key_store, EnrollmentStore(":memory:"))
    return TestClient(app)


def test_blind_mint_produces_verifiable_tokens(blind_http):
    eid = enroll(blind_http, "2000-01-01")
    tokens = mint(blind_http, eid, AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2, "2026-Q4", 3)
    assert len(tokens) == 3
    verifier = RsabssaTokenVerifier("k", RSA_PUB)
    for t in tokens:
        assert verifier.verify(token_message(t.nonce), b64u_decode(t.signature))
    assert len({t.nonce for t in tokens}) == 3


def test_blind_mint_request_never_contains_nonces(blind_http, monkeypatch):
    eid = enroll(blind_http, "2000-01-01")
    captured: list[str] = []
    original_post = blind_http.post

    def spying_post(url, **kwargs):
        if "json" in kwargs:
            captured.append(json.dumps(kwargs["json"]))
        return original_post(url, **kwargs)

    monkeypatch.setattr(blind_http, "post", spying_post)
    tokens = mint(blind_http, eid, AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2, "2026-Q4", 2)
    traffic = " ".join(captured)
    for t in tokens:
        assert t.nonce not in traffic
        assert t.signature not in traffic
    assert '"nonces"' not in traffic


def test_blind_mint_unknown_tuple_raises(blind_http):
    eid = enroll(blind_http, "2000-01-01")
    with pytest.raises(WalletError, match="no issuer key"):
        mint(blind_http, eid, AgeClaim.AGE_OVER_21, AssuranceLevel.AAL2, "2026-Q4", 1)
