import httpx
import pytest
from fastapi.testclient import TestClient

from blindage.crypto import b64u_encode
from blindage.example_site.app import create_site
from blindage.issuer.app import create_app as create_issuer
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.storage import EnrollmentStore
from blindage.registry import TrustRegistry
from blindage.schemas import AgeClaim, AssuranceLevel, VerifierChallenge
from blindage.wallet.client import enroll, mint, build_presentation
from blindage.wallet.vault import StoredToken, VaultData

ISSUER_ID = "did:web:issuer.test"
SECRET = b"e" * 32
KEY_ID = "dev-AGE_OVER_18-AAL2-2026-Q3"


@pytest.fixture()
def issuer_http() -> httpx.Client:
    key_store = IssuerKeyStore(
        [
            {
                "key_id": KEY_ID,
                "secret_b64": b64u_encode(SECRET),
                "claim": "AGE_OVER_18",
                "assurance_level": "AAL2",
                "epoch": "2026-Q3",
                "valid_until": "2026-10-01T00:00:00Z",
            }
        ]
    )
    app = create_issuer(key_store, EnrollmentStore(":memory:"))
    # NOTE: httpx.Client(transport=httpx.ASGITransport(...)) is incompatible with the
    # installed httpx/starlette versions here (ASGITransport lacks handle_request for
    # the sync client). fastapi.testclient.TestClient wraps the same ASGI app and is
    # API-compatible with httpx.Client for the .post()/.get() calls used below.
    return TestClient(app, base_url="http://issuer.test")


@pytest.fixture()
def site() -> TestClient:
    registry = TrustRegistry.from_dict(
        {
            "version": "1.0",
            "generated_at": "2026-07-21T00:00:00Z",
            "issuers": [
                {
                    "version": "1.0",
                    "issuer_id": ISSUER_ID,
                    "legal_name": "Test Issuer",
                    "jurisdiction": "US",
                    "supported_claims": ["AGE_OVER_18"],
                    "assurance_levels": ["AAL2"],
                    "keys": [
                        {
                            "key_id": KEY_ID,
                            "purpose": "token_signing",
                            "algorithm": "mock-hmac-sha256",
                            "public_key": b64u_encode(SECRET),
                            "claim": "AGE_OVER_18",
                            "assurance_level": "AAL2",
                            "epoch": "2026-Q3",
                            "valid_from": "2026-07-01T00:00:00Z",
                            "valid_until": "2026-10-01T00:00:00Z",
                        }
                    ],
                    "status": "active",
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                }
            ],
        }
    )
    return TestClient(create_site(registry, trusted_issuer=ISSUER_ID, audience="localhost"))


def mint_vault(issuer_http: httpx.Client, count: int = 2) -> VaultData:
    eid = enroll(issuer_http, "2000-01-01")
    tokens = mint(issuer_http, eid, AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2, "2026-Q3", count)
    return VaultData(tokens=[StoredToken(token=t) for t in tokens])


def test_full_flow_allow_then_replay_reject(issuer_http, site):
    vault = mint_vault(issuer_http)

    challenge = VerifierChallenge.model_validate(site.post("/api/challenge").json())
    presentation = build_presentation(vault, challenge)
    resp = site.post("/api/redeem", json=presentation.model_dump(mode="json"))
    assert resp.status_code == 200
    assert resp.json()["decision"] == "ALLOW"

    # Replaying the exact same presentation (same token, same challenge) fails.
    resp = site.post("/api/redeem", json=presentation.model_dump(mode="json"))
    assert resp.status_code == 403

    # Same token with a FRESH challenge also fails (nonce burned).
    challenge2 = VerifierChallenge.model_validate(site.post("/api/challenge").json())
    replay = presentation.model_copy(deep=True)
    replay.domain_binding.audience = challenge2.audience
    replay.domain_binding.challenge = challenge2.challenge
    replay.domain_binding.challenge_id = challenge2.challenge_id
    resp = site.post("/api/redeem", json=replay.model_dump(mode="json"))
    assert resp.status_code == 403


def test_second_token_works_after_first_spent(issuer_http, site):
    vault = mint_vault(issuer_http, count=2)
    for _ in range(2):
        challenge = VerifierChallenge.model_validate(site.post("/api/challenge").json())
        presentation = build_presentation(vault, challenge)
        resp = site.post("/api/redeem", json=presentation.model_dump(mode="json"))
        assert resp.json().get("decision") == "ALLOW"
    assert all(t.spent for t in vault.tokens)
