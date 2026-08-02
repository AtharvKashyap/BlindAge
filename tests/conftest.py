import pytest
from fastapi.testclient import TestClient

from blindage.crypto import generate_blind_keypair
from blindage.crypto.bbs import generate_bbs_keypair
from blindage.example_site.app import create_site
from blindage.issuer.app import create_app as create_issuer
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.storage import EnrollmentStore
from blindage.registry import TrustRegistry

ISSUER_ID = "did:web:issuer.test"
DEV_KEY_18 = "dev-AGE_OVER_18-AAL2-2026-Q3"
DEV_VC_KEY = "dev-vc-AAL2-2026-Q3"
DEV_RSA_PRIV, DEV_RSA_PUB = generate_blind_keypair(2048)
DEV_VC_PRIV, DEV_VC_PUB = generate_bbs_keypair()


def dev_key_entries() -> list[dict]:
    return [
        {
            "key_id": DEV_KEY_18,
            "algorithm": "rsabssa-sha384-pss-deterministic",
            "purpose": "token_signing",
            "private_key_b64": DEV_RSA_PRIV,
            "public_key_b64": DEV_RSA_PUB,
            "claim": "AGE_OVER_18",
            "assurance_level": "AAL2",
            "epoch": "2026-Q3",
            "valid_until": "2026-10-01T00:00:00Z",
        },
        {
            "key_id": DEV_VC_KEY,
            "algorithm": "bbs-bls12381-sha256",
            "purpose": "vc_signing",
            "private_key_b64": DEV_VC_PRIV,
            "public_key_b64": DEV_VC_PUB,
            "assurance_level": "AAL2",
            "epoch": "2026-Q3",
            "valid_until": "2026-10-01T00:00:00Z",
        },
    ]


def dev_issuer_entry() -> dict:
    return {
        "version": "1.0",
        "issuer_id": ISSUER_ID,
        "legal_name": "Test Issuer",
        "jurisdiction": "US",
        "endpoint": "http://localhost:8400",
        "supported_claims": ["AGE_OVER_18"],
        "assurance_levels": ["AAL2"],
        "keys": [
            {
                "key_id": DEV_KEY_18,
                "purpose": "token_signing",
                "algorithm": "rsabssa-sha384-pss-deterministic",
                "public_key": DEV_RSA_PUB,
                "claim": "AGE_OVER_18",
                "assurance_level": "AAL2",
                "epoch": "2026-Q3",
                "valid_from": "2026-07-01T00:00:00Z",
                "valid_until": "2026-10-01T00:00:00Z",
            },
            {
                "key_id": DEV_VC_KEY,
                "purpose": "vc_signing",
                "algorithm": "bbs-bls12381-sha256",
                "public_key": DEV_VC_PUB,
                "assurance_level": "AAL2",
                "epoch": "2026-Q3",
                "valid_from": "2026-07-01T00:00:00Z",
                "valid_until": "2026-10-01T00:00:00Z",
            },
        ],
        "status": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
    }


def dev_registry() -> TrustRegistry:
    return TrustRegistry.from_dict(
        {
            "version": "1.0",
            "generated_at": "2026-07-21T00:00:00Z",
            "issuers": [dev_issuer_entry()],
        }
    )


@pytest.fixture()
def issuer_http() -> TestClient:
    # NOTE: httpx.Client(transport=httpx.ASGITransport(...)) is incompatible with the
    # installed httpx/starlette versions here (ASGITransport lacks handle_request for
    # the sync client). fastapi.testclient.TestClient wraps the same ASGI app and is
    # API-compatible with httpx.Client for the .post()/.get() calls used in these
    # tests, including monkeypatching `.post` to spy on request payloads.
    app = create_issuer(IssuerKeyStore(dev_key_entries()), EnrollmentStore(":memory:"))
    return TestClient(app, base_url="http://issuer.test")


@pytest.fixture()
def site() -> TestClient:
    return TestClient(create_site(dev_registry(), trusted_issuer=ISSUER_ID, audience="localhost"))
