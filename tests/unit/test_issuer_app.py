from datetime import date

import pytest
from fastapi.testclient import TestClient

from blindage.crypto import MockTokenVerifier, b64u_decode, b64u_encode
from blindage.issuer.app import create_app
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.storage import EnrollmentStore
from blindage.schemas import token_message

SECRET_18 = b"e" * 32
SECRET_21 = b"t" * 32


@pytest.fixture()
def client() -> TestClient:
    key_store = IssuerKeyStore(
        [
            {
                "key_id": "dev-AGE_OVER_18-AAL2-2026-Q3",
                "secret_b64": b64u_encode(SECRET_18),
                "claim": "AGE_OVER_18",
                "assurance_level": "AAL2",
                "epoch": "2026-Q3",
                "valid_until": "2026-10-01T00:00:00Z",
            },
            {
                "key_id": "dev-AGE_OVER_21-AAL2-2026-Q3",
                "secret_b64": b64u_encode(SECRET_21),
                "claim": "AGE_OVER_21",
                "assurance_level": "AAL2",
                "epoch": "2026-Q3",
                "valid_until": "2026-10-01T00:00:00Z",
            },
        ]
    )
    app = create_app(key_store, EnrollmentStore(":memory:"))
    return TestClient(app)


def enroll(client: TestClient, dob: str) -> str:
    resp = client.post("/v1/enrollment", json={"date_of_birth": dob})
    assert resp.status_code == 201
    return resp.json()["enrollment_id"]


def issue_body(enrollment_id: str, claim: str = "AGE_OVER_18", nonces=None) -> dict:
    return {
        "version": "1.0",
        "enrollment_id": enrollment_id,
        "claim": claim,
        "assurance_level": "AAL2",
        "epoch": "2026-Q3",
        "nonces": nonces if nonces is not None else ["bm9uY2Ux", "bm9uY2Uy"],
    }


def test_enrollment_returns_eligible_claims(client):
    resp = client.post("/v1/enrollment", json={"date_of_birth": "2000-01-01"})
    assert resp.status_code == 201
    assert "AGE_OVER_21" in resp.json()["eligible_claims"]


def test_issue_signs_with_partitioned_key(client):
    eid = enroll(client, "2000-01-01")
    resp = client.post("/v1/tokens/issue", json=issue_body(eid))
    assert resp.status_code == 200
    body = resp.json()
    assert body["issuer_key_id"] == "dev-AGE_OVER_18-AAL2-2026-Q3"
    verifier = MockTokenVerifier(key_id=body["issuer_key_id"], secret=SECRET_18)
    for nonce, sig in zip(["bm9uY2Ux", "bm9uY2Uy"], body["signatures"]):
        assert verifier.verify(token_message(nonce), b64u_decode(sig))


def test_ineligible_claim_is_refused(client):
    # 19-year-old (DOB 2007) must NOT get an AGE_OVER_21 signature.
    eid = enroll(client, "2007-07-21")
    resp = client.post("/v1/tokens/issue", json=issue_body(eid, claim="AGE_OVER_21"))
    assert resp.status_code == 403


def test_unknown_enrollment_404(client):
    resp = client.post("/v1/tokens/issue", json=issue_body("no-such-id"))
    assert resp.status_code == 404


def test_missing_key_tuple_409(client):
    eid = enroll(client, "2000-01-01")
    body = issue_body(eid)
    body["epoch"] = "2030-Q1"  # no key configured for this epoch
    resp = client.post("/v1/tokens/issue", json=body)
    assert resp.status_code == 409


def test_batch_limit_enforced(client):
    eid = enroll(client, "2000-01-01")
    resp = client.post("/v1/tokens/issue", json=issue_body(eid, nonces=["n"] * 101))
    assert resp.status_code == 422


def test_well_known_metadata_and_health(client):
    meta = client.get("/.well-known/blindage-issuer.json")
    assert meta.status_code == 200
    assert meta.json()["issuer_id"] == "did:web:issuer.test"
    key_ids = {k["key_id"] for k in meta.json()["keys"]}
    assert "dev-AGE_OVER_18-AAL2-2026-Q3" in key_ids
    assert client.get("/health").json() == {"status": "ok"}
