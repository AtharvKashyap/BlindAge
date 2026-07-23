import json
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from blindage.crypto import (
    Ed25519TokenVerifier,
    MockTokenVerifier,
    RsabssaTokenVerifier,
    b64u_decode,
    b64u_encode,
    blind,
    finalize,
    generate_blind_keypair,
    generate_token_keypair,
)
from blindage.issuer.app import create_app
from blindage.issuer.keys import IssuerKeyStore, public_material
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


def test_enrollment_store_thread_safe_under_concurrent_access():
    store = EnrollmentStore(":memory:")
    base = date(2000, 1, 1)
    dobs = [base + timedelta(days=i) for i in range(20)]

    def create_and_fetch(dob: date) -> tuple[str, date]:
        enrollment_id = store.create(dob)
        fetched = store.get_dob(enrollment_id)
        return enrollment_id, fetched

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(create_and_fetch, dobs))

    ids = [enrollment_id for enrollment_id, _ in results]
    assert len(set(ids)) == 20

    for i, (enrollment_id, fetched) in enumerate(results):
        assert fetched == dobs[i]
        assert store.get_dob(enrollment_id) == dobs[i]


ED_PRIV, ED_PUB = generate_token_keypair()


def ed25519_entry() -> dict:
    return {
        "key_id": "dev-AGE_OVER_16-AAL2-2026-Q3",
        "algorithm": "ed25519",
        "private_key_b64": ED_PRIV,
        "public_key_b64": ED_PUB,
        "claim": "AGE_OVER_16",
        "assurance_level": "AAL2",
        "epoch": "2026-Q3",
        "valid_until": "2026-10-01T00:00:00Z",
    }


@pytest.fixture()
def ed_client() -> TestClient:
    app = create_app(IssuerKeyStore([ed25519_entry()]), EnrollmentStore(":memory:"))
    return TestClient(app)


def test_ed25519_issuance_verifies_with_public_key(ed_client):
    eid = enroll(ed_client, "2000-01-01")
    body = issue_body(eid, claim="AGE_OVER_16")
    resp = ed_client.post("/v1/tokens/issue", json=body)
    assert resp.status_code == 200
    out = resp.json()
    verifier = Ed25519TokenVerifier(out["issuer_key_id"], ED_PUB)
    for nonce, sig in zip(body["nonces"], out["signatures"]):
        assert verifier.verify(token_message(nonce), b64u_decode(sig))


def test_well_known_publishes_public_key_not_private(ed_client):
    meta = ed_client.get("/.well-known/blindage-issuer.json").json()
    (key,) = meta["keys"]
    assert key["algorithm"] == "ed25519"
    assert key["public_key"] == ED_PUB
    assert ED_PRIV not in json.dumps(meta)


def test_unknown_entry_algorithm_fails_fast():
    entry = ed25519_entry()
    entry["algorithm"] = "rot13"
    with pytest.raises(ValueError, match="algorithm"):
        IssuerKeyStore([entry])


def test_public_material_helper():
    assert public_material(ed25519_entry()) == ("ed25519", ED_PUB)


RSA_PRIV, RSA_PUB = generate_blind_keypair(2048)


def rsabssa_entry() -> dict:
    return {
        "key_id": "dev-AGE_OVER_18-AAL2-2026-Q4",
        "algorithm": "rsabssa-sha384-pss-deterministic",
        "private_key_b64": RSA_PRIV,
        "public_key_b64": RSA_PUB,
        "claim": "AGE_OVER_18",
        "assurance_level": "AAL2",
        "epoch": "2026-Q4",
        "valid_until": "2027-01-01T00:00:00Z",
    }


@pytest.fixture()
def blind_client() -> TestClient:
    app = create_app(IssuerKeyStore([rsabssa_entry()]), EnrollmentStore(":memory:"))
    return TestClient(app)


def test_blind_issuance_round_trip(blind_client):
    eid = enroll(blind_client, "2000-01-01")
    message = token_message("YS1yYW5kb20tbm9uY2U")
    blinded, inv = blind(RSA_PUB, message)
    body = {
        "version": "1.0", "enrollment_id": eid, "claim": "AGE_OVER_18",
        "assurance_level": "AAL2", "epoch": "2026-Q4",
        "blinded_messages": [b64u_encode(blinded)],
    }
    resp = blind_client.post("/v1/tokens/issue", json=body)
    assert resp.status_code == 200
    out = resp.json()
    sig = finalize(RSA_PUB, message, b64u_decode(out["signatures"][0]), inv)
    assert RsabssaTokenVerifier(out["issuer_key_id"], RSA_PUB).verify(message, sig)


def test_malformed_blinded_message_returns_422_not_500(blind_client):
    eid = enroll(blind_client, "2000-01-01")
    body = {
        "version": "1.0", "enrollment_id": eid, "claim": "AGE_OVER_18",
        "assurance_level": "AAL2", "epoch": "2026-Q4",
        "blinded_messages": ["@@@not base64@@@"],
    }
    resp = blind_client.post("/v1/tokens/issue", json=body)
    assert resp.status_code == 422
    assert "invalid blinded message" in resp.json()["detail"]


def test_rsabssa_key_rejects_plain_nonces(blind_client):
    eid = enroll(blind_client, "2000-01-01")
    body = issue_body(eid)
    body["epoch"] = "2026-Q4"
    resp = blind_client.post("/v1/tokens/issue", json=body)
    assert resp.status_code == 422
    assert "blinded_messages" in resp.json()["detail"]


def test_ed25519_key_rejects_blinded_messages(ed_client):
    eid = enroll(ed_client, "2000-01-01")
    body = {
        "version": "1.0", "enrollment_id": eid, "claim": "AGE_OVER_16",
        "assurance_level": "AAL2", "epoch": "2026-Q3",
        "blinded_messages": ["YmxpbmRlZA"],
    }
    resp = ed_client.post("/v1/tokens/issue", json=body)
    assert resp.status_code == 422
    assert "nonces" in resp.json()["detail"]


def test_well_known_includes_rsabssa_public_key(blind_client):
    meta = blind_client.get("/.well-known/blindage-issuer.json").json()
    (key,) = meta["keys"]
    assert key["algorithm"] == "rsabssa-sha384-pss-deterministic"
    assert key["public_key"] == RSA_PUB
    assert RSA_PRIV not in json.dumps(meta)


def test_enroll_page_is_served_with_test_only_framing(client):
    resp = client.get("/enroll")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    body = resp.text
    assert "TEST-ONLY" in body                      # honest framing (constitution rule 9)
    assert "Phase 7" in body                        # says real identity check replaces it
    assert "/v1/enrollment" in body                 # posts to its own origin
    assert '"did:web:issuer.test"' in body          # issuer_id embedded as JSON
    assert "blindage-page" in body and "enrollment" in body  # postMessage handoff


def test_enroll_page_echoes_no_enrollment_data(client):
    # The page is a static form: no enrollment ids or DOBs are rendered server-side.
    created = client.post("/v1/enrollment", json={"date_of_birth": "2000-01-01"}).json()
    body = client.get("/enroll").text
    assert created["enrollment_id"] not in body
    assert "2000-01-01" not in body
