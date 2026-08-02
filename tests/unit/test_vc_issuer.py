from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from blindage.crypto import b64u_decode
from blindage.crypto.bbs import bbs_verify
from blindage.issuer.app import create_app
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.storage import EnrollmentStore
from blindage.schemas import AgeCredential, vc_message_vector
from tests.conftest import dev_key_entries, ISSUER_ID


def _client_and_store():
    store = EnrollmentStore(":memory:")
    return TestClient(create_app(IssuerKeyStore(dev_key_entries()), store)), store


def _vc_pub():
    entry = next(e for e in dev_key_entries() if e["purpose"] == "vc_signing")
    return entry["key_id"], entry["public_key_b64"]


def test_issue_credential_end_to_end():
    client, store = _client_and_store()
    eid = client.post("/v1/enrollment", json={"date_of_birth": "1990-01-01"}).json()["enrollment_id"]
    resp = client.post("/v1/credentials/issue", json={"version": "1.0", "enrollment_id": eid})
    assert resp.status_code == 200
    cred = AgeCredential.model_validate(resp.json())
    assert cred.issuer_id == ISSUER_ID
    assert "AGE_OVER_18" in [c.value for c in cred.claims]
    key_id, pub = _vc_pub()
    assert cred.issuer_key_id == key_id
    msgs = vc_message_vector(cred.issuer_id, cred.assurance_level.value,
                             cred.epoch, [c.value for c in cred.claims])
    assert bbs_verify(pub, b64u_decode(cred.signature), b"blindage-vc-v1", msgs)


def test_issue_rejects_unknown_and_expired():
    client, store = _client_and_store()
    assert client.post("/v1/credentials/issue",
                       json={"version": "1.0", "enrollment_id": "nope"}).status_code == 404
    eid = store.create(datetime(1990, 1, 1).date(),
                       datetime.now(timezone.utc) - timedelta(seconds=1))
    resp = client.post("/v1/credentials/issue", json={"version": "1.0", "enrollment_id": eid})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "enrollment expired"


def test_well_known_publishes_vc_key():
    client, _ = _client_and_store()
    keys = client.get("/.well-known/blindage-issuer.json").json()["keys"]
    vc = [k for k in keys if k["purpose"] == "vc_signing"]
    assert len(vc) == 1 and vc[0]["algorithm"] == "bbs-bls12381-sha256"
