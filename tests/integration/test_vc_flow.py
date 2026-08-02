"""Reusable-credential loop: enroll -> vc issue -> two randomized presentations ->
site accepts each with a fresh challenge, rejects challenge replay and hidden-claim
substitution."""
import json

import pytest
from fastapi.testclient import TestClient

from blindage.crypto import b64u_encode
from blindage.crypto.bbs import bbs_sign
from blindage.example_site.app import create_site
from blindage.issuer.app import create_app as create_issuer
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.storage import EnrollmentStore
from blindage.schemas import (
    VC_HEADER,
    AgeCredential,
    VcPresentation,
    vc_message_vector,
)
from blindage.wallet.client import WalletError, vc_prove
from tests.conftest import (
    DEV_VC_KEY,
    DEV_VC_PRIV,
    DEV_VC_PUB,
    ISSUER_ID,
    dev_key_entries,
    dev_registry,
)


def _stack():
    issuer = TestClient(create_issuer(IssuerKeyStore(dev_key_entries()), EnrollmentStore(":memory:")))
    site = TestClient(create_site(dev_registry(), trusted_issuer=ISSUER_ID, audience="localhost"))
    eid = issuer.post("/v1/enrollment", json={"date_of_birth": "1990-01-01"}).json()["enrollment_id"]
    cred = AgeCredential.model_validate(
        issuer.post("/v1/credentials/issue", json={"version": "1.0", "enrollment_id": eid}).json()
    )
    return site, cred


def _challenge(site):
    from blindage.schemas import VerifierChallenge
    return VerifierChallenge.model_validate(site.post("/api/challenge").json())


def test_two_presentations_both_accepted_and_unlinkable_bytes():
    site, cred = _stack()
    p1 = vc_prove(cred, _challenge(site))
    p2 = vc_prove(cred, _challenge(site))
    r1 = site.post("/api/redeem-vc", json=json.loads(p1.model_dump_json()))
    r2 = site.post("/api/redeem-vc", json=json.loads(p2.model_dump_json()))
    assert r1.status_code == 200 and r1.json()["decision"] == "ALLOW"
    assert r2.status_code == 200 and r2.json()["decision"] == "ALLOW"
    assert p1.proof != p2.proof  # randomized presentations


def test_challenge_replay_denied():
    site, cred = _stack()
    ch = _challenge(site)
    p = vc_prove(cred, ch)
    assert site.post("/api/redeem-vc", json=json.loads(p.model_dump_json())).status_code == 200
    p2 = vc_prove(cred, ch)  # same challenge, fresh proof
    r = site.post("/api/redeem-vc", json=json.loads(p2.model_dump_json()))
    assert r.status_code == 403


def test_wallet_refuses_missing_claim_and_site_rejects_tamper():
    site, cred = _stack()
    ch = _challenge(site)
    p = vc_prove(cred, ch)
    body = json.loads(p.model_dump_json())
    body["required_claim"] = "AGE_OVER_21" if body["required_claim"] != "AGE_OVER_21" else "AGE_OVER_18"
    assert site.post("/api/redeem-vc", json=body).status_code == 403  # proof no longer matches


def test_wallet_refuses_when_credential_lacks_required_claim():
    """The site challenge requires AGE_OVER_18 and a 1990 DOB also grants 21, so the
    real credential can always satisfy it. Exercise the wallet-refusal path directly
    with a hand-built, claims-limited credential (only AGE_OVER_13)."""
    site, _ = _stack()
    claims = ["AGE_OVER_13"]
    messages = vc_message_vector(ISSUER_ID, "AAL2", "2026-Q3", claims)
    signature = b64u_encode(bbs_sign(DEV_VC_PRIV, VC_HEADER, messages))
    limited = AgeCredential(
        issuer_id=ISSUER_ID,
        issuer_key_id=DEV_VC_KEY,
        issuer_public_key=DEV_VC_PUB,
        assurance_level="AAL2",
        epoch="2026-Q3",
        claims=["AGE_OVER_13"],
        signature=signature,
    )
    with pytest.raises(WalletError):
        vc_prove(limited, _challenge(site))
