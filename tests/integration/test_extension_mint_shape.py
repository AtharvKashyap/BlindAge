"""The contract the in-extension minter depends on: POST blinded_messages to the
issuer, unblind the response, and the resulting token verifies at a site. The JS
minter mirrors this Python flow (blind/finalize ported 1:1)."""

from fastapi.testclient import TestClient

from blindage.crypto import b64u_decode, b64u_encode, blind, finalize
from blindage.crypto.rsabssa import RsabssaTokenVerifier
from blindage.example_site.app import create_site
from blindage.issuer.app import create_app as create_issuer
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.storage import EnrollmentStore
from blindage.schemas import token_message
from tests.conftest import ISSUER_ID, dev_key_entries, dev_registry


def test_blind_mint_contract_end_to_end():
    key_store = IssuerKeyStore(dev_key_entries())  # rsabssa dev key
    issuer = TestClient(create_issuer(key_store, EnrollmentStore(":memory:")))
    site = TestClient(
        create_site(dev_registry(), trusted_issuer=ISSUER_ID, audience="localhost")
    )

    # Enroll and read the issuer public key from well-known (as the extension does).
    eid = issuer.post(
        "/v1/enrollment", json={"date_of_birth": "2000-01-01"}
    ).json()["enrollment_id"]
    wk = issuer.get("/.well-known/blindage-issuer.json").json()
    key = next(
        k
        for k in wk["keys"]
        if k["claim"] == "AGE_OVER_18" and k["epoch"] == "2026-Q3"
    )
    pub_b64 = key["public_key"]

    # Blind -> issue -> finalize (the JS path, in Python).
    nonce = b64u_encode(b"x" * 32)
    blinded, inv = blind(pub_b64, token_message(nonce))
    resp = issuer.post(
        "/v1/tokens/issue",
        json={
            "version": "1.0",
            "enrollment_id": eid,
            "claim": "AGE_OVER_18",
            "assurance_level": "AAL2",
            "epoch": "2026-Q3",
            "blinded_messages": [b64u_encode(blinded)],
        },
    )
    assert resp.status_code == 200
    sig = finalize(
        pub_b64,
        token_message(nonce),
        b64u_decode(resp.json()["signatures"][0]),
        inv,
    )
    assert RsabssaTokenVerifier(key["key_id"], pub_b64).verify(token_message(nonce), sig)
