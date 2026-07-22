import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from blindage.example_site.app import create_site
from blindage.schemas import AgeClaim, AssuranceLevel, VerifierChallenge
from blindage.wallet.client import build_presentation, enroll, mint
from blindage.wallet.vault import StoredToken, VaultData
from tests.conftest import ISSUER_ID, dev_registry


def mint_vault(issuer_http, count: int = 1) -> VaultData:
    eid = enroll(issuer_http, "2000-01-01")
    tokens = mint(issuer_http, eid, AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2, "2026-Q3", count)
    return VaultData(tokens=[StoredToken(token=t) for t in tokens])


def test_malformed_presentation_rejected(site):
    for bad in ({}, {"version": "1.0"}, {"unknown": True}):
        assert site.post("/api/redeem", json=bad).status_code == 422


def test_extra_fields_rejected(issuer_http, site):
    vault = mint_vault(issuer_http)
    challenge = VerifierChallenge.model_validate(site.post("/api/challenge").json())
    presentation = build_presentation(vault, challenge)
    payload = json.loads(presentation.model_dump_json())
    payload["tracking_id"] = "abc"  # verifier must refuse unknown fields
    assert site.post("/api/redeem", json=payload).status_code == 422


def test_modified_claim_after_signing_rejected(issuer_http, site):
    vault = mint_vault(issuer_http)
    challenge = VerifierChallenge.model_validate(site.post("/api/challenge").json())
    presentation = build_presentation(vault, challenge)
    payload = json.loads(presentation.model_dump_json())
    payload["token"]["claim"] = "AGE_OVER_21"  # advisory-field tamper
    assert site.post("/api/redeem", json=payload).status_code == 403


def test_modified_nonce_breaks_signature(issuer_http, site):
    vault = mint_vault(issuer_http)
    challenge = VerifierChallenge.model_validate(site.post("/api/challenge").json())
    presentation = build_presentation(vault, challenge)
    payload = json.loads(presentation.model_dump_json())
    payload["token"]["nonce"] = "dGFtcGVyZWQ"
    resp = site.post("/api/redeem", json=payload)
    assert resp.status_code == 403
    assert resp.json()["detail"]["signature_valid"] is False


def test_cross_site_replay_rejected(issuer_http, site):
    # A presentation bound to site A is submitted to site B.
    site_b = TestClient(create_site(dev_registry(), trusted_issuer=ISSUER_ID, audience="other.example"))
    vault = mint_vault(issuer_http)
    challenge = VerifierChallenge.model_validate(site.post("/api/challenge").json())
    presentation = build_presentation(vault, challenge)  # audience: localhost
    resp = site_b.post("/api/redeem", json=presentation.model_dump(mode="json"))
    assert resp.status_code == 403
    assert resp.json()["detail"]["domain_binding_valid"] is False


def test_forged_challenge_rejected(issuer_http, site):
    # Attacker invents a challenge the site never issued.
    vault = mint_vault(issuer_http)
    now = datetime.now(timezone.utc)
    fake = VerifierChallenge(
        challenge_id="99999999-9999-9999-9999-999999999999",
        required_claim=AgeClaim.AGE_OVER_18,
        minimum_assurance_level=AssuranceLevel.AAL2,
        audience="localhost",
        challenge="ZmFrZQ",
        issued_at=now,
        expires_at=now.replace(year=now.year + 1),
    )
    presentation = build_presentation(vault, fake)
    resp = site.post("/api/redeem", json=presentation.model_dump(mode="json"))
    assert resp.status_code == 403
    assert resp.json()["detail"]["challenge_valid"] is False
