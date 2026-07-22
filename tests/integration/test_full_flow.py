from blindage.schemas import AgeClaim, AssuranceLevel, VerifierChallenge
from blindage.wallet.client import enroll, mint, build_presentation
from blindage.wallet.vault import StoredToken, VaultData


def mint_vault(issuer_http, count: int = 2) -> VaultData:
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
