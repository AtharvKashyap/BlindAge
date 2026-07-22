"""Privacy properties are product requirements (spec §15, [MOD-6]).

Double anonymity is real: issuance uses RFC 9474 RSA blind signatures, so
the issuer never sees the final token values it is signing, and the
verifier never sees anything that ties a presentation back to enrollment
or issuance traffic. Every test in this module is a permanent, CI-blocking
guarantee.
"""
import json

from blindage.schemas import (
    AgeClaim,
    AssuranceLevel,
    Presentation,
    TokenIssueRequest,
    VerifierChallenge,
)
from blindage.wallet.client import build_presentation, enroll, mint
from blindage.wallet.vault import StoredToken, VaultData


def mint_vault(issuer_http, count: int = 2) -> tuple[VaultData, str]:
    eid = enroll(issuer_http, "2000-01-01")
    tokens = mint(issuer_http, eid, AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2, "2026-Q3", count)
    return VaultData(tokens=[StoredToken(token=t) for t in tokens]), eid


def redeem(site, vault: VaultData) -> tuple[Presentation, dict]:
    challenge = VerifierChallenge.model_validate(site.post("/api/challenge").json())
    presentation = build_presentation(vault, challenge)
    resp = site.post("/api/redeem", json=presentation.model_dump(mode="json"))
    return presentation, resp.json()


PII_FIELDS = {"name", "date_of_birth", "dob", "address", "document_number",
              "email", "phone", "face_scan", "user_id", "enrollment_id",
              "account_id"}


def _all_keys(obj) -> set[str]:
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(k)
            keys |= _all_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            keys |= _all_keys(item)
    return keys


def test_verifier_never_receives_pii(issuer_http, site):
    vault, _eid = mint_vault(issuer_http)
    presentation, _ = redeem(site, vault)
    payload = json.loads(presentation.model_dump_json())
    assert _all_keys(payload) & PII_FIELDS == set()


def test_verifier_never_receives_enrollment_reference(issuer_http, site):
    vault, eid = mint_vault(issuer_http)
    presentation, _ = redeem(site, vault)
    presentation_json = presentation.model_dump_json()
    # The actual enrollment id value must never appear anywhere in what the
    # site receives, not just the literal substring "enrollment".
    assert eid not in presentation_json
    assert "enrollment" not in presentation_json


def test_issuer_request_schema_cannot_carry_domain():
    # Structural guarantee: there is no field in the issuance request through
    # which the wallet could tell the issuer where tokens will be spent.
    assert set(TokenIssueRequest.model_fields) == {
        "version", "enrollment_id", "claim", "assurance_level", "epoch",
        "nonces", "blinded_messages",
    }


def test_two_presentations_share_no_token_material(issuer_http, site):
    vault, _eid = mint_vault(issuer_http, count=2)
    p1, _ = redeem(site, vault)
    p2, _ = redeem(site, vault)
    assert p1.token.nonce != p2.token.nonce
    assert p1.token.signature != p2.token.signature
    assert p1.domain_binding.challenge != p2.domain_binding.challenge


def test_no_persistent_holder_identifier_across_presentations(issuer_http, site):
    vault, _eid = mint_vault(issuer_http, count=2)
    p1, _ = redeem(site, vault)
    p2, _ = redeem(site, vault)
    d1 = json.loads(p1.model_dump_json())
    d2 = json.loads(p2.model_dump_json())
    # Fields identical across presentations must be protocol constants or
    # issuer-level data only — never a per-user value.
    identical = {
        k for k in _all_keys(d1)
        if _lookup_all(d1, k) == _lookup_all(d2, k)
    }
    allowed_identical = {
        "version", "presentation_type", "required_claim", "claim",
        "assurance_level", "epoch", "issuer_id", "issuer_key_id", "audience",
        "token", "domain_binding",
    }
    assert identical <= allowed_identical


def _lookup_all(obj, key):
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                found.append(json.dumps(v, sort_keys=True, default=str))
            found.extend(_lookup_all(v, key))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_lookup_all(item, key))
    return found


def test_issuer_metadata_never_contains_private_key_material(issuer_http):
    """Registry/well-known must never leak signing secrets for asymmetric keys.

    (Mock-algorithm keys intentionally publish their symmetric secret — the
    documented Phase 1 artifact — so this asserts on ed25519/rsabssa keys.)
    """
    meta = issuer_http.get("/.well-known/blindage-issuer.json").json()
    asymmetric_algorithms = {"ed25519", "rsabssa-sha384-pss-deterministic"}
    for key in meta["keys"]:
        if key["algorithm"] in asymmetric_algorithms:
            assert "private" not in json.dumps(key)
            if key["algorithm"] == "ed25519":
                assert len(key["public_key"]) < 60  # a raw 32-byte public key, not a bundle
    assert any(k["algorithm"] in asymmetric_algorithms for k in meta["keys"]), (
        "fixture must include an ed25519 or rsabssa key or this test asserts nothing"
    )


def test_issuer_never_sees_final_token_values(issuer_http, site):
    """Permanent, CI-blocking double-anonymity guarantee: the issuer only
    ever sees blinded values during issuance. The final token nonce and
    signature the verifier later receives must never appear anywhere in
    issuance traffic sent to the issuer."""
    seen_by_issuer: list[str] = []
    original_post = issuer_http.post

    def spying_post(url, **kwargs):
        if "json" in kwargs:
            seen_by_issuer.append(json.dumps(kwargs["json"]))
        return original_post(url, **kwargs)

    issuer_http.post = spying_post
    vault, _eid = mint_vault(issuer_http, count=1)
    presentation, result = redeem(site, vault)
    assert result["decision"] == "ALLOW"
    issuance_traffic = " ".join(seen_by_issuer)
    assert presentation.token.nonce not in issuance_traffic
    assert presentation.token.signature not in issuance_traffic
