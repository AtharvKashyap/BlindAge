from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from blindage.schemas import (
    AgeClaim,
    AgeToken,
    AssuranceLevel,
    CLAIM_MIN_AGE,
    Decision,
    DomainBinding,
    IssuerKey,
    IssuerMetadata,
    IssuerStatus,
    Presentation,
    TokenIssueRequest,
    VerifierChallenge,
    VerifierDecision,
    VerifierPolicy,
    assurance_at_least,
    token_message,
)


def make_token(**overrides) -> AgeToken:
    data = dict(
        version="1.0",
        claim=AgeClaim.AGE_OVER_18,
        assurance_level=AssuranceLevel.AAL2,
        epoch="2026-Q3",
        issuer_id="did:web:issuer.test",
        issuer_key_id="dev-AGE_OVER_18-AAL2-2026-Q3",
        nonce="bm9uY2U",
        signature="c2ln",
    )
    data.update(overrides)
    return AgeToken(**data)


def test_claim_min_age_mapping():
    assert CLAIM_MIN_AGE[AgeClaim.AGE_OVER_13] == 13
    assert CLAIM_MIN_AGE[AgeClaim.AGE_OVER_21] == 21


def test_assurance_ordering():
    assert assurance_at_least(AssuranceLevel.AAL2, AssuranceLevel.AAL1)
    assert assurance_at_least(AssuranceLevel.AAL2, AssuranceLevel.AAL2)
    assert not assurance_at_least(AssuranceLevel.AAL1, AssuranceLevel.AAL2)


def test_token_message_is_only_the_nonce():
    # MOD-1: no claim/assurance/epoch inside the signed message.
    assert token_message("abc123") == b"abc123"


def test_age_token_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        AgeToken(**{**make_token().model_dump(), "user_id": "12345"})


def test_age_token_rejects_pii_field_names():
    for bad in ("name", "date_of_birth", "address", "document_number"):
        with pytest.raises(ValidationError):
            AgeToken(**{**make_token().model_dump(), bad: "x"})


def test_presentation_round_trips():
    p = Presentation(
        version="1.0",
        presentation_type="blindage.age_token",
        required_claim=AgeClaim.AGE_OVER_18,
        token=make_token(),
        domain_binding=DomainBinding(
            audience="example.test",
            challenge="Y2hhbGxlbmdl",
            challenge_id="11111111-1111-1111-1111-111111111111",
            timestamp=datetime.now(timezone.utc),
        ),
    )
    assert Presentation.model_validate_json(p.model_dump_json()) == p


def test_issue_request_has_no_domain_or_pii_field():
    # Double-anonymity: there is no field through which the wallet could tell
    # the issuer where tokens will be used.
    fields = set(TokenIssueRequest.model_fields)
    assert fields == {
        "version",
        "enrollment_id",
        "claim",
        "assurance_level",
        "epoch",
        "nonces",
        "blinded_messages",
    }


def test_issue_request_requires_exactly_one_payload_kind():
    base = dict(enrollment_id="e", claim=AgeClaim.AGE_OVER_18,
                assurance_level=AssuranceLevel.AAL2, epoch="2026-Q3")
    with pytest.raises(ValidationError):
        TokenIssueRequest(**base)  # neither
    with pytest.raises(ValidationError):
        TokenIssueRequest(**base, nonces=["a"], blinded_messages=["b"])  # both
    assert TokenIssueRequest(**base, nonces=["a"]).nonces == ["a"]
    assert TokenIssueRequest(**base, blinded_messages=["b"]).blinded_messages == ["b"]


def test_issuer_key_requires_binding_for_token_signing():
    with pytest.raises(ValidationError):
        IssuerKey(
            key_id="k1",
            purpose="token_signing",
            algorithm="mock-hmac-sha256",
            public_key="cGs",
            valid_from=datetime.now(timezone.utc),
            valid_until=datetime.now(timezone.utc),
        )  # missing claim/assurance_level/epoch


def test_issuer_key_rejects_purpose_not_in_literal():
    with pytest.raises(ValidationError):
        IssuerKey(
            key_id="k1",
            purpose="Token_Signing",  # wrong case, not a valid Literal member
            algorithm="mock-hmac-sha256",
            public_key="cGs",
            claim=AgeClaim.AGE_OVER_18,
            assurance_level=AssuranceLevel.AAL2,
            epoch="2026-Q3",
            valid_from=datetime.now(timezone.utc),
            valid_until=datetime.now(timezone.utc),
        )


def test_issuer_key_rejects_empty_string_binding_fields():
    with pytest.raises(ValidationError):
        IssuerKey(
            key_id="k1",
            purpose="token_signing",
            algorithm="ed25519",
            public_key="cGs",
            claim=AgeClaim.AGE_OVER_18,
            assurance_level=AssuranceLevel.AAL2,
            epoch="",
            valid_from=datetime.now(timezone.utc),
            valid_until=datetime.now(timezone.utc),
        )


def test_verifier_decision_denies_by_default_shape():
    d = VerifierDecision(
        valid=False,
        claim=None,
        assurance_level=None,
        signature_valid=False,
        issuer_trusted=False,
        claim_satisfied=False,
        assurance_sufficient=False,
        expired=True,
        replayed=True,
        revoked=True,
        domain_binding_valid=False,
        challenge_valid=False,
        decision=Decision.DENY,
    )
    assert d.decision == Decision.DENY


def test_verifier_policy_defaults():
    p = VerifierPolicy(
        policy_id="p1",
        required_claim=AgeClaim.AGE_OVER_18,
        minimum_assurance_level=AssuranceLevel.AAL2,
        trusted_issuers=["did:web:issuer.test"],
    )
    assert p.require_domain_binding is True
    assert p.require_single_use is True
    assert p.maximum_token_age_seconds is None


def test_issuer_metadata_validates(sample_issuer_metadata=None):
    meta = IssuerMetadata(
        version="1.0",
        issuer_id="did:web:issuer.test",
        legal_name="Test Issuer",
        jurisdiction="US",
        supported_claims=[AgeClaim.AGE_OVER_18],
        assurance_levels=[AssuranceLevel.AAL2],
        keys=[
            IssuerKey(
                key_id="dev-AGE_OVER_18-AAL2-2026-Q3",
                purpose="token_signing",
                algorithm="mock-hmac-sha256",
                public_key="cGs",
                claim=AgeClaim.AGE_OVER_18,
                assurance_level=AssuranceLevel.AAL2,
                epoch="2026-Q3",
                valid_from=datetime(2026, 7, 1, tzinfo=timezone.utc),
                valid_until=datetime(2026, 10, 1, tzinfo=timezone.utc),
            )
        ],
        status=IssuerStatus.ACTIVE,
        valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        valid_until=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    assert meta.status == IssuerStatus.ACTIVE
