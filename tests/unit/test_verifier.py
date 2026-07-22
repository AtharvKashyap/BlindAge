from datetime import datetime, timedelta, timezone

import pytest

from blindage.crypto import MockTokenSigner, b64u_encode
from blindage.registry import TrustRegistry
from blindage.schemas import (
    AgeClaim,
    AgeToken,
    AssuranceLevel,
    Decision,
    DomainBinding,
    Presentation,
    VerifierPolicy,
    token_message,
)
from blindage.verifier import BlindAgeVerifier, ChallengeManager, ReplayCache

SECRET_18 = b"e" * 32
SECRET_13 = b"y" * 32
ISSUER = "did:web:issuer.test"
KEY_18 = "dev-AGE_OVER_18-AAL2-2026-Q3"
KEY_13 = "dev-AGE_OVER_13-AAL2-2026-Q3"


def registry(status: str = "active") -> TrustRegistry:
    def key(key_id: str, claim: str, secret: bytes) -> dict:
        return {
            "key_id": key_id,
            "purpose": "token_signing",
            "algorithm": "mock-hmac-sha256",
            "public_key": b64u_encode(secret),
            "claim": claim,
            "assurance_level": "AAL2",
            "epoch": "2026-Q3",
            "valid_from": "2026-07-01T00:00:00Z",
            "valid_until": "2026-10-01T00:00:00Z",
        }

    return TrustRegistry.from_dict(
        {
            "version": "1.0",
            "generated_at": "2026-07-21T00:00:00Z",
            "issuers": [
                {
                    "version": "1.0",
                    "issuer_id": ISSUER,
                    "legal_name": "Test Issuer",
                    "jurisdiction": "US",
                    "supported_claims": ["AGE_OVER_13", "AGE_OVER_18"],
                    "assurance_levels": ["AAL2"],
                    "keys": [key(KEY_18, "AGE_OVER_18", SECRET_18), key(KEY_13, "AGE_OVER_13", SECRET_13)],
                    "status": status,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                }
            ],
        }
    )


def make_verifier(reg: TrustRegistry | None = None, audience: str = "example.test"):
    policy = VerifierPolicy(
        policy_id="p1",
        required_claim=AgeClaim.AGE_OVER_18,
        minimum_assurance_level=AssuranceLevel.AAL2,
        trusted_issuers=[ISSUER],
    )
    cm = ChallengeManager(audience=audience)
    return (
        BlindAgeVerifier(
            registry=reg if reg is not None else registry(),
            policy=policy,
            replay_cache=ReplayCache(":memory:"),
            challenge_manager=cm,
            audience=audience,
        ),
        cm,
    )


def signed_token(
    nonce: str = "bm9uY2U",
    key_id: str = KEY_18,
    secret: bytes = SECRET_18,
    claim: AgeClaim = AgeClaim.AGE_OVER_18,
) -> AgeToken:
    signer = MockTokenSigner(key_id=key_id, secret=secret)
    return AgeToken(
        claim=claim,
        assurance_level=AssuranceLevel.AAL2,
        epoch="2026-Q3",
        issuer_id=ISSUER,
        issuer_key_id=key_id,
        nonce=nonce,
        signature=b64u_encode(signer.sign(token_message(nonce))),
    )


def present(cm: ChallengeManager, token: AgeToken, audience: str = "example.test") -> Presentation:
    challenge = cm.create(AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2)
    return Presentation(
        required_claim=AgeClaim.AGE_OVER_18,
        token=token,
        domain_binding=DomainBinding(
            audience=audience,
            challenge=challenge.challenge,
            challenge_id=challenge.challenge_id,
            timestamp=datetime.now(timezone.utc),
        ),
    )


def test_valid_presentation_allows():
    verifier, cm = make_verifier()
    decision = verifier.verify(present(cm, signed_token()))
    assert decision.decision == Decision.ALLOW
    assert decision.valid and decision.signature_valid and decision.claim_satisfied
    assert decision.claim == AgeClaim.AGE_OVER_18  # derived from key binding


def test_replay_same_token_denied():
    verifier, cm = make_verifier()
    token = signed_token()
    assert verifier.verify(present(cm, token)).decision == Decision.ALLOW
    second = verifier.verify(present(cm, token))
    assert second.decision == Decision.DENY and second.replayed


def test_advisory_claim_mismatch_rejected():
    # MOD-1 break case: genuine AGE_OVER_13 token relabeled AGE_OVER_18.
    verifier, cm = make_verifier()
    forged = signed_token(
        key_id=KEY_13, secret=SECRET_13, claim=AgeClaim.AGE_OVER_18
    )  # signature IS valid under the 13-key; advisory claim lies
    decision = verifier.verify(present(cm, forged))
    assert decision.decision == Decision.DENY
    assert not decision.claim_satisfied


def test_wrong_claim_key_denied():
    # Honest AGE_OVER_13 token presented at an AGE_OVER_18 gate.
    verifier, cm = make_verifier()
    token = signed_token(key_id=KEY_13, secret=SECRET_13, claim=AgeClaim.AGE_OVER_13)
    decision = verifier.verify(present(cm, token))
    assert decision.decision == Decision.DENY and not decision.claim_satisfied


def test_bad_signature_denied():
    verifier, cm = make_verifier()
    token = signed_token(secret=b"wrong-secret-wrong-secret-wrong!")
    decision = verifier.verify(present(cm, token))
    assert decision.decision == Decision.DENY and not decision.signature_valid


def test_untrusted_issuer_denied():
    verifier, cm = make_verifier(reg=registry(status="revoked"))
    decision = verifier.verify(present(cm, signed_token()))
    assert decision.decision == Decision.DENY and not decision.issuer_trusted


def test_wrong_audience_denied():
    verifier, cm = make_verifier()
    decision = verifier.verify(present(cm, signed_token(), audience="evil.test"))
    assert decision.decision == Decision.DENY and not decision.domain_binding_valid


def test_challenge_cannot_be_consumed_twice():
    verifier, cm = make_verifier()
    challenge = cm.create(AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2)

    def build(token: AgeToken) -> Presentation:
        return Presentation(
            required_claim=AgeClaim.AGE_OVER_18,
            token=token,
            domain_binding=DomainBinding(
                audience="example.test",
                challenge=challenge.challenge,
                challenge_id=challenge.challenge_id,
                timestamp=datetime.now(timezone.utc),
            ),
        )

    assert verifier.verify(build(signed_token())).decision == Decision.ALLOW
    second = verifier.verify(build(signed_token(nonce="ZnJlc2g")))
    assert second.decision == Decision.DENY and not second.challenge_valid


def test_failed_attempt_does_not_burn_nonce():
    verifier, cm = make_verifier()
    token = signed_token()
    # First attempt fails on audience — nonce must NOT be marked spent.
    assert verifier.verify(present(cm, token, audience="evil.test")).decision == Decision.DENY
    assert verifier.verify(present(cm, token)).decision == Decision.ALLOW


def test_replay_cache_atomicity():
    cache = ReplayCache(":memory:")
    assert cache.check_and_insert("h1") is True
    assert cache.check_and_insert("h1") is False


def test_challenge_manager_expiry():
    cm = ChallengeManager(audience="example.test", ttl_seconds=-1)  # born expired
    ch = cm.create(AgeClaim.AGE_OVER_18, AssuranceLevel.AAL2)
    assert cm.consume(ch.challenge_id, ch.challenge) is None
