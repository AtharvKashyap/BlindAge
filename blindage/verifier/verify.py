import hashlib
from datetime import datetime, timezone

from blindage.crypto import b64u_decode, mock_verifier_from_public_key
from blindage.registry import TrustRegistry
from blindage.schemas import (
    Decision,
    IssuerStatus,
    Presentation,
    VerifierDecision,
    VerifierPolicy,
    assurance_at_least,
    token_message,
)
from blindage.verifier.challenge import ChallengeManager
from blindage.verifier.replay_cache import ReplayCache


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class BlindAgeVerifier:
    def __init__(
        self,
        registry: TrustRegistry,
        policy: VerifierPolicy,
        replay_cache: ReplayCache,
        challenge_manager: ChallengeManager,
        audience: str,
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._replay = replay_cache
        self._challenges = challenge_manager
        self._audience = audience

    def verify(self, presentation: Presentation) -> VerifierDecision:
        flags = dict(
            signature_valid=False,
            issuer_trusted=False,
            claim_satisfied=False,
            assurance_sufficient=False,
            expired=True,
            replayed=False,
            revoked=True,
            domain_binding_valid=False,
            challenge_valid=False,
        )
        derived_claim = None
        derived_assurance = None
        token = presentation.token

        def deny() -> VerifierDecision:
            return VerifierDecision(
                valid=False,
                claim=derived_claim,
                assurance_level=derived_assurance,
                decision=Decision.DENY,
                **flags,
            )

        issuer = self._registry.get_issuer(token.issuer_id)
        if (
            issuer is None
            or issuer.status != IssuerStatus.ACTIVE
            or token.issuer_id not in self._policy.trusted_issuers
        ):
            return deny()
        flags["issuer_trusted"] = True
        flags["revoked"] = False

        key = self._registry.get_token_key(token.issuer_id, token.issuer_key_id)
        if key is None:
            return deny()

        verifier = mock_verifier_from_public_key(key.key_id, key.public_key)
        flags["signature_valid"] = verifier.verify(
            token_message(token.nonce), b64u_decode(token.signature)
        )
        if not flags["signature_valid"]:
            return deny()

        # MOD-1: authoritative claim/assurance/epoch come from the registry
        # binding of the verifying key. Advisory token fields must agree.
        derived_claim = key.claim
        derived_assurance = key.assurance_level
        if (token.claim, token.assurance_level, token.epoch) != (
            key.claim,
            key.assurance_level,
            key.epoch,
        ):
            return deny()

        flags["claim_satisfied"] = derived_claim == self._policy.required_claim
        flags["assurance_sufficient"] = assurance_at_least(
            derived_assurance, self._policy.minimum_assurance_level
        )
        if not (flags["claim_satisfied"] and flags["assurance_sufficient"]):
            return deny()

        now = datetime.now(timezone.utc)
        flags["expired"] = not (key.valid_from <= now <= key.valid_until)
        if flags["expired"]:
            return deny()

        binding = presentation.domain_binding
        flags["domain_binding_valid"] = binding.audience == self._audience
        if not flags["domain_binding_valid"]:
            return deny()

        challenge = self._challenges.consume(binding.challenge_id, binding.challenge)
        flags["challenge_valid"] = (
            challenge is not None
            and challenge.required_claim == self._policy.required_claim
        )
        if not flags["challenge_valid"]:
            return deny()

        # Replay check LAST: the nonce is only burned once every other check
        # has passed, so a failed attempt does not consume the token.
        if not self._replay.check_and_insert(sha256_hex(token.nonce)):
            flags["replayed"] = True
            return deny()

        return VerifierDecision(
            valid=True,
            claim=derived_claim,
            assurance_level=derived_assurance,
            decision=Decision.ALLOW,
            **flags,
        )
