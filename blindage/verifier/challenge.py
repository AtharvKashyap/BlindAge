import secrets
import uuid
from datetime import datetime, timedelta, timezone

from blindage.crypto import b64u_encode
from blindage.schemas import AgeClaim, AssuranceLevel, VerifierChallenge


class ChallengeManager:
    def __init__(self, audience: str, ttl_seconds: int = 300) -> None:
        self._audience = audience
        self._ttl = ttl_seconds
        self._pending: dict[str, VerifierChallenge] = {}

    def create(
        self, required_claim: AgeClaim, minimum_assurance_level: AssuranceLevel
    ) -> VerifierChallenge:
        now = datetime.now(timezone.utc)
        challenge = VerifierChallenge(
            challenge_id=str(uuid.uuid4()),
            required_claim=required_claim,
            minimum_assurance_level=minimum_assurance_level,
            audience=self._audience,
            challenge=b64u_encode(secrets.token_bytes(32)),
            issued_at=now,
            expires_at=now + timedelta(seconds=self._ttl),
        )
        self._pending[challenge.challenge_id] = challenge
        return challenge

    def consume(self, challenge_id: str, challenge_value: str) -> VerifierChallenge | None:
        """One-time: a challenge is removed on first consume attempt that matches."""
        challenge = self._pending.pop(challenge_id, None)
        if challenge is None:
            return None
        if challenge.challenge != challenge_value:
            return None
        if datetime.now(timezone.utc) > challenge.expires_at:
            return None
        return challenge
