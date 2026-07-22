from datetime import datetime

from pydantic import BaseModel, ConfigDict, model_validator

from blindage.schemas.enums import AgeClaim, AssuranceLevel


def token_message(nonce: str) -> bytes:
    """The ONLY bytes ever signed for a token.

    MOD-1: claim/assurance/epoch are bound by WHICH key signs, never by
    content inside the signed message.
    """
    return nonce.encode("utf-8")


class AgeToken(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    # claim/assurance_level/epoch are ADVISORY routing hints. The verifier
    # derives the authoritative values from the registry entry of the key
    # that verified the signature, and rejects on mismatch. [MOD-1]
    claim: AgeClaim
    assurance_level: AssuranceLevel
    epoch: str
    issuer_id: str
    issuer_key_id: str
    nonce: str
    signature: str


class TokenIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    enrollment_id: str
    claim: AgeClaim
    assurance_level: AssuranceLevel
    epoch: str
    # Exactly one of the two payload kinds:
    # - blinded_messages: RFC 9474 blinded values (rsabssa keys) — the issuer
    #   cannot see the token nonces. This is the double-anonymity path.
    # - nonces: plaintext token nonces (ed25519/mock keys only; the legacy
    #   non-blind path retained for tests and non-blind algorithms).
    nonces: list[str] | None = None
    blinded_messages: list[str] | None = None

    @model_validator(mode="after")
    def _exactly_one_payload(self) -> "TokenIssueRequest":
        has_nonces = bool(self.nonces)
        has_blinded = bool(self.blinded_messages)
        if has_nonces == has_blinded:
            raise ValueError("exactly one of nonces or blinded_messages is required")
        return self


class TokenIssueResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    issuer_id: str
    issuer_key_id: str
    claim: AgeClaim
    assurance_level: AssuranceLevel
    epoch: str
    signatures: list[str]
    expires_at: datetime
