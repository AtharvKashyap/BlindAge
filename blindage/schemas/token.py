from datetime import datetime

from pydantic import BaseModel, ConfigDict

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
    # Phase 1: plaintext nonces (mock, linkable). Phase 3 replaces these with
    # blinded commitments — that swap closes the documented privacy gap.
    nonces: list[str]


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
