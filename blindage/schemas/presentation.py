from datetime import datetime

from pydantic import BaseModel, ConfigDict

from blindage.schemas.enums import AgeClaim, AssuranceLevel, Decision
from blindage.schemas.token import AgeToken


class VerifierChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    challenge_id: str
    required_claim: AgeClaim
    minimum_assurance_level: AssuranceLevel
    audience: str
    challenge: str
    issued_at: datetime
    expires_at: datetime


class DomainBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audience: str
    challenge: str
    challenge_id: str
    timestamp: datetime


class Presentation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    presentation_type: str = "blindage.age_token"
    required_claim: AgeClaim
    token: AgeToken
    domain_binding: DomainBinding


class VerifierDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    claim: AgeClaim | None
    assurance_level: AssuranceLevel | None
    signature_valid: bool
    issuer_trusted: bool
    claim_satisfied: bool
    assurance_sufficient: bool
    expired: bool
    replayed: bool
    revoked: bool
    domain_binding_valid: bool
    challenge_valid: bool
    decision: Decision
