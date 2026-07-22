from pydantic import BaseModel, ConfigDict

from blindage.schemas.enums import AgeClaim, AssuranceLevel


class VerifierPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str
    required_claim: AgeClaim
    minimum_assurance_level: AssuranceLevel
    trusted_issuers: list[str]
    require_domain_binding: bool = True
    require_single_use: bool = True
    maximum_token_age_seconds: int | None = None
