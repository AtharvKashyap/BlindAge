from pydantic import BaseModel, ConfigDict, Field

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
    # Default to the blind algorithm ONLY: a default verifier accepts just
    # unlinkable (blind-signed) tokens, so double anonymity holds unless an
    # operator explicitly opts into a non-blind algorithm. ed25519/mock remain
    # fully supported but must be named here on purpose.
    allowed_algorithms: list[str] = Field(
        default_factory=lambda: ["rsabssa-sha384-pss-deterministic"]
    )
