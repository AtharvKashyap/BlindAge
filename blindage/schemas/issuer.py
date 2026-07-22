from datetime import datetime

from pydantic import BaseModel, ConfigDict, model_validator

from blindage.schemas.enums import AgeClaim, AssuranceLevel, IssuerStatus


class IssuerKey(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str
    purpose: str  # "token_signing" | "registry"
    algorithm: str
    public_key: str
    claim: AgeClaim | None = None
    assurance_level: AssuranceLevel | None = None
    epoch: str | None = None
    valid_from: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def _token_keys_need_binding(self) -> "IssuerKey":
        if self.purpose == "token_signing" and not (
            self.claim and self.assurance_level and self.epoch
        ):
            raise ValueError(
                "token_signing keys must bind exactly one (claim, assurance_level, epoch)"
            )
        return self


class IssuerMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    issuer_id: str
    legal_name: str
    jurisdiction: str
    supported_claims: list[AgeClaim]
    assurance_levels: list[AssuranceLevel]
    keys: list[IssuerKey]
    status: IssuerStatus
    valid_from: datetime
    valid_until: datetime
