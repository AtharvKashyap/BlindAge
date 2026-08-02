from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from blindage.schemas.enums import AgeClaim, AssuranceLevel, IssuerStatus


class IssuerKey(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str
    purpose: Literal["token_signing", "vc_signing", "registry"]
    algorithm: str
    public_key: str
    claim: AgeClaim | None = None
    assurance_level: AssuranceLevel | None = None
    epoch: str | None = None
    valid_from: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def _token_keys_need_binding(self) -> "IssuerKey":
        if self.purpose == "token_signing":
            if self.claim is None or self.assurance_level is None or self.epoch is None:
                raise ValueError(
                    "token_signing keys must bind exactly one (claim, assurance_level, epoch)"
                )
            if not self.epoch:
                raise ValueError("epoch must be a non-empty string")
        if self.purpose == "vc_signing":
            # vc_signing keys bind assurance_level + epoch (key partitioning) but
            # NOT a single claim: one credential carries every eligible claim, and
            # the claim→key binding that tokens rely on does not apply.
            if self.assurance_level is None or not self.epoch:
                raise ValueError(
                    "vc_signing keys must bind assurance_level and a non-empty epoch"
                )
            if self.claim is not None:
                raise ValueError("vc_signing keys must not bind a single claim")
        return self


class IssuerMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    issuer_id: str
    legal_name: str
    jurisdiction: str
    endpoint: str | None = None  # issuer base URL, for client discovery (public data)
    supported_claims: list[AgeClaim]
    assurance_levels: list[AssuranceLevel]
    keys: list[IssuerKey]
    status: IssuerStatus
    valid_from: datetime
    valid_until: datetime
