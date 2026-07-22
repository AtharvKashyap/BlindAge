from enum import Enum


class AgeClaim(str, Enum):
    AGE_OVER_13 = "AGE_OVER_13"
    AGE_OVER_16 = "AGE_OVER_16"
    AGE_OVER_18 = "AGE_OVER_18"
    AGE_OVER_21 = "AGE_OVER_21"


CLAIM_MIN_AGE: dict[AgeClaim, int] = {
    AgeClaim.AGE_OVER_13: 13,
    AgeClaim.AGE_OVER_16: 16,
    AgeClaim.AGE_OVER_18: 18,
    AgeClaim.AGE_OVER_21: 21,
}


class AssuranceLevel(str, Enum):
    AAL0 = "AAL0"
    AAL1 = "AAL1"
    AAL2 = "AAL2"
    AAL3 = "AAL3"


_ASSURANCE_ORDER = {
    AssuranceLevel.AAL0: 0,
    AssuranceLevel.AAL1: 1,
    AssuranceLevel.AAL2: 2,
    AssuranceLevel.AAL3: 3,
}


def assurance_at_least(level: AssuranceLevel, minimum: AssuranceLevel) -> bool:
    return _ASSURANCE_ORDER[level] >= _ASSURANCE_ORDER[minimum]


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class IssuerStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"
