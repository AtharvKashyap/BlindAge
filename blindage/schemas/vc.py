"""BBS age-credential protocol objects (Phase 10).

A reusable, multi-claim age credential is signed once by the issuer under a
``vc_signing`` BBS key. Unlike tokens, the credential carries *all* claims the
enrolled user is eligible for; unlinkability comes from selective-disclosure
proofs at presentation time (``VcPresentation``), never from blind issuance —
see ``blindage/crypto/bbs.py`` for the (deliberate) non-blindness of BBS Sign.

Single source of truth for two conventions shared by issuer and verifier:

* ``VC_HEADER`` — the BBS ``header`` octets bound into every credential
  signature. It partitions BBS signatures to the BlindAge VC context.
* ``vc_message_vector`` — the exact ordered byte messages that are signed and
  later selectively disclosed. Order is fixed and deterministic so the verifier
  reconstructs the same vector: ``[issuer_id, assurance_level, epoch,
  *sorted(claim values)]``, each UTF-8 encoded.
"""
from pydantic import BaseModel, ConfigDict

from blindage.schemas.enums import AgeClaim, AssuranceLevel
from blindage.schemas.presentation import DomainBinding

VC_HEADER = b"blindage-vc-v1"


def vc_message_vector(
    issuer_id: str, assurance_level: str, epoch: str, claims: list[str]
) -> list[bytes]:
    """Ordered BBS message vector for a credential.

    ``[issuer_id, assurance_level, epoch, *sorted(claim values)]`` as UTF-8.
    Claims are sorted so issuer and verifier agree on message indexes regardless
    of the order in which eligible claims were computed.
    """
    return [
        m.encode("utf-8")
        for m in [issuer_id, assurance_level, epoch, *sorted(claims)]
    ]


class AgeCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    issuer_id: str
    issuer_key_id: str
    assurance_level: AssuranceLevel
    epoch: str
    claims: list[AgeClaim]
    signature: str


class VcPresentation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    presentation_type: str = "blindage.vc"
    required_claim: AgeClaim
    issuer_id: str
    issuer_key_id: str
    assurance_level: AssuranceLevel
    epoch: str
    proof: str
    disclosed_indexes: list[int]
    domain_binding: DomainBinding


class CredentialIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    enrollment_id: str
