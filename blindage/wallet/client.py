import secrets
from datetime import datetime, timezone

import httpx

from blindage.crypto import b64u_encode
from blindage.schemas import (
    AgeClaim,
    AgeToken,
    AssuranceLevel,
    DomainBinding,
    Presentation,
    TokenIssueRequest,
    TokenIssueResponse,
    VerifierChallenge,
    assurance_at_least,
)
from blindage.wallet.vault import VaultData


class WalletError(Exception):
    pass


def enroll(http: httpx.Client, date_of_birth: str) -> str:
    resp = http.post("/v1/enrollment", json={"date_of_birth": date_of_birth})
    if resp.status_code != 201:
        raise WalletError(f"enrollment failed: {resp.status_code} {resp.text}")
    return resp.json()["enrollment_id"]


def mint(
    http: httpx.Client,
    enrollment_id: str,
    claim: AgeClaim,
    assurance_level: AssuranceLevel,
    epoch: str,
    count: int,
) -> list[AgeToken]:
    nonces = [b64u_encode(secrets.token_bytes(32)) for _ in range(count)]
    req = TokenIssueRequest(
        enrollment_id=enrollment_id,
        claim=claim,
        assurance_level=assurance_level,
        epoch=epoch,
        nonces=nonces,
    )
    resp = http.post("/v1/tokens/issue", json=req.model_dump(mode="json"))
    if resp.status_code != 200:
        raise WalletError(f"issuance failed: {resp.status_code} {resp.text}")
    body = TokenIssueResponse.model_validate(resp.json())
    return [
        AgeToken(
            claim=body.claim,
            assurance_level=body.assurance_level,
            epoch=body.epoch,
            issuer_id=body.issuer_id,
            issuer_key_id=body.issuer_key_id,
            nonce=nonce,
            signature=signature,
        )
        for nonce, signature in zip(nonces, body.signatures, strict=True)
    ]


def build_presentation(data: VaultData, challenge: VerifierChallenge) -> Presentation:
    now = datetime.now(timezone.utc)
    if now > challenge.expires_at:
        raise WalletError("challenge expired")
    for stored in data.tokens:
        if stored.spent:
            continue
        if stored.token.claim != challenge.required_claim:
            continue
        if not assurance_at_least(
            stored.token.assurance_level, challenge.minimum_assurance_level
        ):
            continue
        stored.spent = True
        return Presentation(
            required_claim=challenge.required_claim,
            token=stored.token,
            domain_binding=DomainBinding(
                audience=challenge.audience,
                challenge=challenge.challenge,
                challenge_id=challenge.challenge_id,
                timestamp=now,
            ),
        )
    raise WalletError(
        f"no unspent token for claim {challenge.required_claim.value}"
    )
