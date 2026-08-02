import secrets
from datetime import datetime, timezone

import httpx

from blindage.crypto import (
    RSABSSA_ALGORITHM,
    BlindSignatureError,
    b64u_decode,
    b64u_encode,
    blind,
    finalize,
)
from blindage.crypto.bbs import BbsError, bbs_proof_gen
from blindage.schemas import (
    VC_HEADER,
    AgeClaim,
    AgeCredential,
    AgeToken,
    AssuranceLevel,
    CredentialIssueRequest,
    DomainBinding,
    Presentation,
    TokenIssueRequest,
    TokenIssueResponse,
    VcPresentation,
    VerifierChallenge,
    assurance_at_least,
    token_message,
    vc_message_vector,
    vc_presentation_header,
)
from blindage.wallet.vault import VaultData


class WalletError(Exception):
    pass


def enroll(http: httpx.Client, date_of_birth: str) -> str:
    resp = http.post("/v1/enrollment", json={"date_of_birth": date_of_birth})
    if resp.status_code != 201:
        raise WalletError(f"enrollment failed: {resp.status_code} {resp.text}")
    return resp.json()["enrollment_id"]


def _issuer_key_for(
    http: httpx.Client, claim: AgeClaim, assurance_level: AssuranceLevel, epoch: str
) -> dict:
    resp = http.get("/.well-known/blindage-issuer.json")
    if resp.status_code != 200:
        raise WalletError(f"cannot fetch issuer metadata: {resp.status_code}")
    for key in resp.json().get("keys", []):
        if (
            key.get("purpose") == "token_signing"
            and key.get("claim") == claim.value
            and key.get("assurance_level") == assurance_level.value
            and key.get("epoch") == epoch
        ):
            return key
    raise WalletError(
        f"no issuer key advertised for ({claim.value}, {assurance_level.value}, {epoch})"
    )


def mint(
    http: httpx.Client,
    enrollment_id: str,
    claim: AgeClaim,
    assurance_level: AssuranceLevel,
    epoch: str,
    count: int,
) -> list[AgeToken]:
    key = _issuer_key_for(http, claim, assurance_level, epoch)
    nonces = [b64u_encode(secrets.token_bytes(32)) for _ in range(count)]

    if key["algorithm"] == RSABSSA_ALGORITHM:
        public_key = key["public_key"]
        blinded: list[bytes] = []
        invs: list[int] = []
        for nonce in nonces:
            blinded_msg, inv = blind(public_key, token_message(nonce))
            blinded.append(blinded_msg)
            invs.append(inv)
        req = TokenIssueRequest(
            enrollment_id=enrollment_id,
            claim=claim,
            assurance_level=assurance_level,
            epoch=epoch,
            blinded_messages=[b64u_encode(b) for b in blinded],
        )
        resp = http.post(
            "/v1/tokens/issue", json=req.model_dump(mode="json", exclude_none=True)
        )
        if resp.status_code != 200:
            raise WalletError(f"issuance failed: {resp.status_code} {resp.text}")
        body = TokenIssueResponse.model_validate(resp.json())
        tokens = []
        for nonce, inv, blind_sig_b64 in zip(nonces, invs, body.signatures, strict=True):
            try:
                signature = finalize(
                    public_key,
                    token_message(nonce),
                    b64u_decode(blind_sig_b64),
                    inv,
                )
            except BlindSignatureError as exc:
                raise WalletError(f"failed to finalize blind signature: {exc}") from exc
            tokens.append(
                AgeToken(
                    claim=body.claim,
                    assurance_level=body.assurance_level,
                    epoch=body.epoch,
                    issuer_id=body.issuer_id,
                    issuer_key_id=body.issuer_key_id,
                    nonce=nonce,
                    signature=b64u_encode(signature),
                )
            )
        return tokens

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


def vc_get(http: httpx.Client, enrollment_id: str) -> AgeCredential:
    """Fetch a reusable BBS age credential for a stored enrollment.

    Unlike ``mint`` (blind, single-use tokens) this issues ONE multi-claim
    credential; unlinkability comes from fresh selective-disclosure proofs at
    presentation time, not from the issuance.
    """
    req = CredentialIssueRequest(enrollment_id=enrollment_id)
    resp = http.post("/v1/credentials/issue", json=req.model_dump(mode="json"))
    if resp.status_code != 200:
        raise WalletError(
            f"credential issuance failed: {resp.status_code} {resp.text}"
        )
    return AgeCredential.model_validate(resp.json())


def vc_prove(credential: AgeCredential, challenge: VerifierChallenge) -> VcPresentation:
    """Build a domain-bound selective-disclosure presentation for one challenge.

    Discloses exactly ``[issuer_id, assurance_level, epoch, required_claim]``
    (message indexes ``[0, 1, 2, claim_index]``) and keeps every other eligible
    claim hidden. Refuses (``WalletError``) if the credential lacks the required
    claim or does not meet the challenge's minimum assurance — the wallet never
    over-discloses or presents a claim it cannot back.
    """
    now = datetime.now(timezone.utc)
    if now > challenge.expires_at:
        raise WalletError("challenge expired")
    if challenge.required_claim not in credential.claims:
        raise WalletError(
            f"credential does not carry required claim {challenge.required_claim.value}"
        )
    if not assurance_at_least(
        credential.assurance_level, challenge.minimum_assurance_level
    ):
        raise WalletError(
            "credential assurance below the challenge minimum"
        )

    # Claims are signed in sorted order (see vc_message_vector); the disclosed
    # claim sits at 3 + its index in that sorted list, after the three fixed
    # metadata messages.
    claim_values = sorted(c.value for c in credential.claims)
    claim_index = 3 + claim_values.index(challenge.required_claim.value)
    disclosed_indexes = [0, 1, 2, claim_index]
    messages = vc_message_vector(
        credential.issuer_id,
        credential.assurance_level.value,
        credential.epoch,
        claim_values,
    )

    domain_binding = DomainBinding(
        audience=challenge.audience,
        challenge=challenge.challenge,
        challenge_id=challenge.challenge_id,
        timestamp=now,
    )
    ph = vc_presentation_header(domain_binding)
    try:
        proof = bbs_proof_gen(
            credential.issuer_public_key,
            b64u_decode(credential.signature),
            VC_HEADER,
            ph,
            messages,
            disclosed_indexes,
        )
    except BbsError as exc:
        raise WalletError(f"failed to build presentation proof: {exc}") from exc

    return VcPresentation(
        required_claim=challenge.required_claim,
        issuer_id=credential.issuer_id,
        issuer_key_id=credential.issuer_key_id,
        assurance_level=credential.assurance_level,
        epoch=credential.epoch,
        proof=b64u_encode(proof),
        disclosed_indexes=disclosed_indexes,
        domain_binding=domain_binding,
    )
