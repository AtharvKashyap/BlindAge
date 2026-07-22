from datetime import date, datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from blindage.crypto import b64u_encode
from blindage.issuer.eligibility import eligible_claims
from blindage.issuer.keys import IssuerKeyStore, public_material
from blindage.issuer.storage import EnrollmentStore
from blindage.schemas import TokenIssueRequest, TokenIssueResponse, token_message

MAX_BATCH = 100


class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    date_of_birth: date


def create_app(
    key_store: IssuerKeyStore,
    enrollment_store: EnrollmentStore,
    issuer_id: str = "did:web:issuer.test",
) -> FastAPI:
    app = FastAPI(title="BlindAge Issuer (Phase 2, Ed25519 — issuance not yet blind)")

    @app.post("/v1/enrollment", status_code=201)
    def enroll(req: EnrollmentRequest) -> dict:
        # Phase 1 test-only proofing: the DOB is asserted, not verified.
        enrollment_id = enrollment_store.create(req.date_of_birth)
        claims = eligible_claims(req.date_of_birth, datetime.now(timezone.utc).date())
        return {
            "enrollment_id": enrollment_id,
            "eligible_claims": sorted(c.value for c in claims),
        }

    @app.post("/v1/tokens/issue")
    def issue(req: TokenIssueRequest) -> TokenIssueResponse:
        if len(req.nonces) > MAX_BATCH:
            raise HTTPException(422, detail=f"batch limit is {MAX_BATCH}")
        dob = enrollment_store.get_dob(req.enrollment_id)
        if dob is None:
            raise HTTPException(404, detail="unknown enrollment")
        today = datetime.now(timezone.utc).date()
        # Phase 1 checks claim eligibility only; assurance_level is user-asserted
        # because proofing is simulated — real assurance binding arrives with
        # real proofing (see spec AAL levels).
        if req.claim not in eligible_claims(dob, today):
            # Key-partitioning enforcement point [MOD-1]: never sign under a
            # key whose tuple the enrolled user is not eligible for.
            raise HTTPException(403, detail="not eligible for requested claim")
        found = key_store.signer_for(req.claim, req.assurance_level, req.epoch)
        if found is None:
            raise HTTPException(409, detail="no signing key for requested tuple")
        signer, valid_until = found
        signatures = [b64u_encode(signer.sign(token_message(n))) for n in req.nonces]
        return TokenIssueResponse(
            issuer_id=issuer_id,
            issuer_key_id=signer.key_id,
            claim=req.claim,
            assurance_level=req.assurance_level,
            epoch=req.epoch,
            signatures=signatures,
            expires_at=datetime.fromisoformat(valid_until.replace("Z", "+00:00")),
        )

    @app.get("/.well-known/blindage-issuer.json")
    def well_known() -> dict:
        keys = []
        for e in key_store.all_entries():
            algorithm, public_key = public_material(e)
            keys.append(
                {
                    "key_id": e["key_id"],
                    "purpose": "token_signing",
                    "algorithm": algorithm,
                    "public_key": public_key,
                    "claim": e["claim"],
                    "assurance_level": e["assurance_level"],
                    "epoch": e["epoch"],
                    "valid_from": "2026-07-01T00:00:00Z",
                    "valid_until": e["valid_until"],
                }
            )
        return {
            "version": "1.0",
            "issuer_id": issuer_id,
            "legal_name": "BlindAge Dev Issuer",
            "jurisdiction": "US",
            "supported_claims": sorted({e["claim"] for e in key_store.all_entries()}),
            "assurance_levels": sorted({e["assurance_level"] for e in key_store.all_entries()}),
            "keys": keys,
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        }

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app
