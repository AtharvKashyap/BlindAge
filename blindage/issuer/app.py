import json
from datetime import date, datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict

from blindage.crypto import RSABSSA_ALGORITHM, BlindSignatureError, b64u_decode, b64u_encode, blind_sign
from blindage.issuer.eligibility import eligible_claims
from blindage.issuer.keys import IssuerKeyStore, public_material
from blindage.issuer.storage import EnrollmentStore
from blindage.schemas import TokenIssueRequest, TokenIssueResponse, token_message

MAX_BATCH = 100

ENROLL_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>BlindAge Dev Issuer — Enroll</title>
<style>body{font-family:system-ui;max-width:30rem;margin:3rem auto;padding:0 1rem}
.warn{background:#fffaf0;border:1px solid #dd6b20;border-radius:.4rem;padding:.6rem}
button{padding:.5rem .8rem;border:0;border-radius:.3rem;background:#2b6cb0;color:#fff}</style>
</head><body>
<h1>Enroll with BlindAge Dev Issuer</h1>
<p class="warn"><strong>TEST-ONLY:</strong> this form asserts a date of birth without
verifying it. Phase 7 replaces it with a real identity check (bank / eID / mDL).</p>
<form id="f"><label>Date of birth <input type="date" id="dob" required></label>
<button type="submit">Enroll</button></form>
<p id="msg"></p>
<script>
const ISSUER_ID = __ISSUER_ID__;
document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = document.getElementById("msg");
  const resp = await fetch("/v1/enrollment", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({date_of_birth: document.getElementById("dob").value}),
  });
  if (!resp.ok) { msg.textContent = "Enrollment failed (" + resp.status + ")."; return; }
  const body = await resp.json();
  window.postMessage({source: "blindage-page", kind: "enrollment",
    issuer_id: ISSUER_ID, enrollment_id: body.enrollment_id}, location.origin);
  msg.textContent = "You're enrolled — return to the extension.";
});
</script></body></html>"""


class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    date_of_birth: date


def create_app(
    key_store: IssuerKeyStore,
    enrollment_store: EnrollmentStore,
    issuer_id: str = "did:web:issuer.test",
) -> FastAPI:
    app = FastAPI(title="BlindAge Issuer (Phase 3, blind issuance)")

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
        entry_algorithm = key_store.algorithm_for(req.claim, req.assurance_level, req.epoch)
        if entry_algorithm is None:
            raise HTTPException(409, detail="no signing key for requested tuple")
        if entry_algorithm == RSABSSA_ALGORITHM:
            if not req.blinded_messages:
                raise HTTPException(422, detail="this key requires blinded_messages")
            if len(req.blinded_messages) > MAX_BATCH:
                raise HTTPException(422, detail=f"batch limit is {MAX_BATCH}")
            key_id, private_key_b64, valid_until = key_store.blind_signer_for(
                req.claim, req.assurance_level, req.epoch
            )
            try:
                signatures = [
                    b64u_encode(blind_sign(private_key_b64, b64u_decode(bm)))
                    for bm in req.blinded_messages
                ]
            except (BlindSignatureError, ValueError) as exc:
                raise HTTPException(422, detail=f"invalid blinded message: {exc}")
        else:
            if not req.nonces:
                raise HTTPException(422, detail="this key requires nonces")
            if len(req.nonces) > MAX_BATCH:
                raise HTTPException(422, detail=f"batch limit is {MAX_BATCH}")
            signer, valid_until = key_store.signer_for(req.claim, req.assurance_level, req.epoch)
            signatures = [b64u_encode(signer.sign(token_message(n))) for n in req.nonces]
            key_id = signer.key_id
        return TokenIssueResponse(
            issuer_id=issuer_id,
            issuer_key_id=key_id,
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

    @app.get("/enroll", response_class=HTMLResponse)
    def enroll_page() -> str:
        # Identity (the DOB) flows only page -> issuer on this origin; the page
        # hands the extension nothing but the opaque enrollment_id.
        return ENROLL_PAGE.replace("__ISSUER_ID__", json.dumps(issuer_id))

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app
