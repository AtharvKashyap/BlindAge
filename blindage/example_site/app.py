from fastapi import FastAPI
from fastapi.responses import JSONResponse

from blindage.registry import TrustRegistry
from blindage.schemas import (
    AgeClaim,
    AssuranceLevel,
    Presentation,
    VerifierPolicy,
)
from blindage.verifier import BlindAgeVerifier, ChallengeManager, ReplayCache


def create_site(
    registry: TrustRegistry, trusted_issuer: str, audience: str = "localhost"
) -> FastAPI:
    app = FastAPI(title="BlindAge Example Age-Gated Site")
    policy = VerifierPolicy(
        policy_id="example-age18",
        required_claim=AgeClaim.AGE_OVER_18,
        minimum_assurance_level=AssuranceLevel.AAL2,
        trusted_issuers=[trusted_issuer],
    )
    challenges = ChallengeManager(audience=audience)
    verifier = BlindAgeVerifier(
        registry=registry,
        policy=policy,
        replay_cache=ReplayCache(":memory:"),
        challenge_manager=challenges,
        audience=audience,
    )

    @app.get("/")
    def landing() -> dict:
        return {"page": "landing", "age_gate": "/api/challenge"}

    @app.post("/api/challenge")
    def challenge() -> dict:
        ch = challenges.create(policy.required_claim, policy.minimum_assurance_level)
        return ch.model_dump(mode="json")

    @app.post("/api/redeem")
    def redeem(presentation: Presentation) -> JSONResponse:
        decision = verifier.verify(presentation)
        status = 200 if decision.valid else 403
        return JSONResponse(
            status_code=status,
            content={
                "decision": decision.decision.value,
                "detail": decision.model_dump(mode="json"),
            },
        )

    return app
