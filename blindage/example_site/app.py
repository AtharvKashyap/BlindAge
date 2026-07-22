from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from blindage.registry import TrustRegistry
from blindage.schemas import (
    AgeClaim,
    AssuranceLevel,
    Presentation,
    VerifierPolicy,
)
from blindage.verifier import BlindAgeVerifier, ChallengeManager, ReplayCache

_LANDING_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>BlindAge Demo Site</title>
<style>body{font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
a.button{display:inline-block;padding:.6rem 1rem;background:#2b6cb0;color:#fff;border-radius:.4rem;text-decoration:none}</style>
</head><body>
<h1>BlindAge Demo Site</h1>
<p>This page is public. The content behind the age gate requires proof of
<strong>AGE_OVER_18</strong> — but this site never learns who you are.</p>
<p><a class="button" href="/protected">Enter age-restricted area</a></p>
</body></html>"""

_PROTECTED_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Age-gated area — BlindAge</title>
<style>body{font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
#status{padding:1rem;border-radius:.4rem;background:#edf2f7}
#content{display:none;padding:1rem;border-radius:.4rem;background:#c6f6d5}
textarea{width:100%;height:6rem}</style>
</head><body>
<h1>Age-restricted area</h1>
<div id="status">Requesting age proof… waiting for the BlindAge extension.</div>
<div id="content"><h2>🔓 Access granted</h2><p>You proved you are old enough — and this
site learned nothing else about you.</p></div>
<details><summary>No extension? Paste a presentation manually</summary>
<p>Run <code>blindage prove</code> against the challenge below, then paste the presentation.</p>
<pre id="challenge"></pre>
<textarea id="manual"></textarea><button id="submit">Submit presentation</button></details>
<script>
let currentChallenge = null;
async function getChallenge() {
  const r = await fetch("/api/challenge", {method: "POST"});
  currentChallenge = await r.json();
  document.getElementById("challenge").textContent = JSON.stringify(currentChallenge, null, 2);
  // Announce the request to the BlindAge extension content script.
  window.postMessage({source: "blindage-page", kind: "request", challenge: currentChallenge}, "*");
}
async function redeem(presentation) {
  const r = await fetch("/api/redeem", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(presentation),
  });
  const body = await r.json();
  if (r.ok && body.decision === "ALLOW") {
    document.getElementById("status").style.display = "none";
    document.getElementById("content").style.display = "block";
  } else {
    document.getElementById("status").textContent = "Access denied: " + JSON.stringify(body.decision);
  }
}
window.addEventListener("message", (e) => {
  const d = e.data || {};
  if (d.source === "blindage-ext" && d.kind === "presentation") redeem(d.presentation);
});
document.getElementById("submit").addEventListener("click", () => {
  redeem(JSON.parse(document.getElementById("manual").value));
});
getChallenge();
</script>
</body></html>"""


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

    @app.get("/", response_class=HTMLResponse)
    def landing() -> str:
        return _LANDING_HTML

    @app.get("/protected", response_class=HTMLResponse)
    def protected() -> str:
        return _PROTECTED_HTML

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
