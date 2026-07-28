"""SIMULATED OIDC identity provider — TEST ONLY.

Exercises the real Authorization Code + PKCE machinery (discovery, authorize,
code exchange, RS256 ID tokens with a birthdate claim) without real identity
documents, per the protocol spec's testing rule. Every page says so. The `sub`
claim is random per authorization: even the simulation has no stable identity.
"""
import html
import json
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from blindage.issuer.proofing import code_challenge_s256

KID = "dev-idp-1"
CODE_TTL_SECONDS = 300
ID_TOKEN_TTL_SECONDS = 300

LOGIN_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Dev IdP — SIMULATED, TEST ONLY</title>
<style>body{font-family:system-ui;max-width:30rem;margin:3rem auto;padding:0 1rem}
.warn{background:#fff5f5;border:1px solid #c53030;border-radius:.4rem;padding:.6rem}
button{margin:.2rem;padding:.5rem .8rem;border:0;border-radius:.3rem;background:#2b6cb0;color:#fff}</style>
</head><body>
<h1>Dev Identity Provider</h1>
<p class="warn"><strong>SIMULATED — TEST ONLY.</strong> This pretends to be a bank/eID
login. It verifies nothing. Pick a persona or enter any date of birth.</p>
<form method="post" action="/authorize/submit">
__HIDDEN__
<p><label>Date of birth <input type="date" name="dob" value="1988-05-14" required></label></p>
<p><button type="submit">Continue as entered DOB</button></p>
</form>
<form method="post" action="/authorize/submit">__HIDDEN__
<button type="submit" name="dob" value="1988-05-14">Adult (1988-05-14)</button>
<button type="submit" name="dob" value="2010-09-02">Teen (2010-09-02)</button>
<button type="submit" name="dob" value="__ADULT_TODAY__">Turned 18 today</button>
</form>
</body></html>"""


def create_idp(
    issuer_url: str = "http://localhost:8600",
    client_id: str = "blindage-issuer",
    client_secret: str = "dev-secret",
    redirect_uri: str = "http://localhost:8400/oidc/callback",
    private_key_pem: bytes | None = None,
) -> FastAPI:
    if private_key_pem is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    else:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})

    codes: dict[str, dict] = {}  # code -> {nonce, code_challenge, birthdate, created_at}
    lock = threading.Lock()
    app = FastAPI(title="BlindAge Dev IdP (SIMULATED — TEST ONLY)")
    app.state.client_id = client_id
    app.state.client_secret = client_secret
    app.state.redirect_uri = redirect_uri

    @app.get("/.well-known/openid-configuration")
    def discovery() -> dict:
        return {
            "issuer": issuer_url,
            "authorization_endpoint": f"{issuer_url}/authorize",
            "token_endpoint": f"{issuer_url}/token",
            "jwks_uri": f"{issuer_url}/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid"],
        }

    @app.get("/jwks.json")
    def jwks() -> dict:
        return {"keys": [jwk]}

    @app.get("/authorize", response_class=HTMLResponse)
    def authorize(
        response_type: str,
        client_id: str,      # noqa: A002 - OIDC parameter names are fixed
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
        code_challenge_method: str,
        scope: str = "openid",
    ) -> str:
        if response_type != "code":
            raise HTTPException(400, detail="response_type must be code")
        if client_id != app.state.client_id:
            raise HTTPException(400, detail="unknown client_id")
        if redirect_uri != app.state.redirect_uri:
            raise HTTPException(400, detail="redirect_uri not registered")
        if code_challenge_method != "S256" or not code_challenge:
            raise HTTPException(400, detail="PKCE S256 required")
        hidden = "".join(
            f'<input type="hidden" name="{name}" value="{html.escape(value, quote=True)}">'
            for name, value in [
                ("state", state), ("nonce", nonce), ("redirect_uri", redirect_uri),
                ("code_challenge", code_challenge), ("client_id", client_id),
            ]
        )
        adult_today = (
            datetime.now(timezone.utc) - timedelta(days=18 * 365 + 5)
        ).date().isoformat()
        return LOGIN_PAGE.replace("__HIDDEN__", hidden).replace("__ADULT_TODAY__", adult_today)

    @app.post("/authorize/submit")
    def authorize_submit(
        dob: str = Form(...),
        state: str = Form(...),
        nonce: str = Form(...),
        redirect_uri: str = Form(...),
        code_challenge: str = Form(...),
        client_id: str = Form(...),
    ) -> RedirectResponse:
        if client_id != app.state.client_id or redirect_uri != app.state.redirect_uri:
            raise HTTPException(400, detail="unknown client or redirect_uri")
        try:
            datetime.fromisoformat(dob)
        except ValueError:
            raise HTTPException(400, detail="invalid date of birth")
        code = str(uuid.uuid4())
        with lock:
            codes[code] = {
                "nonce": nonce, "code_challenge": code_challenge,
                "birthdate": dob, "created_at": time.time(),
            }
        return RedirectResponse(f"{redirect_uri}?code={code}&state={state}", status_code=302)

    @app.post("/token")
    def token(
        grant_type: str = Form(...),
        code: str = Form(...),
        redirect_uri: str = Form(...),
        client_id: str = Form(...),
        client_secret: str = Form(...),
        code_verifier: str = Form(...),
    ) -> dict:
        if client_id != app.state.client_id or client_secret != app.state.client_secret:
            raise HTTPException(401, detail="bad client credentials")
        if grant_type != "authorization_code" or redirect_uri != app.state.redirect_uri:
            raise HTTPException(400, detail="bad grant")
        with lock:
            record = codes.pop(code, None)  # single-use
        if record is None or time.time() - record["created_at"] > CODE_TTL_SECONDS:
            raise HTTPException(400, detail="unknown, used, or expired code")
        if code_challenge_s256(code_verifier) != record["code_challenge"]:
            raise HTTPException(400, detail="PKCE verification failed")
        now = datetime.now(timezone.utc)
        id_token = jwt.encode(
            {
                "iss": issuer_url,
                "sub": str(uuid.uuid4()),  # random per authorization: no stable identity
                "aud": client_id,
                "iat": now,
                "exp": now + timedelta(seconds=ID_TOKEN_TTL_SECONDS),
                "nonce": record["nonce"],
                "birthdate": record["birthdate"],
            },
            private_key_pem, algorithm="RS256", headers={"kid": KID},
        )
        return {"access_token": "dev-access-token", "token_type": "Bearer", "id_token": id_token}

    return app
