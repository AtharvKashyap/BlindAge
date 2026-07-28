from datetime import date
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from blindage.dev_idp.app import create_idp
from blindage.issuer.proofing import ProofingError, code_challenge_s256, validate_id_token

ISS = "http://idp.test"
CLIENT, SECRET = "blindage-issuer", "dev-secret"
REDIRECT = "http://localhost:8400/oidc/callback"
VERIFIER = "v" * 48


@pytest.fixture()
def idp():
    return TestClient(
        create_idp(issuer_url=ISS, client_id=CLIENT, client_secret=SECRET, redirect_uri=REDIRECT)
    )


def _get_code(idp, dob="2000-01-01", state="st-1", nonce="n-1"):
    page = idp.get("/authorize", params={
        "response_type": "code", "client_id": CLIENT, "redirect_uri": REDIRECT,
        "scope": "openid", "state": state, "nonce": nonce,
        "code_challenge": code_challenge_s256(VERIFIER), "code_challenge_method": "S256",
    })
    assert page.status_code == 200
    assert "SIMULATED" in page.text and "TEST ONLY" in page.text
    resp = idp.post("/authorize/submit", data={
        "dob": dob, "state": state, "nonce": nonce, "redirect_uri": REDIRECT,
        "code_challenge": code_challenge_s256(VERIFIER), "client_id": CLIENT,
    }, follow_redirects=False)
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["state"] == [state]
    return q["code"][0]


def _exchange(idp, code, verifier=VERIFIER, secret=SECRET):
    return idp.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": CLIENT, "client_secret": secret, "code_verifier": verifier,
    })


def test_discovery_document_shape(idp):
    doc = idp.get("/.well-known/openid-configuration").json()
    assert doc["issuer"] == ISS
    assert doc["authorization_endpoint"] == f"{ISS}/authorize"
    assert doc["token_endpoint"] == f"{ISS}/token"
    assert doc["jwks_uri"] == f"{ISS}/jwks.json"
    assert doc["id_token_signing_alg_values_supported"] == ["RS256"]
    assert doc["code_challenge_methods_supported"] == ["S256"]


def test_full_code_flow_yields_valid_id_token(idp):
    code = _get_code(idp)
    resp = _exchange(idp, code)
    assert resp.status_code == 200
    jwks = idp.get("/jwks.json").json()
    dob = validate_id_token(
        resp.json()["id_token"], jwks, issuer=ISS, audience=CLIENT, nonce="n-1"
    )
    assert dob == date(2000, 1, 1)


def test_random_sub_per_authorization(idp):
    import jwt as pyjwt
    subs = set()
    for i in range(2):
        code = _get_code(idp, state=f"st-{i}", nonce=f"n-{i}")
        tok = _exchange(idp, code).json()["id_token"]
        subs.add(pyjwt.decode(tok, options={"verify_signature": False})["sub"])
    assert len(subs) == 2  # no stable identity in the simulation


def test_code_is_single_use(idp):
    code = _get_code(idp)
    assert _exchange(idp, code).status_code == 200
    assert _exchange(idp, code).status_code == 400


def test_wrong_verifier_and_wrong_secret_rejected(idp):
    assert _exchange(idp, _get_code(idp, state="a", nonce="na"), verifier="x" * 48).status_code == 400
    assert _exchange(idp, _get_code(idp, state="b", nonce="nb"), secret="wrong").status_code == 401


def test_authorize_rejects_wrong_client_or_redirect(idp):
    base = {
        "response_type": "code", "client_id": CLIENT, "redirect_uri": REDIRECT,
        "scope": "openid", "state": "s", "nonce": "n",
        "code_challenge": code_challenge_s256(VERIFIER), "code_challenge_method": "S256",
    }
    assert idp.get("/authorize", params={**base, "client_id": "evil"}).status_code == 400
    assert idp.get("/authorize", params={**base, "redirect_uri": "http://evil.test/cb"}).status_code == 400
    assert idp.get("/authorize", params={**base, "code_challenge_method": "plain"}).status_code == 400
