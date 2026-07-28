"""Full OIDC enrollment loop: issuer /enroll redirect -> dev IdP authorize ->
callback -> enrollment -> blind mint -> verifier accepts. The IdP is contacted
only during enrollment; the issuer stores only DOB + expiry."""
import re
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from blindage.crypto import b64u_encode, b64u_decode, blind, finalize
from blindage.crypto.rsabssa import RsabssaTokenVerifier
from blindage.dev_idp.app import create_idp
from blindage.issuer.app import create_app as create_issuer
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.proofing import OidcConfig, OidcProofing
from blindage.issuer.storage import EnrollmentStore
from blindage.schemas import token_message
from tests.conftest import dev_key_entries

IDP_URL = "http://idp.test"
ISSUER_URL = "http://issuer.test"


def _build_pair():
    idp_app = create_idp(
        issuer_url=IDP_URL, client_id="blindage-issuer", client_secret="dev-secret",
        redirect_uri=f"{ISSUER_URL}/oidc/callback",
    )
    idp = TestClient(idp_app, base_url=IDP_URL)
    # The issuer's server-side HTTP client routes straight to the IdP ASGI app.
    # NOTE: httpx.Client(transport=httpx.ASGITransport(...)) is incompatible with the
    # installed httpx/starlette (ASGITransport lacks handle_request for the sync
    # client). fastapi.testclient.TestClient subclasses httpx.Client and is
    # API-compatible for the .get()/.post() calls OidcProofing makes — same
    # substitution documented in tests/conftest.py and tests/unit/test_cli.py.
    idp_http = TestClient(idp_app, base_url=IDP_URL)
    proofing = OidcProofing(
        OidcConfig(
            idp_base_url=IDP_URL, client_id="blindage-issuer",
            client_secret="dev-secret", redirect_uri=f"{ISSUER_URL}/oidc/callback",
        ),
        http=idp_http,
    )
    store = EnrollmentStore(":memory:")
    issuer = TestClient(
        create_issuer(IssuerKeyStore(dev_key_entries()), store, proofing=proofing),
        base_url=ISSUER_URL,
    )
    return idp, issuer, store


def _enroll(idp, issuer, dob="2000-01-01"):
    r = issuer.get("/enroll", follow_redirects=False)
    assert r.status_code in (302, 307)
    authorize_url = r.headers["location"]
    assert authorize_url.startswith(f"{IDP_URL}/authorize?")
    q = parse_qs(urlparse(authorize_url).query)
    page = idp.get("/authorize", params={k: v[0] for k, v in q.items()})
    assert page.status_code == 200 and "SIMULATED" in page.text
    submit = idp.post("/authorize/submit", data={
        "dob": dob, "state": q["state"][0], "nonce": q["nonce"][0],
        "redirect_uri": q["redirect_uri"][0], "code_challenge": q["code_challenge"][0],
        "client_id": q["client_id"][0],
    }, follow_redirects=False)
    assert submit.status_code == 302
    cb = parse_qs(urlparse(submit.headers["location"]).query)
    done = issuer.get("/oidc/callback", params={"code": cb["code"][0], "state": cb["state"][0]})
    assert done.status_code == 200
    # The template embeds a JS object literal with an unquoted key
    # (enrollment_id: "<uuid>") to match ENROLL_PAGE's binding postMessage shape,
    # so tolerate an optionally-quoted key here.
    match = re.search(r'"?enrollment_id"?:\s*"([0-9a-f-]{36})"', done.text)
    assert match, "completion page must embed the enrollment_id for the bridge"
    assert "blindage-page" in done.text and "enrollment" in done.text
    return match.group(1)


def test_oidc_enrollment_then_blind_mint_end_to_end():
    idp, issuer, _ = _build_pair()
    eid = _enroll(idp, issuer)
    wk = issuer.get("/.well-known/blindage-issuer.json").json()
    key = next(k for k in wk["keys"] if k["claim"] == "AGE_OVER_18")
    nonce = b64u_encode(b"x" * 32)
    blinded, inv = blind(key["public_key"], token_message(nonce))
    resp = issuer.post("/v1/tokens/issue", json={
        "version": "1.0", "enrollment_id": eid, "claim": "AGE_OVER_18",
        "assurance_level": "AAL2", "epoch": "2026-Q3",
        "blinded_messages": [b64u_encode(blinded)],
    })
    assert resp.status_code == 200
    sig = finalize(key["public_key"], token_message(nonce),
                   b64u_decode(resp.json()["signatures"][0]), inv)
    assert RsabssaTokenVerifier(key["key_id"], key["public_key"]).verify(
        token_message(nonce), sig)


def test_underage_persona_cannot_mint_over18():
    idp, issuer, _ = _build_pair()
    eid = _enroll(idp, issuer, dob="2010-09-02")
    resp = issuer.post("/v1/tokens/issue", json={
        "version": "1.0", "enrollment_id": eid, "claim": "AGE_OVER_18",
        "assurance_level": "AAL2", "epoch": "2026-Q3", "blinded_messages": ["AA=="],
    })
    assert resp.status_code == 403


def test_state_is_single_use_and_asserted_enrollment_disabled():
    idp, issuer, _ = _build_pair()
    r = issuer.get("/enroll", follow_redirects=False)
    q = parse_qs(urlparse(r.headers["location"]).query)
    submit = idp.post("/authorize/submit", data={
        "dob": "2000-01-01", "state": q["state"][0], "nonce": q["nonce"][0],
        "redirect_uri": q["redirect_uri"][0], "code_challenge": q["code_challenge"][0],
        "client_id": q["client_id"][0],
    }, follow_redirects=False)
    cb = parse_qs(urlparse(submit.headers["location"]).query)
    first = issuer.get("/oidc/callback", params={"code": cb["code"][0], "state": cb["state"][0]})
    assert first.status_code == 200
    replay = issuer.get("/oidc/callback", params={"code": cb["code"][0], "state": cb["state"][0]})
    assert replay.status_code == 400  # state consumed — fail closed
    asserted = issuer.post("/v1/enrollment", json={"date_of_birth": "2000-01-01"})
    assert asserted.status_code == 403  # proofing cannot be bypassed in OIDC mode
