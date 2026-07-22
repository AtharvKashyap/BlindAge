from fastapi.testclient import TestClient

from blindage.example_site.app import create_site
from tests.conftest import ISSUER_ID, dev_registry


def make_site() -> TestClient:
    return TestClient(create_site(dev_registry(), trusted_issuer=ISSUER_ID, audience="localhost"))


def test_landing_is_html():
    resp = make_site().get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "BlindAge" in resp.text


def test_protected_page_is_html_and_wires_the_bridge():
    resp = make_site().get("/protected")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    # The page must talk the extension bridge protocol and hit the JSON API.
    assert "blindage-page" in resp.text
    assert "blindage-ext" in resp.text
    assert "/api/challenge" in resp.text
    assert "/api/redeem" in resp.text


def test_challenge_and_redeem_json_api_still_work():
    site = make_site()
    ch = site.post("/api/challenge")
    assert ch.status_code == 200
    assert ch.json()["required_claim"] == "AGE_OVER_18"
