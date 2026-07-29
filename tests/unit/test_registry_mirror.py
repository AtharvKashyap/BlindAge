from fastapi.testclient import TestClient

from blindage.registry import TrustRegistry
from blindage.registry_mirror.app import create_mirror


def _mirror(tmp_path, write=True):
    if write:
        (tmp_path / "registry.json").write_text('{"version": "1.0"}')
        (tmp_path / "registry.sig").write_text("c2ln\n")
    return TestClient(create_mirror(tmp_path))


def test_mirror_serves_registry_and_sig_raw(tmp_path):
    client = _mirror(tmp_path)
    reg = client.get("/registry.json")
    assert reg.status_code == 200
    assert reg.headers["content-type"].startswith("application/json")
    assert reg.text == '{"version": "1.0"}'  # raw passthrough, no re-serialization
    sig = client.get("/registry.sig")
    assert sig.status_code == 200
    assert sig.headers["content-type"].startswith("text/plain")
    assert sig.text == "c2ln\n"
    assert client.get("/health").json() == {"status": "ok"}


def test_mirror_404s_when_files_missing(tmp_path):
    client = _mirror(tmp_path, write=False)
    assert client.get("/registry.json").status_code == 404
    assert client.get("/registry.sig").status_code == 404


def test_endpoint_field_accepted_and_optional():
    from tests.conftest import dev_issuer_entry

    entry = dev_issuer_entry()
    assert entry["endpoint"] == "http://localhost:8400"
    reg = TrustRegistry.from_dict(
        {"version": "1.0", "generated_at": "2026-07-29T00:00:00Z", "issuers": [entry]}
    )
    assert reg.get_issuer("did:web:issuer.test").endpoint == "http://localhost:8400"
    # endpoint is optional — an entry without it must still validate
    no_endpoint = {k: v for k, v in dev_issuer_entry().items() if k != "endpoint"}
    reg2 = TrustRegistry.from_dict(
        {"version": "1.0", "generated_at": "2026-07-29T00:00:00Z", "issuers": [no_endpoint]}
    )
    assert reg2.get_issuer("did:web:issuer.test").endpoint is None
