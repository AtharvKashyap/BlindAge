import json

import pytest
from fastapi.testclient import TestClient

from blindage.registry import RegistryError, TrustRegistry
from blindage.registry_chain.anchor import AnchorError, registry_keccak
from blindage.registry_mirror.app import create_mirror
from blindage.registry import generate_root_keypair, sign_registry
from tests.conftest import dev_issuer_entry


def _registry_dict():
    return {"version": "1.0", "generated_at": "2026-07-30T00:00:00Z",
            "issuers": [dev_issuer_entry()]}


class FakeAnchor:
    def __init__(self, registry_hash):
        self._h = registry_hash

    def current(self):
        return {"registry_hash": self._h, "generated_at": "g", "version": 1,
                "updated_at": 0}


class DownAnchor:
    def current(self):
        raise AnchorError("rpc down")


def _write(tmp_path, reg):
    priv, pub = generate_root_keypair()
    (tmp_path / "registry.json").write_text(json.dumps(reg))
    (tmp_path / "registry.sig").write_text(sign_registry(reg, priv))
    return pub


def test_mirror_serves_when_anchor_matches(tmp_path):
    reg = _registry_dict()
    _write(tmp_path, reg)
    client = TestClient(create_mirror(tmp_path, anchor=FakeAnchor(registry_keccak(reg))))
    assert client.get("/registry.json").status_code == 200


def test_mirror_503_on_mismatch_and_rpc_failure(tmp_path):
    reg = _registry_dict()
    _write(tmp_path, reg)
    mismatch = TestClient(create_mirror(tmp_path, anchor=FakeAnchor(b"\x00" * 32)))
    assert mismatch.get("/registry.json").status_code == 503
    down = TestClient(create_mirror(tmp_path, anchor=DownAnchor()))
    assert down.get("/registry.json").status_code == 503
    # the signature file is anchor-independent
    assert mismatch.get("/registry.sig").status_code == 200


def test_mirror_without_anchor_unchanged(tmp_path):
    _write(tmp_path, _registry_dict())
    client = TestClient(create_mirror(tmp_path))
    assert client.get("/registry.json").status_code == 200


def test_trust_registry_load_anchor_gate(tmp_path):
    reg = _registry_dict()
    pub = _write(tmp_path, reg)
    ok = TrustRegistry.load(
        tmp_path / "registry.json", tmp_path / "registry.sig", pub,
        anchor=FakeAnchor(registry_keccak(reg)),
    )
    assert ok.get_issuer("did:web:issuer.test") is not None
    with pytest.raises(RegistryError):
        TrustRegistry.load(tmp_path / "registry.json", tmp_path / "registry.sig",
                           pub, anchor=FakeAnchor(b"\x00" * 32))
    with pytest.raises(RegistryError):
        TrustRegistry.load(tmp_path / "registry.json", tmp_path / "registry.sig",
                           pub, anchor=DownAnchor())
