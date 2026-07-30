import json
import time
from pathlib import Path

import pytest

from blindage.canonical import canonical_json_bytes
from blindage.registry_chain.anchor import (
    REGISTRY_ANCHOR_ABI, AnchorClient, AnchorError, registry_keccak,
)

V = json.loads(
    (Path(__file__).parents[1] / "vectors" / "registry_signing.json").read_text()
)


def test_registry_keccak_is_keccak_of_canonical_bytes():
    from web3 import Web3

    expected = Web3.keccak(bytes.fromhex(V["canonical_hex"]))
    assert registry_keccak(V["registry"]) == bytes(expected)
    assert len(registry_keccak(V["registry"])) == 32


def test_registry_keccak_differs_from_sha3_256():
    # keccak256 != NIST SHA3-256 (different padding); guard against the classic mixup.
    import hashlib

    assert registry_keccak(V["registry"]) != hashlib.sha3_256(
        canonical_json_bytes(V["registry"])
    ).digest()


def test_abi_exposes_only_anchor_fields():
    """Constitution rule 3: the chain interface carries only public registry
    metadata — hash, generated_at, version, updated_at, and events over them."""
    allowed_functions = {
        "setAnchor", "current", "registryHash", "generatedAt", "version",
        "updatedAt", "timelock",
    }
    names = {e["name"] for e in REGISTRY_ANCHOR_ABI if e["type"] == "function"}
    assert names <= allowed_functions
    events = {e["name"] for e in REGISTRY_ANCHOR_ABI if e["type"] == "event"}
    assert events <= {"AnchorUpdated"}
    banned = {"identity", "dob", "birth", "token", "nonce", "domain", "ip",
              "email", "name_", "user"}
    flat = json.dumps(REGISTRY_ANCHOR_ABI).lower()
    assert not any(b in flat for b in banned)


def test_anchor_client_raises_anchor_error_when_rpc_down():
    client = AnchorClient("http://127.0.0.1:1", "0x" + "11" * 20, cache_ttl=0.0)
    with pytest.raises(AnchorError):
        client.current()


def test_anchor_client_caches(monkeypatch):
    client = AnchorClient("http://127.0.0.1:1", "0x" + "11" * 20, cache_ttl=60.0)
    calls = {"n": 0}

    def fake_fetch():
        calls["n"] += 1
        return {"registry_hash": b"\x00" * 32, "generated_at": "g",
                "version": 1, "updated_at": 2}

    monkeypatch.setattr(client, "_fetch", fake_fetch)
    assert client.current() == client.current()
    assert calls["n"] == 1
