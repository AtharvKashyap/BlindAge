"""End-to-end against a local anvil chain. Self-skips when Foundry is absent."""
import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("anvil") is None or shutil.which("forge") is None,
    reason="Foundry (anvil/forge) not installed",
)

REPO = Path(__file__).parents[2]
V = json.loads((REPO / "tests" / "vectors" / "registry_signing.json").read_text())
RPC = "http://127.0.0.1:8545"
# anvil's deterministic account #0
DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


@pytest.fixture(scope="module")
def anvil():
    subprocess.run(["forge", "build"], cwd=REPO / "registry" / "contracts", check=True)
    proc = subprocess.Popen(
        ["anvil", "--port", "8545", "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", 8545), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            proc.kill()
            pytest.fail("anvil did not start")
        yield RPC
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="module")
def stack(anvil):
    from web3 import Web3
    from blindage.registry_chain.deploy import deploy_anchor_stack

    w3 = Web3(Web3.HTTPProvider(anvil))
    account = w3.eth.account.from_key(DEV_KEY)
    addrs = deploy_anchor_stack(w3, account, min_delay=1)
    return w3, account, addrs


def test_publish_and_read_roundtrip(stack):
    from blindage.registry_chain.anchor import AnchorClient, registry_keccak
    from blindage.registry_chain.publish import publish_anchor

    w3, account, addrs = stack
    publish_anchor(
        w3, account, addrs["anchor"], addrs["timelock"], V["registry"],
        version=1, delay=1,
    )
    client = AnchorClient(RPC, addrs["anchor"], cache_ttl=0.0)
    cur = client.current()
    assert cur["registry_hash"] == registry_keccak(V["registry"])
    assert cur["generated_at"] == V["registry"]["generated_at"]
    assert cur["version"] == 1


def test_publisher_rejects_non_monotonic(stack):
    from blindage.registry_chain.publish import publish_anchor

    w3, account, addrs = stack
    with pytest.raises(ValueError):
        publish_anchor(  # same version as the roundtrip test → pre-check refuses
            w3, account, addrs["anchor"], addrs["timelock"], V["registry"],
            version=1, delay=1,
        )


def test_mirror_and_verifier_against_live_anchor(stack, tmp_path):
    from fastapi.testclient import TestClient

    from blindage.registry import TrustRegistry, generate_root_keypair, sign_registry
    from blindage.registry_chain.anchor import AnchorClient
    from blindage.registry_mirror.app import create_mirror

    w3, account, addrs = stack  # anchor already holds V["registry"] from the roundtrip test
    priv, pub = generate_root_keypair()
    (tmp_path / "registry.json").write_text(json.dumps(V["registry"]))
    (tmp_path / "registry.sig").write_text(sign_registry(V["registry"], priv))
    client = AnchorClient(RPC, addrs["anchor"], cache_ttl=0.0)

    mirror = TestClient(create_mirror(tmp_path, anchor=client))
    assert mirror.get("/registry.json").status_code == 200

    reg = TrustRegistry.load(
        tmp_path / "registry.json", tmp_path / "registry.sig", pub, anchor=client
    )
    assert reg.get_issuer("did:web:issuer.test") is not None
