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


def test_transparency_log_and_auditor_end_to_end(stack, tmp_path):
    import json

    from fastapi.testclient import TestClient

    from blindage.registry import generate_root_keypair, sign_registry
    from blindage.transparency.app import create_log_server
    from blindage.transparency.auditor import audit, fetch_history

    w3, account, addrs = stack
    # history: at least the v1 publish from the roundtrip test
    entries = fetch_history(RPC, addrs["anchor"])
    assert entries and entries[-1]["version"] >= 1
    assert entries == sorted(entries, key=lambda e: (e["block_number"],))

    log_client = TestClient(create_log_server(RPC, addrs["anchor"], cache_ttl=0.0))
    served = log_client.get("/log").json()["entries"]
    assert served == entries

    # honest mirror -> PASS  (serve V["registry"] which the anchor holds)
    priv, _pub = generate_root_keypair()
    (tmp_path / "registry.json").write_text(json.dumps(V["registry"]))
    (tmp_path / "registry.sig").write_text(sign_registry(V["registry"], priv))
    import threading

    import uvicorn

    from blindage.registry_mirror.app import create_mirror
    config = uvicorn.Config(create_mirror(tmp_path), port=8791, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    import time as _t
    for _ in range(50):
        try:
            import httpx as _h
            _h.get("http://127.0.0.1:8791/health", timeout=0.2)
            break
        except Exception:
            _t.sleep(0.1)
    try:
        good = audit("http://127.0.0.1:8791", RPC, addrs["anchor"])
        assert good["ok"], good["problems"]

        # tampered mirror -> FAIL with the hash-mismatch reason
        tampered = json.loads(json.dumps(V["registry"]))
        tampered["issuers"] = []
        (tmp_path / "registry.json").write_text(json.dumps(tampered))
        bad = audit("http://127.0.0.1:8791", RPC, addrs["anchor"])
        assert not bad["ok"]
        assert any("does not match the chain head anchor" in p for p in bad["problems"])
    finally:
        server.should_exit = True
        thread.join(timeout=5)

    # mirror down -> FAIL
    down = audit("http://127.0.0.1:8790", RPC, addrs["anchor"])
    assert not down["ok"]
    assert any("mirror registry unreachable" in p for p in down["problems"])


def test_governance_separation_of_duties(anvil):
    """Proposer A schedules; only executor B may execute."""
    from web3 import Web3
    from web3.exceptions import ContractLogicError

    from blindage.registry_chain.anchor import registry_keccak
    from blindage.registry_chain.deploy import _deploy, load_artifact

    w3 = Web3(Web3.HTTPProvider(RPC))
    key_a = DEV_KEY
    key_b = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # anvil #1
    a = w3.eth.account.from_key(key_a)
    b = w3.eth.account.from_key(key_b)
    timelock = _deploy(
        w3, a, load_artifact("TimelockController"),
        [1, [a.address], [b.address], "0x0000000000000000000000000000000000000000"],
    )
    anchor = _deploy(w3, a, load_artifact("RegistryAnchor"), [timelock])
    tl = w3.eth.contract(address=timelock, abi=load_artifact("TimelockController")["abi"])
    # Full compiled ABI so the public version() getter resolves; the minimal
    # REGISTRY_ANCHOR_ABI carries only current()/setAnchor/the event.
    target = w3.eth.contract(address=anchor, abi=load_artifact("RegistryAnchor")["abi"])
    calldata = target.functions.setAnchor(
        registry_keccak(V["registry"]), V["registry"]["generated_at"], 1
    )._encode_transaction_data()
    zero32 = "0x" + "00" * 32

    def send(acct, fn, gas=500_000):
        tx = fn.build_transaction({"from": acct.address, "gas": gas,
                                   "nonce": w3.eth.get_transaction_count(acct.address)})
        signed = acct.sign_transaction(tx)
        return w3.eth.wait_for_transaction_receipt(
            w3.eth.send_raw_transaction(signed.raw_transaction))

    # A schedules (proposer role)
    assert send(a, tl.functions.schedule(anchor, 0, calldata, zero32, zero32, 1)).status == 1
    import time as _t
    _t.sleep(2)
    # A may NOT execute (not an executor). Anvil mines the reverting tx with
    # status 0 under explicit gas; some web3 versions simulate first and raise
    # instead. Either way is a denial — the one thing forbidden is success.
    try:
        assert send(a, tl.functions.execute(anchor, 0, calldata, zero32, zero32)).status == 0
    except (ContractLogicError, ValueError):
        pass
    # B executes (executor role)
    assert send(b, tl.functions.execute(anchor, 0, calldata, zero32, zero32)).status == 1
    assert target.functions.version().call() == 1
