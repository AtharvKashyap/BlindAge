"""Anchor a registry on-chain through the timelock (schedule -> execute)."""
import json
import time
from pathlib import Path

from blindage.registry_chain.anchor import (
    REGISTRY_ANCHOR_ABI, AnchorClient, registry_keccak,
)
from blindage.registry_chain.deploy import load_artifact

ZERO32 = "0x" + "00" * 32


def _raw(signed):
    # web3 v7: raw_transaction; v6: rawTransaction.
    return getattr(signed, "raw_transaction", None) or signed.rawTransaction


def _send(w3, account, contract_fn) -> dict:
    # Explicit gas skips eth_estimateGas: on anvil the estimate call runs
    # against a block whose timestamp has not advanced past the timelock's
    # ready-time, so it would revert even though the mined tx (at real-clock
    # time) succeeds. A generous fixed limit avoids that false negative.
    tx = contract_fn.build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 500_000,
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(_raw(signed))
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise RuntimeError(f"transaction reverted: {tx_hash.hex()}")
    return receipt


def publish_anchor(w3, account, anchor_address, timelock_address, registry_dict,
                   *, version: int, delay: int = 1):
    current = AnchorClient(
        w3.provider.endpoint_uri, anchor_address, cache_ttl=0.0
    ).current()
    generated_at = registry_dict["generated_at"]
    if version <= current["version"] or generated_at <= current["generated_at"]:
        raise ValueError(
            f"non-monotonic anchor: version {version} <= {current['version']} "
            f"or generated_at {generated_at!r} <= {current['generated_at']!r}"
        )
    anchor = w3.eth.contract(
        address=w3.to_checksum_address(anchor_address), abi=REGISTRY_ANCHOR_ABI
    )
    calldata = anchor.functions.setAnchor(
        registry_keccak(registry_dict), generated_at, version
    )._encode_transaction_data()
    timelock = w3.eth.contract(
        address=w3.to_checksum_address(timelock_address),
        abi=load_artifact("TimelockController")["abi"],
    )
    salt = "0x" + version.to_bytes(32, "big").hex()
    _send(w3, account, timelock.functions.schedule(
        anchor_address, 0, calldata, ZERO32, salt, delay))
    time.sleep(delay + 1)
    return _send(w3, account, timelock.functions.execute(
        anchor_address, 0, calldata, ZERO32, salt))


def main() -> None:
    from web3 import Web3

    registry = json.loads(Path("config/dev/registry.json").read_text())
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    account = w3.eth.account.from_key(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )  # anvil dev account 0 — DEV ONLY
    from blindage.registry_chain.deploy import deploy_anchor_stack

    addrs = deploy_anchor_stack(w3, account, min_delay=1)
    publish_anchor(w3, account, addrs["anchor"], addrs["timelock"], registry,
                   version=1, delay=1)
    print(json.dumps(addrs))


if __name__ == "__main__":
    main()
