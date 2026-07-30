"""Deploy the timelock + anchor stack from Foundry artifacts (dev/test only)."""
import json
from pathlib import Path

CONTRACTS_OUT = Path(__file__).parents[2] / "registry" / "contracts" / "out"


def load_artifact(name: str) -> dict:
    path = CONTRACTS_OUT / f"{name}.sol" / f"{name}.json"
    data = json.loads(path.read_text())
    return {"abi": data["abi"], "bytecode": data["bytecode"]["object"]}


def _raw(signed):
    # web3 v7: raw_transaction; v6: rawTransaction.
    return getattr(signed, "raw_transaction", None) or signed.rawTransaction


def _deploy(w3, account, artifact: dict, args: list) -> str:
    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    tx = contract.constructor(*args).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(_raw(signed))
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt.contractAddress


def deploy_anchor_stack(w3, account, min_delay: int = 1) -> dict:
    timelock = _deploy(
        w3, account, load_artifact("TimelockController"),
        [min_delay, [account.address], [account.address],
         "0x0000000000000000000000000000000000000000"],
    )
    anchor = _deploy(w3, account, load_artifact("RegistryAnchor"), [timelock])
    return {"timelock": timelock, "anchor": anchor}
