"""Independent transparency auditor: mirror ↔ chain consistency (public data only).

Fail closed: any unreachable dependency or inconsistency is a FAIL with a
distinct problem string — an auditor that skips is an auditor that lies.
"""
import argparse
import json

import httpx

from blindage.canonical import canonical_json_bytes
from blindage.registry_chain.anchor import AnchorClient, AnchorError, registry_keccak


def check_history(entries: list[dict]) -> list[str]:
    problems: list[str] = []
    for prev, cur in zip(entries, entries[1:]):
        if cur["version"] <= prev["version"]:
            problems.append(
                f"history version rollback: {prev['version']} -> {cur['version']}"
            )
        if cur["generated_at"] <= prev["generated_at"]:
            problems.append(
                "history generated_at rollback: "
                f"{prev['generated_at']!r} -> {cur['generated_at']!r}"
            )
    return problems


def fetch_history(rpc_url: str, contract_address: str) -> list[dict]:
    """AnchorUpdated events ordered by (block, log index)."""
    from web3 import Web3

    from blindage.registry_chain.anchor import REGISTRY_ANCHOR_ABI

    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address), abi=REGISTRY_ANCHOR_ABI
    )
    logs = contract.events.AnchorUpdated().get_logs(from_block=0)
    entries = sorted(logs, key=lambda l: (l["blockNumber"], l["logIndex"]))
    return [
        {
            "version": int(l["args"]["version"]),
            "generated_at": l["args"]["generatedAt"],
            "registry_hash": bytes(l["args"]["registryHash"]).hex(),
            "block_number": int(l["blockNumber"]),
            "tx_hash": l["transactionHash"].hex(),
        }
        for l in entries
    ]


def audit(mirror_url: str, rpc_url: str, contract_address: str) -> dict:
    problems: list[str] = []
    head = None
    entries: list[dict] = []
    try:
        head = AnchorClient(rpc_url, contract_address, cache_ttl=0.0).current()
    except AnchorError as exc:
        problems.append(f"chain head unreachable: {exc}")
    try:
        entries = fetch_history(rpc_url, contract_address)
    except Exception as exc:
        problems.append(f"event history unreachable: {exc}")
    if entries:
        problems += check_history(entries)
    if head is not None and entries:
        last = entries[-1]
        if (last["version"] != head["version"]
                or last["registry_hash"] != head["registry_hash"].hex()):
            problems.append("chain head does not match the last logged event")
    registry = None
    try:
        resp = httpx.get(f"{mirror_url}/registry.json", timeout=5)
        resp.raise_for_status()
        registry = json.loads(resp.text)
    except Exception as exc:
        problems.append(f"mirror registry unreachable: {exc}")
    if registry is not None and head is not None:
        if registry_keccak(registry) != head["registry_hash"]:
            problems.append("mirror registry does not match the chain head anchor")
        if registry.get("generated_at") != head["generated_at"]:
            problems.append("mirror registry generated_at does not match the chain head")
    return {"ok": not problems, "problems": problems, "head": head}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mirror", required=True)
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--contract", required=True)
    args = parser.parse_args()
    result = audit(args.mirror, args.rpc, args.contract)
    if result["ok"]:
        print(f"PASS (head version {result['head']['version']})")
        return 0
    print("FAIL:")
    for problem in result["problems"]:
        print(f"  - {problem}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
