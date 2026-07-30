"""Read-side chain anchor for the trust registry.

The chain holds ONLY public registry metadata (constitution rule 3): the
keccak256 of the registry's canonical JSON, generated_at, version, updated_at.
keccak comes from web3 (NOT hashlib.sha3_256 — different padding). AnchorClient
caches reads: never a per-request chain query (spec §6).
"""
import threading
import time
from typing import Any

from web3 import Web3

from blindage.canonical import canonical_json_bytes

REGISTRY_ANCHOR_ABI: list[dict[str, Any]] = [
    {
        "type": "function", "name": "current", "stateMutability": "view",
        "inputs": [],
        "outputs": [
            {"name": "", "type": "bytes32"},
            {"name": "", "type": "string"},
            {"name": "", "type": "uint64"},
            {"name": "", "type": "uint64"},
        ],
    },
    {
        "type": "function", "name": "setAnchor", "stateMutability": "nonpayable",
        "inputs": [
            {"name": "newHash", "type": "bytes32"},
            {"name": "newGeneratedAt", "type": "string"},
            {"name": "newVersion", "type": "uint64"},
        ],
        "outputs": [],
    },
    {
        "type": "event", "name": "AnchorUpdated",
        "inputs": [
            {"name": "registryHash", "type": "bytes32", "indexed": False},
            {"name": "generatedAt", "type": "string", "indexed": False},
            {"name": "version", "type": "uint64", "indexed": False},
        ],
        "anonymous": False,
    },
]


class AnchorError(Exception):
    pass


def registry_keccak(registry_dict: dict) -> bytes:
    return bytes(Web3.keccak(canonical_json_bytes(registry_dict)))


class AnchorClient:
    """Read-only, cached view of the on-chain anchor. Fail closed: any RPC or
    contract failure raises AnchorError."""

    def __init__(self, rpc_url: str, contract_address: str, cache_ttl: float = 30.0):
        self._rpc_url = rpc_url
        self._address = contract_address
        self._ttl = cache_ttl
        self._lock = threading.Lock()
        self._cached: dict | None = None
        self._cached_at = 0.0

    def _fetch(self) -> dict:
        try:
            w3 = Web3(Web3.HTTPProvider(self._rpc_url, request_kwargs={"timeout": 5}))
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(self._address),
                abi=REGISTRY_ANCHOR_ABI,
            )
            h, generated_at, version, updated_at = contract.functions.current().call()
            return {
                "registry_hash": bytes(h),
                "generated_at": generated_at,
                "version": int(version),
                "updated_at": int(updated_at),
            }
        except AnchorError:
            raise
        except Exception as exc:  # fail closed on any RPC/contract error
            raise AnchorError(f"anchor read failed: {exc}") from exc

    def current(self) -> dict:
        with self._lock:
            now = time.monotonic()
            if self._cached is not None and now - self._cached_at < self._ttl:
                return self._cached
            fetched = self._fetch()
            self._cached = fetched
            self._cached_at = time.monotonic()
            return fetched
