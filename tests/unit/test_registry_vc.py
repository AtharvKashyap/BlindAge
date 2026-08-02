"""Registry integrity for vc_signing keys (Task 4 review fold-in).

Duplicate BBS key material — whether across two vc keys or across a vc key and a
token key — must be rejected, mirroring the token-key material-uniqueness rule.
"""
import copy

import pytest

from blindage.registry import TrustRegistry
from blindage.registry.store import RegistryError
from tests.conftest import dev_issuer_entry


def _reg(issuer_entry: dict) -> dict:
    return {
        "version": "1.0",
        "generated_at": "2026-07-21T00:00:00Z",
        "issuers": [issuer_entry],
    }


def test_duplicate_vc_key_material_rejected():
    entry = copy.deepcopy(dev_issuer_entry())
    vc = next(k for k in entry["keys"] if k["purpose"] == "vc_signing")
    dup = copy.deepcopy(vc)
    dup["key_id"] = vc["key_id"] + "-dup"  # distinct id, same public material
    entry["keys"].append(dup)
    with pytest.raises(RegistryError):
        TrustRegistry.from_dict(_reg(entry))


def test_vc_vs_token_cross_purpose_material_collision_rejected():
    entry = copy.deepcopy(dev_issuer_entry())
    vc = next(k for k in entry["keys"] if k["purpose"] == "vc_signing")
    token = next(k for k in entry["keys"] if k["purpose"] == "token_signing")
    vc["public_key"] = token["public_key"]  # same material across purposes
    with pytest.raises(RegistryError):
        TrustRegistry.from_dict(_reg(entry))
