import json
from pathlib import Path

from blindage.canonical import canonical_json_bytes
from blindage.registry import verify_registry_signature

V = json.loads(
    (Path(__file__).parents[1] / "vectors" / "registry_signing.json").read_text()
)


def test_vector_canonical_bytes_match():
    assert canonical_json_bytes(V["registry"]).hex() == V["canonical_hex"]


def test_vector_signature_verifies():
    assert verify_registry_signature(
        V["registry"], V["signature_b64"], V["root_public_key_b64"]
    )
