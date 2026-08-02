import json
from pathlib import Path

V = json.loads(
    (Path(__file__).parents[1] / "vectors" / "bbs_bls12381_sha256.json").read_text()
)


def test_vector_file_shape():
    assert len(V["keypair"]["public_key"]) == 192  # 96-byte G2 point, hex
    assert len(V["signatures"]) >= 5
    assert any(c["valid"] for c in V["signatures"])
    assert any(not c["valid"] for c in V["signatures"])
    assert len(V["proofs"]) >= 5
    assert any(c["valid"] for c in V["proofs"])
    for c in V["signatures"]:
        bytes.fromhex(c["signature"])
        for m in c["messages"]:
            bytes.fromhex(m)
