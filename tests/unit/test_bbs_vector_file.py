import json
from pathlib import Path

V = json.loads(
    (Path(__file__).parents[1] / "vectors" / "bbs_bls12381_sha256.json").read_text()
)


def test_vector_file_shape():
    assert len(V["keypair"]["public_key"]) == 192  # 96-byte G2 point, hex
    # secret key is a 32-byte scalar and must decode.
    assert len(bytes.fromhex(V["keypair"]["secret_key"])) == 32
    assert len(V["signatures"]) >= 5
    assert any(c["valid"] for c in V["signatures"])
    assert any(not c["valid"] for c in V["signatures"])
    assert len(V["proofs"]) >= 5
    assert any(c["valid"] for c in V["proofs"])
    for c in V["signatures"]:
        bytes.fromhex(c["signature"])
        bytes.fromhex(c["header"])
        # Every per-case public key (present on all official cases) must decode.
        if "public_key" in c:
            assert len(bytes.fromhex(c["public_key"])) == 96
        for m in c["messages"]:
            bytes.fromhex(m)


def test_proof_vectors_decode():
    for c in V["proofs"]:
        bytes.fromhex(c["proof"])
        bytes.fromhex(c["header"])
        bytes.fromhex(c["presentation_header"])
        if "public_key" in c:
            assert len(bytes.fromhex(c["public_key"])) == 96
        for m in c["messages"]:
            bytes.fromhex(m)
        # disclosed_indexes are integers; range validity is a Task 3 concern
        # (the fixtures deliberately include invalid-index cases).
        for idx in c["disclosed_indexes"]:
            assert isinstance(idx, int)
