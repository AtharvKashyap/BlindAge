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
        # disclosed_indexes are always integers.
        for idx in c["disclosed_indexes"]:
            assert isinstance(idx, int) and not isinstance(idx, bool)
        # For cases the fixtures mark valid, the indexes must be a strictly
        # increasing, in-range selection of the message vector. Invalid cases
        # (e.g. disclosed_indexes [4, 2, 4, 6]) deliberately violate this, so
        # the range assertions apply only to the valid ones.
        if c["valid"]:
            n = len(c["messages"])
            idxs = c["disclosed_indexes"]
            assert all(0 <= i < n for i in idxs)
            assert idxs == sorted(set(idxs))
