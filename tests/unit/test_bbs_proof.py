import json
from pathlib import Path

import pytest

from blindage.crypto import b64u_encode
from blindage.crypto.bbs import (
    BbsError, bbs_proof_gen, bbs_proof_verify, bbs_sign, generate_bbs_keypair,
)

V = json.loads(
    (Path(__file__).parents[1] / "vectors" / "bbs_bls12381_sha256.json").read_text()
)
PUB_B64U = b64u_encode(bytes.fromhex(V["keypair"]["public_key"]))


def _case_pub_b64u(case):
    # Proof cases carry a per-case public key; one ("wrong public key") differs
    # from the top-level keypair and must be honoured or that invalid case would
    # spuriously verify. Fall back to the top-level key when absent.
    return b64u_encode(bytes.fromhex(case.get("public_key", V["keypair"]["public_key"])))


@pytest.mark.parametrize("case", V["proofs"], ids=lambda c: c["case"])
def test_official_proof_vectors(case):
    disclosed = [bytes.fromhex(case["messages"][i]) for i in case["disclosed_indexes"]]
    ok = bbs_proof_verify(
        _case_pub_b64u(case), bytes.fromhex(case["proof"]), bytes.fromhex(case["header"]),
        bytes.fromhex(case["presentation_header"]), disclosed, case["disclosed_indexes"],
    )
    assert ok == case["valid"]


def _setup():
    sec, pub = generate_bbs_keypair()
    msgs = [b"did:web:issuer.test", b"AAL2", b"2026-Q3", b"AGE_OVER_18", b"AGE_OVER_21"]
    sig = bbs_sign(sec, b"h", msgs)
    return pub, sig, msgs


def test_proof_roundtrip_selective_disclosure():
    pub, sig, msgs = _setup()
    idx = [0, 1, 2, 3]  # metadata + AGE_OVER_18; AGE_OVER_21 stays hidden
    proof = bbs_proof_gen(pub, sig, b"h", b"ph", msgs, idx)
    assert bbs_proof_verify(pub, proof, b"h", b"ph", [msgs[i] for i in idx], idx)


def test_proofs_are_randomized_and_binding():
    pub, sig, msgs = _setup()
    idx = [0, 1, 2, 3]
    p1 = bbs_proof_gen(pub, sig, b"h", b"ph", msgs, idx)
    p2 = bbs_proof_gen(pub, sig, b"h", b"ph", msgs, idx)
    assert p1 != p2  # fresh randomness per presentation
    disclosed = [msgs[i] for i in idx]
    assert not bbs_proof_verify(pub, p1, b"h", b"OTHER", disclosed, idx)  # header-bound
    assert not bbs_proof_verify(
        pub, p1, b"h", b"ph", disclosed[:-1] + [b"AGE_OVER_21"], idx
    )  # can't swap the disclosed claim
    bad = bytearray(p1); bad[5] ^= 1
    assert not bbs_proof_verify(pub, bytes(bad), b"h", b"ph", disclosed, idx)


def test_invalid_indexes_raise():
    pub, sig, msgs = _setup()
    with pytest.raises(BbsError):
        bbs_proof_gen(pub, sig, b"h", b"ph", msgs, [0, 99])
    with pytest.raises(BbsError):
        bbs_proof_gen(pub, sig, b"h", b"ph", msgs, [1, 0])  # must be strictly increasing
