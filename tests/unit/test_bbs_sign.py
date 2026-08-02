import json
from pathlib import Path

import pytest

from blindage.crypto.bbs import (
    BBS_ALGORITHM,
    BbsError,
    bbs_sign,
    bbs_verify,
    generate_bbs_keypair,
)
from blindage.crypto import b64u_encode

V = json.loads(
    (Path(__file__).parents[1] / "vectors" / "bbs_bls12381_sha256.json").read_text()
)
TOP_PUB_B64U = b64u_encode(bytes.fromhex(V["keypair"]["public_key"]))
SEC_B64U = b64u_encode(bytes.fromhex(V["keypair"]["secret_key"]))


def _case_pub_b64u(case):
    # Some fixture cases (e.g. the wrong-public-key case) carry a per-case
    # "public_key" that overrides the top-level keypair; the plan anticipated
    # this adaptation. Fall back to the top-level key when absent.
    pub_hex = case.get("public_key")
    if pub_hex is None:
        return TOP_PUB_B64U
    return b64u_encode(bytes.fromhex(pub_hex))


@pytest.mark.parametrize("case", V["signatures"], ids=lambda c: c["case"])
def test_official_signature_vectors(case):
    header = bytes.fromhex(case["header"])
    messages = [bytes.fromhex(m) for m in case["messages"]]
    ok = bbs_verify(
        _case_pub_b64u(case), bytes.fromhex(case["signature"]), header, messages
    )
    assert ok == case["valid"]


def test_sign_reproduces_valid_vectors():
    # BBS BLS12-381-SHA-256 signing is deterministic given (sk, header, messages).
    for case in V["signatures"]:
        if not case["valid"]:
            continue
        sig = bbs_sign(
            SEC_B64U,
            bytes.fromhex(case["header"]),
            [bytes.fromhex(m) for m in case["messages"]],
        )
        assert sig.hex() == case["signature"], case["case"]


def test_roundtrip_and_tamper():
    sec, pub = generate_bbs_keypair()
    msgs = [b"did:web:issuer.test", b"AAL2", b"2026-Q3", b"AGE_OVER_18"]
    sig = bbs_sign(sec, b"blindage-vc", msgs)
    assert bbs_verify(pub, sig, b"blindage-vc", msgs)
    assert not bbs_verify(pub, sig, b"blindage-vc", msgs[:-1] + [b"AGE_OVER_21"])
    assert not bbs_verify(pub, sig, b"other-header", msgs)
    bad = bytearray(sig)
    bad[0] ^= 1
    assert not bbs_verify(pub, bytes(bad), b"blindage-vc", msgs)


def test_malformed_inputs_raise_bbs_error():
    with pytest.raises(BbsError):
        bbs_sign("!!!", b"", [b"m"])
    sec, pub = generate_bbs_keypair()
    with pytest.raises(BbsError):
        bbs_verify("!!!", b"\x00" * 80, b"", [b"m"])
    assert BBS_ALGORITHM == "bbs-bls12381-sha256"
