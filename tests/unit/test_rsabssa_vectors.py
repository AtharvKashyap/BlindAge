"""Byte-for-byte conformance with RFC 9474 Appendix A (Deterministic variant).

If these fail, the implementation is wrong — NEVER adjust a vector.
"""
import json
from pathlib import Path

from blindage.crypto import RsabssaTokenVerifier, b64u_encode, blind_sign, finalize
from blindage.crypto.rsabssa import _emsa_pss_encode, _i2osp, _os2ip
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

V = json.loads(
    (Path(__file__).resolve().parents[1] / "vectors" / "rfc9474_deterministic.json").read_text()
)


def h2b(name: str) -> bytes:
    return bytes.fromhex(V[name])


def build_keys() -> tuple[str, str]:
    n, e, d = (int(V[k], 16) for k in ("n", "e", "d"))
    p, q = int(V["p"], 16), int(V["q"], 16)
    iqmp = rsa.rsa_crt_iqmp(p, q)
    dmp1 = rsa.rsa_crt_dmp1(d, p)
    dmq1 = rsa.rsa_crt_dmq1(d, q)
    pub = rsa.RSAPublicNumbers(e, n)
    priv = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub).private_key()
    priv_b64 = b64u_encode(
        priv.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub_b64 = b64u_encode(
        priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return priv_b64, pub_b64


PRIV_B64, PUB_B64 = build_keys()
N_BITS = int(V["n"], 16).bit_length()


def test_emsa_pss_encode_matches_vector():
    encoded = _emsa_pss_encode(h2b("msg"), N_BITS - 1, h2b("salt"))
    assert encoded == h2b("encoded_msg")


def test_blind_with_vector_randomness_matches():
    # Reproduce Blind deterministically using the vector's inv:
    # z = m * r^e mod n where r = inv^-1 mod n.
    n, e = int(V["n"], 16), int(V["e"], 16)
    inv = int(V["inv"], 16)
    r = pow(inv, -1, n)
    m = _os2ip(h2b("encoded_msg"))
    z = (m * pow(r, e, n)) % n
    assert _i2osp(z, (N_BITS + 7) // 8) == h2b("blinded_msg")


def test_blind_sign_matches_vector():
    assert blind_sign(PRIV_B64, h2b("blinded_msg")) == h2b("blind_sig")


def test_finalize_matches_vector_and_verifies():
    sig = finalize(PUB_B64, h2b("msg"), h2b("blind_sig"), int(V["inv"], 16))
    assert sig == h2b("sig")
    assert RsabssaTokenVerifier("vec", PUB_B64).verify(h2b("msg"), sig)
