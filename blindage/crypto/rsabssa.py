"""RSA Blind Signatures per RFC 9474, variant RSABSSA-SHA384-PSS-Deterministic.

Implemented from spec on top of the `cryptography` package because no
maintained Python RFC 9474 library exists (decision log:
docs/decisions.md, 2026-07-22). The primitives stay reviewed: final
signature verification is OpenSSL RSA-PSS via `cryptography`; the RSA
private-key math uses CPython big-int pow() over key numbers exposed by
`cryptography`. What is hand-written here — EMSA-PSS encoding (RFC 8017
§9.1.1) and the blind/unblind arithmetic (RFC 9474 §4) — is gated
byte-for-byte by RFC 9474 Appendix A official test vectors
(tests/unit/test_rsabssa_vectors.py).

Known caveat: Python big-int arithmetic is not constant-time. Acceptable
at dev stage; the production path is wrapping an audited native
implementation (see docs/decisions.md).
"""
import hashlib
import math
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from blindage.crypto.interface import b64u_decode, b64u_encode

RSABSSA_ALGORITHM = "rsabssa-sha384-pss-deterministic"
_HASH = hashlib.sha384
_HASH_LEN = 48
_SALT_LEN = 48  # RSABSSA-SHA384-PSS-* uses sLen = 48


class BlindSignatureError(Exception):
    pass


def generate_blind_keypair(bits: int = 2048) -> tuple[str, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_der = private.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64u_encode(private_der), b64u_encode(public_der)


def _load_public(public_key_b64: str) -> rsa.RSAPublicKey:
    key = serialization.load_der_public_key(b64u_decode(public_key_b64))
    if not isinstance(key, rsa.RSAPublicKey):
        raise BlindSignatureError("not an RSA public key")
    return key


def _load_private(private_key_b64: str) -> rsa.RSAPrivateKey:
    key = serialization.load_der_private_key(b64u_decode(private_key_b64), None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise BlindSignatureError("not an RSA private key")
    return key


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _mgf1(seed: bytes, mask_len: int) -> bytes:
    output = b""
    for counter in range((mask_len + _HASH_LEN - 1) // _HASH_LEN):
        output += _HASH(seed + counter.to_bytes(4, "big")).digest()
    return output[:mask_len]


def _emsa_pss_encode(message: bytes, em_bits: int, salt: bytes) -> bytes:
    """RFC 8017 §9.1.1 EMSA-PSS-ENCODE with SHA-384/MGF1-SHA-384."""
    m_hash = _HASH(message).digest()
    em_len = (em_bits + 7) // 8
    s_len = len(salt)
    if em_len < _HASH_LEN + s_len + 2:
        raise BlindSignatureError("encoding error: message too long")
    m_prime = b"\x00" * 8 + m_hash + salt
    h = _HASH(m_prime).digest()
    ps = b"\x00" * (em_len - s_len - _HASH_LEN - 2)
    db = ps + b"\x01" + salt
    db_mask = _mgf1(h, em_len - _HASH_LEN - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    # Zero the leftmost 8*em_len - em_bits bits of the first octet.
    top_bits = 8 * em_len - em_bits
    masked_db = bytes([masked_db[0] & (0xFF >> top_bits)]) + masked_db[1:]
    return masked_db + h + b"\xbc"


def blind(public_key_b64: str, message: bytes) -> tuple[bytes, int]:
    """RFC 9474 §4.1 Blind (Deterministic variant: prepare = identity)."""
    public = _load_public(public_key_b64)
    numbers = public.public_numbers()
    n, e = numbers.n, numbers.e
    modulus_len = (n.bit_length() + 7) // 8
    salt = secrets.token_bytes(_SALT_LEN)
    encoded = _emsa_pss_encode(message, n.bit_length() - 1, salt)
    m = _os2ip(encoded)
    if math.gcd(m, n) != 1:
        raise BlindSignatureError("invalid input: message not coprime with modulus")
    while True:
        r = secrets.randbelow(n - 2) + 1
        if math.gcd(r, n) == 1:
            break
    inv = pow(r, -1, n)
    z = (m * pow(r, e, n)) % n
    return _i2osp(z, modulus_len), inv


def blind_sign(private_key_b64: str, blinded_msg: bytes) -> bytes:
    """RFC 9474 §4.2 BlindSign, including the mandatory correctness check."""
    private = _load_private(private_key_b64)
    numbers = private.private_numbers()
    n = numbers.public_numbers.n
    e = numbers.public_numbers.e
    d = numbers.d
    modulus_len = (n.bit_length() + 7) // 8
    m = _os2ip(blinded_msg)
    if m >= n:
        raise BlindSignatureError("invalid blinded message: out of range")
    s = pow(m, d, n)
    if pow(s, e, n) != m:
        raise BlindSignatureError("signing failure: verification of raw signature failed")
    return _i2osp(s, modulus_len)


def finalize(
    public_key_b64: str, message: bytes, blind_sig: bytes, inv: int
) -> bytes:
    """RFC 9474 §4.3 Finalize: unblind, then MUST verify before returning."""
    public = _load_public(public_key_b64)
    n = public.public_numbers().n
    modulus_len = (n.bit_length() + 7) // 8
    if len(blind_sig) != modulus_len:
        raise BlindSignatureError("invalid blind signature length")
    z = _os2ip(blind_sig)
    s = (z * inv) % n
    signature = _i2osp(s, modulus_len)
    try:
        public.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=_SALT_LEN),
            hashes.SHA384(),
        )
    except InvalidSignature as exc:
        raise BlindSignatureError("invalid signature after unblinding") from exc
    return signature


class RsabssaTokenVerifier:
    algorithm = RSABSSA_ALGORITHM

    def __init__(self, key_id: str, public_key_b64: str) -> None:
        self.key_id = key_id
        self._public = _load_public(public_key_b64)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=_SALT_LEN),
                hashes.SHA384(),
            )
            return True
        except (InvalidSignature, ValueError):
            return False
