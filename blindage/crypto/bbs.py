"""BBS signatures (draft-irtf-cfrg-bbs-signatures) — ciphersuite BLS12-381-SHA-256.

This is a *from-draft* implementation of the BBS core protocol (KeyGen / Sign /
Verify) built on py_ecc's reviewed BLS12-381 curve, pairing, hash-to-curve, and
point (de)compression operations. Only the BBS protocol layer — generator
derivation, hash-to-scalar, domain calculation, and the CoreSign/CoreVerify glue —
is hand-written here; every elliptic-curve and pairing operation is delegated to
py_ecc.

Correctness is gated by the official CFRG test vectors
(tests/vectors/bbs_bls12381_sha256.json, exercised by tests/unit/test_bbs_sign.py):
if a vector fails, the implementation is wrong, never the vector.

SECURITY / SCOPE NOTES:

* This code is **NOT constant-time**. py_ecc's scalar multiplication and this
  module's modular arithmetic leak timing. It is suitable for development,
  testing, and protocol validation only. Production deployment is gated on
  replacing the primitives with an audited, constant-time native implementation
  (the same production gate that applies to the pure-Python RSABSSA).
* **VC issuance with BBS here is NOT blind.** The issuer sees the full message
  vector it signs. BBS provides *unlinkable selective disclosure at presentation
  time* (Task 3's proofs), not blind issuance. Do not conflate the two.
"""

from __future__ import annotations

import secrets
from hashlib import sha256

from py_ecc.optimized_bls12_381 import (
    G2,
    add,
    curve_order,
    is_inf,
    multiply,
    neg,
    pairing,
)
from py_ecc.optimized_bls12_381.optimized_curve import FQ12
from py_ecc.bls.hash_to_curve import expand_message_xmd, hash_to_G1
from py_ecc.bls.point_compression import (
    compress_G1,
    compress_G2,
    decompress_G1,
    decompress_G2,
)

from blindage.crypto.interface import b64u_decode, b64u_encode

BBS_ALGORITHM = "bbs-bls12381-sha256"

# --- Ciphersuite parameters: BLS12-381-SHA-256 (draft-irtf-cfrg-bbs-signatures) ---
# api_id = ciphersuite_id || "H2G_HM2S_"; ciphersuite_id ends in "SSWU_RO_".
_API_ID = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_"
_H2S_DST = _API_ID + b"H2S_"
_SEED_DST = _API_ID + b"SIG_GENERATOR_SEED_"
_GENERATOR_DST = _API_ID + b"SIG_GENERATOR_DST_"
_GENERATOR_SEED = _API_ID + b"MESSAGE_GENERATOR_SEED"
_MAP_DST = _API_ID + b"MAP_MSG_TO_SCALAR_AS_HASH_"

_EXPAND_LEN = 48
_OCTET_SCALAR_LENGTH = 32
_OCTET_POINT_LENGTH = 48

# Fixed point P1 of G1 for the SHA-256 ciphersuite (compressed, hex from the draft).
_P1_HEX = (
    "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd22"
    "5e7c59698588e70d11406d161b4e28c9"
)

_R = curve_order


class BbsError(Exception):
    """Raised on any malformed BBS input (bad key, bad encoding, parse failure)."""


# --------------------------------------------------------------------------- #
# Octet-string primitives (I2OSP / OS2IP) and point (de)serialization.
# --------------------------------------------------------------------------- #
def _i2osp(value: int, length: int) -> bytes:
    if value < 0 or value >= (1 << (8 * length)):
        raise BbsError("integer does not fit in the requested octet length")
    return value.to_bytes(length, "big")


def _os2ip(octets: bytes) -> int:
    return int.from_bytes(octets, "big")


def _point_to_octets_e1(point) -> bytes:
    """Serialize a G1 point to its 48-byte compressed encoding."""
    return _i2osp(int(compress_G1(point)), _OCTET_POINT_LENGTH)


def _octets_to_point_e1(octets: bytes):
    """Deserialize 48 compressed octets to a G1 point, with a subgroup check."""
    if len(octets) != _OCTET_POINT_LENGTH:
        raise BbsError("G1 point must be 48 octets")
    try:
        point = decompress_G1(_os2ip(octets))
    except Exception as exc:  # noqa: BLE001 - normalize any decode failure
        raise BbsError("invalid G1 point encoding") from exc
    if not is_inf(multiply(point, _R)):
        raise BbsError("G1 point is not in the prime-order subgroup")
    return point


def _octets_to_pubkey(octets: bytes):
    """Deserialize a 96-byte compressed G2 public key, with a subgroup check."""
    if len(octets) != 2 * _OCTET_POINT_LENGTH:
        raise BbsError("public key must be 96 octets")
    try:
        c0 = _os2ip(octets[:_OCTET_POINT_LENGTH])
        c1 = _os2ip(octets[_OCTET_POINT_LENGTH:])
        point = decompress_G2((c0, c1))
    except Exception as exc:  # noqa: BLE001
        raise BbsError("invalid public key encoding") from exc
    if is_inf(point):
        raise BbsError("public key is the identity")
    if not is_inf(multiply(point, _R)):
        raise BbsError("public key is not in the prime-order subgroup")
    return point


def _pubkey_to_octets(point) -> bytes:
    c0, c1 = compress_G2(point)
    return _i2osp(int(c0), _OCTET_POINT_LENGTH) + _i2osp(int(c1), _OCTET_POINT_LENGTH)


_P1 = _octets_to_point_e1(bytes.fromhex(_P1_HEX))


# --------------------------------------------------------------------------- #
# BBS building blocks.
# --------------------------------------------------------------------------- #
def _hash_to_scalar(msg_octets: bytes, dst: bytes) -> int:
    if len(dst) > 255:
        raise BbsError("hash_to_scalar DST exceeds 255 octets")
    uniform = expand_message_xmd(msg_octets, dst, _EXPAND_LEN, sha256)
    return _os2ip(uniform) % _R


def _create_generators(count: int):
    """Derive `count` deterministic G1 generators (Q_1, H_1, ..., H_{count-1})."""
    generators = []
    v = expand_message_xmd(_GENERATOR_SEED, _SEED_DST, _EXPAND_LEN, sha256)
    for i in range(1, count + 1):
        v = expand_message_xmd(v + _i2osp(i, 8), _SEED_DST, _EXPAND_LEN, sha256)
        generators.append(hash_to_G1(v, _GENERATOR_DST, sha256))
    return generators


def _messages_to_scalars(messages: list[bytes]) -> list[int]:
    return [_hash_to_scalar(m, _MAP_DST) for m in messages]


def _calculate_domain(
    pk_octets: bytes, q_1, h_points: list, header: bytes
) -> int:
    length = len(h_points)
    dom_octs = _i2osp(length, 8) + _point_to_octets_e1(q_1)
    for h in h_points:
        dom_octs += _point_to_octets_e1(h)
    dom_octs += _API_ID
    dom_input = pk_octets + dom_octs + _i2osp(len(header), 8) + header
    return _hash_to_scalar(dom_input, _H2S_DST)


def _b_value(domain: int, q_1, h_points: list, msg_scalars: list[int]):
    """B = P1 + Q_1*domain + sum(H_i * msg_i)."""
    b = add(_P1, multiply(q_1, domain))
    for h, m in zip(h_points, msg_scalars):
        b = add(b, multiply(h, m))
    return b


def _decode_scalar_secret(secret_b64u: str) -> int:
    try:
        raw = b64u_decode(secret_b64u)
    except Exception as exc:  # noqa: BLE001
        raise BbsError("secret key is not valid base64url") from exc
    sk = _os2ip(raw)
    if sk == 0 or sk >= _R:
        raise BbsError("secret key is not a valid scalar in [1, r-1]")
    return sk


# --------------------------------------------------------------------------- #
# Public API.
# --------------------------------------------------------------------------- #
def generate_bbs_keypair() -> tuple[str, str]:
    """Return (secret_b64u, public_b64u): a random scalar SK and PK = SK * P2."""
    sk = 1 + secrets.randbelow(_R - 1)
    pk_point = multiply(G2, sk)
    secret_b64u = b64u_encode(_i2osp(sk, _OCTET_SCALAR_LENGTH))
    public_b64u = b64u_encode(_pubkey_to_octets(pk_point))
    return secret_b64u, public_b64u


def bbs_sign(secret_b64u: str, header: bytes, messages: list[bytes]) -> bytes:
    """Deterministically sign `messages` under `header`; return 80 octets (A || e)."""
    sk = _decode_scalar_secret(secret_b64u)
    pk_octets = _pubkey_to_octets(multiply(G2, sk))

    msg_scalars = _messages_to_scalars(messages)
    length = len(msg_scalars)
    generators = _create_generators(length + 1)
    q_1, h_points = generators[0], generators[1:]

    domain = _calculate_domain(pk_octets, q_1, h_points, header)

    # e = hash_to_scalar( serialize((SK, msg_1, ..., msg_L, domain)) , H2S_DST )
    e_input = _i2osp(sk, _OCTET_SCALAR_LENGTH)
    for m in msg_scalars:
        e_input += _i2osp(m, _OCTET_SCALAR_LENGTH)
    e_input += _i2osp(domain, _OCTET_SCALAR_LENGTH)
    e = _hash_to_scalar(e_input, _H2S_DST)

    b = _b_value(domain, q_1, h_points, msg_scalars)
    # A = B * (1 / (SK + e)) mod r
    inv = pow((sk + e) % _R, -1, _R)
    a_point = multiply(b, inv)
    if is_inf(a_point):
        raise BbsError("signature computation produced the identity (SK + e == 0)")

    return _point_to_octets_e1(a_point) + _i2osp(e, _OCTET_SCALAR_LENGTH)


def bbs_verify(
    public_b64u: str, signature: bytes, header: bytes, messages: list[bytes]
) -> bool:
    """Return True iff `signature` is a valid BBS signature. Malformed key -> BbsError."""
    # Public key problems are caller-provided garbage -> raise.
    try:
        pk_octets = b64u_decode(public_b64u)
    except Exception as exc:  # noqa: BLE001
        raise BbsError("public key is not valid base64url") from exc
    w = _octets_to_pubkey(pk_octets)

    # Signature problems mean "invalid signature" -> return False, do not raise.
    try:
        if len(signature) != _OCTET_POINT_LENGTH + _OCTET_SCALAR_LENGTH:
            return False
        a_point = _octets_to_point_e1(signature[:_OCTET_POINT_LENGTH])
        e = _os2ip(signature[_OCTET_POINT_LENGTH:])
    except BbsError:
        return False
    if e == 0 or e >= _R:
        return False
    if is_inf(a_point):
        return False

    msg_scalars = _messages_to_scalars(messages)
    length = len(msg_scalars)
    generators = _create_generators(length + 1)
    q_1, h_points = generators[0], generators[1:]

    domain = _calculate_domain(pk_octets, q_1, h_points, header)
    b = _b_value(domain, q_1, h_points, msg_scalars)

    # Check: e(A, W + P2*e) * e(B, -P2) == Identity_GT
    lhs = pairing(add(w, multiply(G2, e)), a_point)
    rhs = pairing(neg(G2), b)
    return lhs * rhs == FQ12.one()


# --------------------------------------------------------------------------- #
# Selective-disclosure proofs (draft-irtf-cfrg-bbs-signatures CoreProofGen /
# CoreProofVerify). A BBS proof is a zero-knowledge proof-of-knowledge of a
# signature that reveals only a chosen subset of the signed messages and binds
# to a fresh, caller-supplied `presentation_header`. Proofs are randomized:
# every call to `bbs_proof_gen` draws fresh blinding scalars, so two proofs of
# the same signature are unlinkable. Correctness is gated by the official CFRG
# proof vectors (tests/unit/test_bbs_proof.py).
# --------------------------------------------------------------------------- #
def _octets_to_signature(signature: bytes):
    """Parse 80 octets (A || e) to a (point, scalar) pair. Malformed -> BbsError."""
    if len(signature) != _OCTET_POINT_LENGTH + _OCTET_SCALAR_LENGTH:
        raise BbsError("signature must be 80 octets")
    a_point = _octets_to_point_e1(signature[:_OCTET_POINT_LENGTH])
    if is_inf(a_point):
        raise BbsError("signature point A is the identity")
    e = _os2ip(signature[_OCTET_POINT_LENGTH:])
    if e == 0 or e >= _R:
        raise BbsError("signature scalar e is out of range")
    return a_point, e


def _is_valid_index(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _octets_to_proof(proof: bytes):
    """Parse a BBS proof to (Abar, Bbar, D, e^, r1^, r3^, commitments, c).

    Any structural problem (short length, misaligned scalar section, bad or
    identity point, out-of-range scalar) raises BbsError; the verify entry point
    maps that to a False result.
    """
    floor = 3 * _OCTET_POINT_LENGTH + 4 * _OCTET_SCALAR_LENGTH
    if len(proof) < floor:
        raise BbsError("proof is shorter than the minimum length")
    if (len(proof) - 3 * _OCTET_POINT_LENGTH) % _OCTET_SCALAR_LENGTH != 0:
        raise BbsError("proof scalar section is misaligned")

    index = 0
    points = []
    for _ in range(3):
        point = _octets_to_point_e1(proof[index : index + _OCTET_POINT_LENGTH])
        if is_inf(point):
            raise BbsError("proof point is the identity")
        points.append(point)
        index += _OCTET_POINT_LENGTH

    scalars = []
    while index < len(proof):
        s = _os2ip(proof[index : index + _OCTET_SCALAR_LENGTH])
        if s == 0 or s >= _R:
            raise BbsError("proof scalar is out of range")
        scalars.append(s)
        index += _OCTET_SCALAR_LENGTH

    # scalars = (e^, r1^, r3^, m^_j1, ..., m^_jU, c); at least 4 by the floor check.
    abar, bbar, d = points
    e_hat, r1_hat, r3_hat = scalars[0], scalars[1], scalars[2]
    commitments = scalars[3:-1]
    challenge = scalars[-1]
    return abar, bbar, d, e_hat, r1_hat, r3_hat, commitments, challenge


def _proof_to_octets(
    abar, bbar, d, e_hat: int, r1_hat: int, r3_hat: int, commitments, challenge: int
) -> bytes:
    """serialize((Abar, Bbar, D, e^, r1^, r3^, m^_1, ..., m^_U, c))."""
    out = (
        _point_to_octets_e1(abar)
        + _point_to_octets_e1(bbar)
        + _point_to_octets_e1(d)
        + _i2osp(e_hat, _OCTET_SCALAR_LENGTH)
        + _i2osp(r1_hat, _OCTET_SCALAR_LENGTH)
        + _i2osp(r3_hat, _OCTET_SCALAR_LENGTH)
    )
    for m in commitments:
        out += _i2osp(m, _OCTET_SCALAR_LENGTH)
    out += _i2osp(challenge, _OCTET_SCALAR_LENGTH)
    return out


def _proof_challenge_calculate(
    abar, bbar, d, t1, t2, domain: int, disclosed_scalars, disclosed_indexes, ph: bytes
) -> int:
    """ProofChallengeCalculate: hash_to_scalar over the Fiat-Shamir transcript."""
    c_octs = _i2osp(len(disclosed_indexes), 8)
    for i, m in zip(disclosed_indexes, disclosed_scalars):
        c_octs += _i2osp(i, 8) + _i2osp(m, _OCTET_SCALAR_LENGTH)
    c_octs += (
        _point_to_octets_e1(abar)
        + _point_to_octets_e1(bbar)
        + _point_to_octets_e1(d)
        + _point_to_octets_e1(t1)
        + _point_to_octets_e1(t2)
        + _i2osp(domain, _OCTET_SCALAR_LENGTH)
    )
    c_octs += _i2osp(len(ph), 8) + ph
    return _hash_to_scalar(c_octs, _H2S_DST)


def bbs_proof_gen(
    public_b64u: str,
    signature: bytes,
    header: bytes,
    presentation_header: bytes,
    messages: list[bytes],
    disclosed_indexes: list[int],
) -> bytes:
    """Create a selective-disclosure BBS proof revealing only `disclosed_indexes`.

    `disclosed_indexes` MUST be strictly increasing and within [0, len(messages)-1];
    any structural problem raises BbsError. The proof draws fresh randomness on
    every call, so it is not deterministic (unlike `bbs_sign`).
    """
    try:
        pk_octets = b64u_decode(public_b64u)
    except Exception as exc:  # noqa: BLE001
        raise BbsError("public key is not valid base64url") from exc
    _octets_to_pubkey(pk_octets)  # structural validation of the key

    a_point, e = _octets_to_signature(signature)

    length = len(messages)
    r = len(disclosed_indexes)
    if r > length:
        raise BbsError("more disclosed indexes than messages")
    prev = -1
    for i in disclosed_indexes:
        if not _is_valid_index(i):
            raise BbsError("disclosed index is not an integer")
        if i < 0 or i > length - 1:
            raise BbsError("disclosed index out of range")
        if i <= prev:
            raise BbsError("disclosed indexes must be strictly increasing")
        prev = i

    disclosed_set = set(disclosed_indexes)
    undisclosed_indexes = [i for i in range(length) if i not in disclosed_set]
    u = len(undisclosed_indexes)

    msg_scalars = _messages_to_scalars(messages)
    generators = _create_generators(length + 1)
    q_1, h_points = generators[0], generators[1:]
    domain = _calculate_domain(pk_octets, q_1, h_points, header)

    # random_scalars = (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU)
    random_scalars = [1 + secrets.randbelow(_R - 1) for _ in range(5 + u)]
    r1, r2, e_tilde, r1_tilde, r3_tilde = random_scalars[:5]
    m_tildes = random_scalars[5:]

    # ProofInit.
    b = _b_value(domain, q_1, h_points, msg_scalars)
    d = multiply(b, r2)
    abar = multiply(a_point, (r1 * r2) % _R)
    bbar = add(multiply(d, r1), neg(multiply(abar, e)))
    t1 = add(multiply(abar, e_tilde), multiply(d, r1_tilde))
    t2 = multiply(d, r3_tilde)
    for m_tilde, j in zip(m_tildes, undisclosed_indexes):
        t2 = add(t2, multiply(h_points[j], m_tilde))

    disclosed_scalars = [msg_scalars[i] for i in disclosed_indexes]
    challenge = _proof_challenge_calculate(
        abar, bbar, d, t1, t2, domain, disclosed_scalars, disclosed_indexes,
        presentation_header,
    )

    # ProofFinalize.
    r3 = pow(r2, -1, _R)
    e_hat = (e_tilde + e * challenge) % _R
    r1_hat = (r1_tilde - r1 * challenge) % _R
    r3_hat = (r3_tilde - r3 * challenge) % _R
    commitments = [
        (m_tilde + msg_scalars[j] * challenge) % _R
        for m_tilde, j in zip(m_tildes, undisclosed_indexes)
    ]
    return _proof_to_octets(abar, bbar, d, e_hat, r1_hat, r3_hat, commitments, challenge)


def bbs_proof_verify(
    public_b64u: str,
    proof: bytes,
    header: bytes,
    presentation_header: bytes,
    disclosed_messages: list[bytes],
    disclosed_indexes: list[int],
) -> bool:
    """Return True iff `proof` is a valid selective-disclosure proof.

    Any proof-level problem (bad encoding, out-of-range or non-ascending indexes,
    disclosed-count mismatch, challenge mismatch, failed pairing) yields False.
    Only a malformed public key raises BbsError, matching `bbs_verify`.
    """
    try:
        pk_octets = b64u_decode(public_b64u)
    except Exception as exc:  # noqa: BLE001
        raise BbsError("public key is not valid base64url") from exc
    w = _octets_to_pubkey(pk_octets)  # malformed key -> BbsError, as with bbs_verify

    try:
        abar, bbar, d, e_hat, r1_hat, r3_hat, commitments, challenge = _octets_to_proof(
            proof
        )
        u = len(commitments)
        r = len(disclosed_indexes)
        length = r + u

        for i in disclosed_indexes:
            if not _is_valid_index(i) or i < 0 or i > length - 1:
                return False
        if len(disclosed_messages) != r:
            return False

        disclosed_set = set(disclosed_indexes)
        undisclosed_indexes = [i for i in range(length) if i not in disclosed_set]

        disclosed_scalars = _messages_to_scalars(disclosed_messages)
        generators = _create_generators(length + 1)
        q_1, h_points = generators[0], generators[1:]
        domain = _calculate_domain(pk_octets, q_1, h_points, header)

        # ProofVerifyInit.
        t1 = add(
            add(multiply(bbar, challenge), multiply(abar, e_hat)),
            multiply(d, r1_hat),
        )
        bv = add(_P1, multiply(q_1, domain))
        for i, m in zip(disclosed_indexes, disclosed_scalars):
            bv = add(bv, multiply(h_points[i], m))
        t2 = add(multiply(bv, challenge), multiply(d, r3_hat))
        for j, m_hat in zip(undisclosed_indexes, commitments):
            t2 = add(t2, multiply(h_points[j], m_hat))

        expected = _proof_challenge_calculate(
            abar, bbar, d, t1, t2, domain, disclosed_scalars, disclosed_indexes,
            presentation_header,
        )
        if expected != challenge:
            return False

        # Pairing check: e(Abar, W) * e(Bbar, -P2) == Identity_GT.
        lhs = pairing(w, abar)
        rhs = pairing(neg(G2), bbar)
        return lhs * rhs == FQ12.one()
    except BbsError:
        return False
