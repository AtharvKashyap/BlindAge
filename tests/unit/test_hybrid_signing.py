import pytest

from blindage.registry import (
    HybridVerificationError, RegistryPolicy, generate_mldsa_keypair,
    generate_root_keypair, sign_registry, sign_registry_mldsa,
    verify_registry_hybrid, verify_registry_mldsa,
)

REG = {"version": "1.0", "generated_at": "2026-08-02T00:00:00Z", "issuers": []}
ED_PRIV, ED_PUB = generate_root_keypair()
PQ_SEED, PQ_PUB = generate_mldsa_keypair()
ED_SIG = sign_registry(REG, ED_PRIV)
PQ_SIG = sign_registry_mldsa(REG, PQ_SEED)


def test_mldsa_roundtrip_and_sizes():
    assert verify_registry_mldsa(REG, PQ_SIG, PQ_PUB)
    from blindage.crypto import b64u_decode
    assert len(b64u_decode(PQ_PUB)) == 1952   # ML-DSA-65 raw public key
    assert len(b64u_decode(PQ_SIG)) == 3309   # ML-DSA-65 signature
    seed2, pub2 = generate_mldsa_keypair()
    assert (seed2, pub2) != (PQ_SEED, PQ_PUB)


def test_mldsa_verify_fails_closed():
    assert not verify_registry_mldsa({"tampered": True}, PQ_SIG, PQ_PUB)
    corrupt = ("A" if PQ_SIG[0] != "A" else "B") + PQ_SIG[1:]
    assert not verify_registry_mldsa(REG, corrupt, PQ_PUB)
    assert not verify_registry_mldsa(REG, "!!!", PQ_PUB)
    assert not verify_registry_mldsa(REG, PQ_SIG, "!!!")


def _hybrid(policy, *, ed_sig=None, pq_sig=PQ_SIG, pq_pub=PQ_PUB):
    verify_registry_hybrid(REG, ed_sig or ED_SIG, ED_PUB, pq_sig, pq_pub, policy)


def test_ed25519_invalid_always_denies():
    bad_ed = sign_registry({"other": 1}, ED_PRIV)
    for policy in RegistryPolicy:
        with pytest.raises(HybridVerificationError):
            _hybrid(policy, ed_sig=bad_ed)


def test_classical_only_ignores_pq_entirely():
    _hybrid(RegistryPolicy.CLASSICAL_ONLY, pq_sig=None, pq_pub=None)
    _hybrid(RegistryPolicy.CLASSICAL_ONLY, pq_sig="garbage", pq_pub=PQ_PUB)


def test_hybrid_preferred_semantics():
    # no pinned key -> accept on Ed25519 alone
    _hybrid(RegistryPolicy.HYBRID_PREFERRED, pq_sig=None, pq_pub=None)
    # pinned key + valid sig -> accept
    _hybrid(RegistryPolicy.HYBRID_PREFERRED)
    # pinned key + MISSING sig -> deny (downgrade protection)
    with pytest.raises(HybridVerificationError, match="missing"):
        _hybrid(RegistryPolicy.HYBRID_PREFERRED, pq_sig=None)
    # present but invalid -> deny (never accept broken PQ)
    with pytest.raises(HybridVerificationError, match="invalid"):
        _hybrid(RegistryPolicy.HYBRID_PREFERRED, pq_sig=PQ_SIG[:-4] + "AAAA")


def test_hybrid_required_semantics():
    _hybrid(RegistryPolicy.HYBRID_REQUIRED)
    with pytest.raises(HybridVerificationError):
        _hybrid(RegistryPolicy.HYBRID_REQUIRED, pq_sig=None)
    with pytest.raises(HybridVerificationError):
        _hybrid(RegistryPolicy.HYBRID_REQUIRED, pq_pub=None)
    with pytest.raises(HybridVerificationError):
        _hybrid(RegistryPolicy.HYBRID_REQUIRED, pq_sig=PQ_SIG[:-4] + "AAAA")


def test_downgrade_strip_attack_denied():
    """Adversarial: stripping the PQ signature never yields acceptance a valid
    dual-signed registry wouldn't already have under a weaker policy."""
    _hybrid(RegistryPolicy.HYBRID_REQUIRED)  # baseline: dual-signed accepts
    for policy in (RegistryPolicy.HYBRID_PREFERRED, RegistryPolicy.HYBRID_REQUIRED):
        with pytest.raises(HybridVerificationError):
            _hybrid(policy, pq_sig=None)  # stripped -> deny under both hybrid modes
