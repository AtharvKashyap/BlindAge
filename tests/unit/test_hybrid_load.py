import json

import pytest

from blindage.registry import (
    RegistryError, RegistryPolicy, TrustRegistry, generate_mldsa_keypair,
    generate_root_keypair, sign_registry, sign_registry_mldsa,
)
from tests.conftest import dev_issuer_entry


def _write_all(tmp_path, *, strip_pq=False, corrupt_pq=False):
    reg = {"version": "1.0", "generated_at": "2026-08-02T00:00:00Z",
           "issuers": [dev_issuer_entry()]}
    ed_priv, ed_pub = generate_root_keypair()
    pq_seed, pq_pub = generate_mldsa_keypair()
    (tmp_path / "registry.json").write_text(json.dumps(reg))
    (tmp_path / "registry.sig").write_text(sign_registry(reg, ed_priv))
    if not strip_pq:
        sig = sign_registry_mldsa(reg, pq_seed)
        if corrupt_pq:
            sig = sig[:-4] + ("AAAA" if not sig.endswith("AAAA") else "BBBB")
        (tmp_path / "registry.sig.mldsa").write_text(sig)
    return ed_pub, pq_pub


def _load(tmp_path, ed_pub, pq_pub, policy):
    return TrustRegistry.load(
        tmp_path / "registry.json", tmp_path / "registry.sig", ed_pub,
        mldsa_signature_path=tmp_path / "registry.sig.mldsa",
        mldsa_root_public_key_b64=pq_pub, policy=policy,
    )


def test_hybrid_required_accepts_dual_signed(tmp_path):
    ed_pub, pq_pub = _write_all(tmp_path)
    reg = _load(tmp_path, ed_pub, pq_pub, RegistryPolicy.HYBRID_REQUIRED)
    assert reg.get_issuer("did:web:issuer.test") is not None


def test_missing_pq_file_denies_when_needed(tmp_path):
    ed_pub, pq_pub = _write_all(tmp_path, strip_pq=True)
    for policy in (RegistryPolicy.HYBRID_PREFERRED, RegistryPolicy.HYBRID_REQUIRED):
        with pytest.raises(RegistryError):
            _load(tmp_path, ed_pub, pq_pub, policy)
    # classical callers with no hybrid args remain untouched
    reg = TrustRegistry.load(tmp_path / "registry.json", tmp_path / "registry.sig", ed_pub)
    assert reg.get_issuer("did:web:issuer.test") is not None


def test_corrupt_pq_denies_hybrid_but_not_classical(tmp_path):
    ed_pub, pq_pub = _write_all(tmp_path, corrupt_pq=True)
    with pytest.raises(RegistryError):
        _load(tmp_path, ed_pub, pq_pub, RegistryPolicy.HYBRID_REQUIRED)
    reg = _load(tmp_path, ed_pub, pq_pub, RegistryPolicy.CLASSICAL_ONLY)
    assert reg.get_issuer("did:web:issuer.test") is not None
