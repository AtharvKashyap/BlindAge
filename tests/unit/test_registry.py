import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from blindage.crypto import b64u_encode
from blindage.registry import (
    RegistryError,
    TrustRegistry,
    generate_root_keypair,
    sign_registry,
    verify_registry_signature,
)

NOW = datetime(2026, 7, 21, tzinfo=timezone.utc)


def issuer_dict(keys: list[dict]) -> dict:
    return {
        "version": "1.0",
        "issuer_id": "did:web:issuer.test",
        "legal_name": "Test Issuer",
        "jurisdiction": "US",
        "supported_claims": ["AGE_OVER_18"],
        "assurance_levels": ["AAL2"],
        "keys": keys,
        "status": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
    }


def token_key(key_id="dev-AGE_OVER_18-AAL2-2026-Q3", claim="AGE_OVER_18") -> dict:
    return {
        "key_id": key_id,
        "purpose": "token_signing",
        "algorithm": "mock-hmac-sha256",
        "public_key": b64u_encode(b"s" * 32),
        "claim": claim,
        "assurance_level": "AAL2",
        "epoch": "2026-Q3",
        "valid_from": "2026-07-01T00:00:00Z",
        "valid_until": "2026-10-01T00:00:00Z",
    }


def registry_dict(keys: list[dict] | None = None) -> dict:
    return {
        "version": "1.0",
        "generated_at": "2026-07-21T00:00:00Z",
        "issuers": [issuer_dict(keys if keys is not None else [token_key()])],
    }


def test_root_sign_and_verify_round_trip():
    priv, pub = generate_root_keypair()
    data = registry_dict()
    sig = sign_registry(data, priv)
    assert verify_registry_signature(data, sig, pub)


def test_tampered_registry_fails_verification():
    priv, pub = generate_root_keypair()
    data = registry_dict()
    sig = sign_registry(data, priv)
    data["issuers"][0]["status"] = "revoked"
    assert not verify_registry_signature(data, sig, pub)


def test_load_verifies_signature_and_exposes_lookups(tmp_path: Path):
    priv, pub = generate_root_keypair()
    data = registry_dict()
    (tmp_path / "registry.json").write_text(json.dumps(data))
    (tmp_path / "registry.sig").write_text(sign_registry(data, priv))
    reg = TrustRegistry.load(tmp_path / "registry.json", tmp_path / "registry.sig", pub)
    assert reg.get_issuer("did:web:issuer.test") is not None
    key = reg.get_token_key("did:web:issuer.test", "dev-AGE_OVER_18-AAL2-2026-Q3")
    assert key is not None and key.claim.value == "AGE_OVER_18"
    assert reg.get_token_key("did:web:issuer.test", "no-such-key") is None
    assert reg.get_issuer("did:web:other") is None


def test_load_rejects_bad_signature(tmp_path: Path):
    _, pub = generate_root_keypair()
    other_priv, _ = generate_root_keypair()
    data = registry_dict()
    (tmp_path / "registry.json").write_text(json.dumps(data))
    (tmp_path / "registry.sig").write_text(sign_registry(data, other_priv))
    with pytest.raises(RegistryError, match="signature"):
        TrustRegistry.load(tmp_path / "registry.json", tmp_path / "registry.sig", pub)


def test_duplicate_tuple_binding_rejected():
    # Two keys binding the same (claim, assurance, epoch) — key-uniqueness
    # invariant [MOD-1] must reject at load.
    keys = [token_key(), token_key(key_id="second-key-same-tuple")]
    with pytest.raises(RegistryError, match="tuple"):
        TrustRegistry.from_dict(registry_dict(keys))


def test_duplicate_key_id_rejected():
    keys = [token_key(), token_key(claim="AGE_OVER_21")]  # same key_id, different tuple
    with pytest.raises(RegistryError, match="key_id"):
        TrustRegistry.from_dict(registry_dict(keys))


def test_duplicate_issuer_id_rejected():
    # Two distinct, individually-valid issuer entries sharing an issuer_id
    # must be rejected, not silently collapsed by the dict comprehension.
    data = {
        "version": "1.0",
        "generated_at": "2026-07-21T00:00:00Z",
        "issuers": [issuer_dict([token_key()]), issuer_dict([token_key()])],
    }
    with pytest.raises(RegistryError, match="issuer_id"):
        TrustRegistry.from_dict(data)


def test_verify_registry_signature_rejects_malformed_base64_signature():
    _, pub = generate_root_keypair()
    assert verify_registry_signature(registry_dict(), "!!!not-base64!!!", pub) is False


def test_verify_registry_signature_rejects_malformed_public_key():
    priv, _ = generate_root_keypair()
    data = registry_dict()
    sig = sign_registry(data, priv)
    assert verify_registry_signature(data, sig, "!!!not-base64!!!") is False


def test_load_raises_registry_error_on_malformed_json(tmp_path: Path):
    priv, pub = generate_root_keypair()
    (tmp_path / "registry.json").write_text("{not json")
    (tmp_path / "registry.sig").write_text(sign_registry(registry_dict(), priv))
    with pytest.raises(RegistryError):
        TrustRegistry.load(tmp_path / "registry.json", tmp_path / "registry.sig", pub)


def test_load_raises_registry_error_on_missing_registry_file(tmp_path: Path):
    _, pub = generate_root_keypair()
    (tmp_path / "registry.sig").write_text("somesig")
    with pytest.raises(RegistryError):
        TrustRegistry.load(tmp_path / "missing.json", tmp_path / "registry.sig", pub)


def test_load_raises_registry_error_on_malformed_signature_file(tmp_path: Path):
    _, pub = generate_root_keypair()
    data = registry_dict()
    (tmp_path / "registry.json").write_text(json.dumps(data))
    (tmp_path / "registry.sig").write_text("!!!not-base64!!!")
    with pytest.raises(RegistryError):
        TrustRegistry.load(tmp_path / "registry.json", tmp_path / "registry.sig", pub)


def test_load_raises_registry_error_on_malformed_root_public_key(tmp_path: Path):
    priv, pub = generate_root_keypair()
    data = registry_dict()
    (tmp_path / "registry.json").write_text(json.dumps(data))
    (tmp_path / "registry.sig").write_text(sign_registry(data, priv))
    with pytest.raises(RegistryError):
        TrustRegistry.load(
            tmp_path / "registry.json", tmp_path / "registry.sig", "!!!not-base64!!!"
        )
