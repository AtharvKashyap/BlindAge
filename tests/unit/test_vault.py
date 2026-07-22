import json
import stat
import sys
from pathlib import Path

import pytest

from blindage.schemas import AgeClaim, AgeToken, AssuranceLevel
from blindage.wallet.vault import StoredToken, VaultData, VaultError, WalletVault


def make_token() -> AgeToken:
    return AgeToken(
        claim=AgeClaim.AGE_OVER_18,
        assurance_level=AssuranceLevel.AAL2,
        epoch="2026-Q3",
        issuer_id="did:web:issuer.test",
        issuer_key_id="dev-AGE_OVER_18-AAL2-2026-Q3",
        nonce="bm9uY2U",
        signature="c2ln",
    )


def test_empty_vault_when_file_missing(tmp_path: Path):
    vault = WalletVault(tmp_path / "vault.blindage", "pass")
    data = vault.load()
    assert data.tokens == [] and data.enrollments == {}


def test_save_load_round_trip(tmp_path: Path):
    vault = WalletVault(tmp_path / "vault.blindage", "pass")
    data = VaultData(
        enrollments={"http://localhost:8000": "eid-1"},
        tokens=[StoredToken(token=make_token())],
    )
    vault.save(data)
    loaded = WalletVault(tmp_path / "vault.blindage", "pass").load()
    assert loaded == data


def test_wrong_passphrase_raises(tmp_path: Path):
    vault = WalletVault(tmp_path / "vault.blindage", "pass")
    vault.save(VaultData())
    with pytest.raises(VaultError):
        WalletVault(tmp_path / "vault.blindage", "wrong").load()


def test_file_is_ciphertext_not_plaintext(tmp_path: Path):
    path = tmp_path / "vault.blindage"
    WalletVault(path, "pass").save(VaultData(tokens=[StoredToken(token=make_token())]))
    on_disk = path.read_text()
    assert "AGE_OVER_18" not in on_disk
    assert "bm9uY2U" not in on_disk
    envelope = json.loads(on_disk)
    assert set(envelope) == {"kdf", "salt", "nonce", "ciphertext"}
    assert envelope["kdf"] == "argon2id"


def test_spent_state_persists_inside_vault(tmp_path: Path):
    path = tmp_path / "vault.blindage"
    vault = WalletVault(path, "pass")
    data = VaultData(tokens=[StoredToken(token=make_token())])
    data.tokens[0].spent = True
    vault.save(data)
    assert WalletVault(path, "pass").load().tokens[0].spent is True


def test_load_raises_vault_error_on_non_dict_json(tmp_path: Path):
    path = tmp_path / "vault.blindage"
    path.write_text(json.dumps([1, 2, 3]))
    vault = WalletVault(path, "pass")
    with pytest.raises(VaultError):
        vault.load()


def test_save_leaves_no_temp_file_and_sets_restrictive_permissions(tmp_path: Path):
    path = tmp_path / "vault.blindage"
    vault = WalletVault(path, "pass")
    vault.save(VaultData(tokens=[StoredToken(token=make_token())]))

    leftover = list(tmp_path.glob("*.tmp"))
    assert leftover == []

    if sys.platform != "win32":
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600
