import json
import os
import secrets
import tempfile
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pydantic import BaseModel, ConfigDict, Field

from blindage.crypto import b64u_decode, b64u_encode
from blindage.schemas import AgeToken


class StoredToken(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: AgeToken
    spent: bool = False


class VaultData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enrollments: dict[str, str] = Field(default_factory=dict)
    tokens: list[StoredToken] = Field(default_factory=list)


class VaultError(Exception):
    pass


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )


class WalletVault:
    def __init__(self, path: Path, passphrase: str) -> None:
        self._path = Path(path)
        self._passphrase = passphrase

    def load(self) -> VaultData:
        if not self._path.exists():
            return VaultData()
        try:
            envelope = json.loads(self._path.read_text())
            key = _derive_key(self._passphrase, b64u_decode(envelope["salt"]))
            plaintext = ChaCha20Poly1305(key).decrypt(
                b64u_decode(envelope["nonce"]), b64u_decode(envelope["ciphertext"]), None
            )
            return VaultData.model_validate_json(plaintext)
        except (InvalidTag, KeyError, ValueError, TypeError) as exc:
            raise VaultError(f"cannot open vault: {exc}") from exc

    def save(self, data: VaultData) -> None:
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = _derive_key(self._passphrase, salt)
        ciphertext = ChaCha20Poly1305(key).encrypt(
            nonce, data.model_dump_json().encode("utf-8"), None
        )
        envelope = {
            "kdf": "argon2id",
            "salt": b64u_encode(salt),
            "nonce": b64u_encode(nonce),
            "ciphertext": b64u_encode(ciphertext),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=self._path.parent, prefix=f".{self._path.name}.", suffix=".tmp"
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(json.dumps(envelope))
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self._path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
