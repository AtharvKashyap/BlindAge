import json
from pathlib import Path

from blindage.crypto import (
    ED25519_ALGORITHM,
    MOCK_ALGORITHM,
    RSABSSA_ALGORITHM,
    Ed25519TokenSigner,
    MockTokenSigner,
    b64u_decode,
)
from blindage.schemas import AgeClaim, AssuranceLevel


def _entry_algorithm(entry: dict) -> str:
    # Entries without an explicit algorithm are legacy mock entries.
    return entry.get("algorithm", MOCK_ALGORITHM)


def public_material(entry: dict) -> tuple[str, str]:
    """(algorithm, public_key_b64) as published in registry/well-known.

    Ed25519/rsabssa: the real public key. Mock: the shared secret doubles as
    the 'public key' — documented Phase 1 test-only behavior.
    """
    algorithm = _entry_algorithm(entry)
    if algorithm in (ED25519_ALGORITHM, RSABSSA_ALGORITHM):
        return algorithm, entry["public_key_b64"]
    return algorithm, entry["secret_b64"]


class IssuerKeyStore:
    """Holds one signing key per (claim, assurance_level, epoch) tuple [MOD-1]."""

    def __init__(self, keys: list[dict]) -> None:
        self._by_tuple: dict[tuple, dict] = {}
        for entry in keys:
            algorithm = _entry_algorithm(entry)
            if algorithm not in (ED25519_ALGORITHM, MOCK_ALGORITHM, RSABSSA_ALGORITHM):
                raise ValueError(f"unsupported key algorithm: {algorithm!r}")
            binding = (
                AgeClaim(entry["claim"]),
                AssuranceLevel(entry["assurance_level"]),
                entry["epoch"],
            )
            if binding in self._by_tuple:
                raise ValueError(f"duplicate key tuple {binding}")
            self._by_tuple[binding] = entry

    @classmethod
    def from_file(cls, path: Path) -> "IssuerKeyStore":
        return cls(json.loads(Path(path).read_text())["keys"])

    def signer_for(
        self, claim: AgeClaim, assurance_level: AssuranceLevel, epoch: str
    ) -> tuple[Ed25519TokenSigner | MockTokenSigner, str] | None:
        entry = self._by_tuple.get((claim, assurance_level, epoch))
        if entry is None:
            return None
        algorithm = _entry_algorithm(entry)
        if algorithm == RSABSSA_ALGORITHM:
            # rsabssa keys never sign plaintext — only blind_signer_for.
            return None
        if algorithm == ED25519_ALGORITHM:
            signer: Ed25519TokenSigner | MockTokenSigner = Ed25519TokenSigner(
                key_id=entry["key_id"], private_key_b64=entry["private_key_b64"]
            )
        else:
            signer = MockTokenSigner(
                key_id=entry["key_id"], secret=b64u_decode(entry["secret_b64"])
            )
        return signer, entry["valid_until"]

    def blind_signer_for(
        self, claim: AgeClaim, assurance_level: AssuranceLevel, epoch: str
    ) -> tuple[str, str, str] | None:
        """(key_id, private_key_b64, valid_until) for rsabssa tuples only."""
        entry = self._by_tuple.get((claim, assurance_level, epoch))
        if entry is None or _entry_algorithm(entry) != RSABSSA_ALGORITHM:
            return None
        return entry["key_id"], entry["private_key_b64"], entry["valid_until"]

    def algorithm_for(
        self, claim: AgeClaim, assurance_level: AssuranceLevel, epoch: str
    ) -> str | None:
        entry = self._by_tuple.get((claim, assurance_level, epoch))
        if entry is None:
            return None
        return _entry_algorithm(entry)

    def all_entries(self) -> list[dict]:
        return list(self._by_tuple.values())
