import json
from pathlib import Path

from blindage.crypto import MockTokenSigner, b64u_decode
from blindage.schemas import AgeClaim, AssuranceLevel


class IssuerKeyStore:
    """Holds one signing key per (claim, assurance_level, epoch) tuple [MOD-1]."""

    def __init__(self, keys: list[dict]) -> None:
        self._by_tuple: dict[tuple, dict] = {}
        for entry in keys:
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
    ) -> tuple[MockTokenSigner, str] | None:
        entry = self._by_tuple.get((claim, assurance_level, epoch))
        if entry is None:
            return None
        signer = MockTokenSigner(
            key_id=entry["key_id"], secret=b64u_decode(entry["secret_b64"])
        )
        return signer, entry["valid_until"]

    def all_entries(self) -> list[dict]:
        return list(self._by_tuple.values())
