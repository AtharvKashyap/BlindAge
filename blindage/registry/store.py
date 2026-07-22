import json
from pathlib import Path

from pydantic import ValidationError

from blindage.registry.signing import verify_registry_signature
from blindage.schemas import IssuerKey, IssuerMetadata


class RegistryError(Exception):
    pass


class TrustRegistry:
    def __init__(self, issuers: dict[str, IssuerMetadata]) -> None:
        self._issuers = issuers

    @classmethod
    def from_dict(cls, data: dict) -> "TrustRegistry":
        try:
            issuers = [IssuerMetadata.model_validate(i) for i in data["issuers"]]
        except (KeyError, ValidationError) as exc:
            raise RegistryError(f"invalid registry contents: {exc}") from exc
        for issuer in issuers:
            seen_ids: set[str] = set()
            seen_tuples: set[tuple] = set()
            for key in issuer.keys:
                if key.key_id in seen_ids:
                    raise RegistryError(f"duplicate key_id {key.key_id!r}")
                seen_ids.add(key.key_id)
                if key.purpose == "token_signing":
                    binding = (key.claim, key.assurance_level, key.epoch)
                    if binding in seen_tuples:
                        raise RegistryError(
                            f"duplicate (claim, assurance, epoch) tuple binding: {binding}"
                        )
                    seen_tuples.add(binding)
        return cls({i.issuer_id: i for i in issuers})

    @classmethod
    def load(
        cls, registry_path: Path, signature_path: Path, root_public_key_b64: str
    ) -> "TrustRegistry":
        data = json.loads(Path(registry_path).read_text())
        signature = Path(signature_path).read_text().strip()
        if not verify_registry_signature(data, signature, root_public_key_b64):
            raise RegistryError("registry signature verification failed")
        return cls.from_dict(data)

    def get_issuer(self, issuer_id: str) -> IssuerMetadata | None:
        return self._issuers.get(issuer_id)

    def get_token_key(self, issuer_id: str, key_id: str) -> IssuerKey | None:
        issuer = self.get_issuer(issuer_id)
        if issuer is None:
            return None
        for key in issuer.keys:
            if key.key_id == key_id and key.purpose == "token_signing":
                return key
        return None
