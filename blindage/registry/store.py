"""Trust registry loader and lookups.

``TrustRegistry.load`` accepts an optional ``anchor`` to gate a loaded registry
against an on-chain hash (fail closed on mismatch or lookup failure).
``blindage.registry_chain`` is imported lazily inside ``load`` so this module
stays importable without web3 in minimal environments.
"""
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
        seen_issuer_ids: set[str] = set()
        seen_material: set[str] = set()
        for issuer in issuers:
            if issuer.issuer_id in seen_issuer_ids:
                raise RegistryError(f"duplicate issuer_id {issuer.issuer_id!r}")
            seen_issuer_ids.add(issuer.issuer_id)
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
                    if key.public_key in seen_material:
                        raise RegistryError(
                            f"key material reuse detected for key_id {key.key_id!r}"
                        )
                    seen_material.add(key.public_key)
                elif key.purpose == "vc_signing":
                    # vc keys have claim=None, so they take no part in the
                    # (claim, assurance, epoch) tuple check — only key-material
                    # uniqueness applies.
                    if key.public_key in seen_material:
                        raise RegistryError(
                            f"key material reuse detected for key_id {key.key_id!r}"
                        )
                    seen_material.add(key.public_key)
        for issuer in issuers:
            for key in issuer.keys:
                if key.purpose == "registry" and key.public_key in seen_material:
                    raise RegistryError(
                        f"cross-purpose key material collision for key_id {key.key_id!r}"
                    )
        return cls({i.issuer_id: i for i in issuers})

    @classmethod
    def load(
        cls,
        registry_path: Path,
        signature_path: Path,
        root_public_key_b64: str,
        *,
        anchor=None,
    ) -> "TrustRegistry":
        try:
            data = json.loads(Path(registry_path).read_text())
            signature = Path(signature_path).read_text().strip()
            if not verify_registry_signature(data, signature, root_public_key_b64):
                raise RegistryError("registry signature verification failed")
            if anchor is not None:
                # Fail closed: an opt-in anchor gate that cannot be evaluated is
                # a hard error, never a silent fallback. Lazy import keeps this
                # module importable without web3 in minimal environments.
                from blindage.registry_chain.anchor import (
                    AnchorError,
                    registry_keccak,
                )

                try:
                    onchain = anchor.current()["registry_hash"]
                except AnchorError as exc:
                    raise RegistryError(f"anchor check unavailable: {exc}") from exc
                if registry_keccak(data) != onchain:
                    raise RegistryError("registry does not match the on-chain anchor")
            return cls.from_dict(data)
        except RegistryError:
            raise
        except (FileNotFoundError, OSError) as exc:
            raise RegistryError(f"failed to read registry files: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RegistryError(f"malformed registry JSON: {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise RegistryError(f"invalid registry input: {exc}") from exc

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
