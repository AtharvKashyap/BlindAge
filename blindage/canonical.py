import json
from typing import Any

from pydantic import BaseModel


def canonical_json_bytes(data: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    """Deterministic JSON encoding used for all signed artifacts."""
    if isinstance(data, BaseModel):
        data = data.model_dump(mode="json", exclude_none=True)
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
