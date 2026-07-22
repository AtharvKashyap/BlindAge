import base64
from typing import Protocol, runtime_checkable


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


@runtime_checkable
class TokenSigner(Protocol):
    algorithm: str
    key_id: str

    def sign(self, message: bytes) -> bytes: ...


@runtime_checkable
class TokenVerifier(Protocol):
    algorithm: str
    key_id: str

    def verify(self, message: bytes, signature: bytes) -> bool: ...
