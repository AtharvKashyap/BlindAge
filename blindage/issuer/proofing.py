"""Pluggable identity proofing for the issuer.

TestDobProofing keeps the Phase 6 TEST-ONLY asserted-DOB flow (unit tests, CLI).
OidcProofing runs a real OIDC Authorization Code + PKCE flow and derives the DOB
from a validated ID token's `birthdate` claim. Fail closed: any defect raises
ProofingError and no enrollment is created. Constitution rule 4: JOSE handling
is PyJWT (reviewed), never hand-rolled.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import date
from urllib.parse import urlencode

import httpx
import jwt


class ProofingError(Exception):
    pass


class TestDobProofing:
    """Marker: the issuer serves the Phase 6 TEST-ONLY DOB form."""


@dataclass(frozen=True)
class OidcConfig:
    idp_base_url: str
    client_id: str
    client_secret: str
    redirect_uri: str


@dataclass(frozen=True)
class ProofingSession:
    state: str
    nonce: str
    verifier: str
    created_at: float


class ProofingSessionStore:
    """In-memory, single-use, TTL-bound OIDC sessions (state -> session)."""

    def __init__(self, ttl_seconds: float = 600.0) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._sessions: dict[str, ProofingSession] = {}

    def create(self, now: float | None = None) -> ProofingSession:
        session = ProofingSession(
            state=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(32),
            verifier=secrets.token_urlsafe(64),
            created_at=time.time() if now is None else now,
        )
        with self._lock:
            self._sessions[session.state] = session
        return session

    def consume(self, state: str, now: float | None = None) -> ProofingSession | None:
        now = time.time() if now is None else now
        with self._lock:
            session = self._sessions.pop(state, None)
        if session is None or now - session.created_at > self._ttl:
            return None
        return session


def code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def validate_id_token(
    id_token: str, jwks: dict, *, issuer: str, audience: str, nonce: str
) -> date:
    """Validate an OIDC ID token and return its birthdate. Fail closed."""
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise ProofingError(f"unparseable id token: {exc}") from None
    if header.get("alg") != "RS256":  # allowlist: exactly RS256, no negotiation
        raise ProofingError("id token alg is not RS256")
    kid = header.get("kid")
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if jwk is None:
        raise ProofingError("id token signed by unknown key")
    try:
        key = jwt.PyJWK.from_dict(jwk).key
        claims = jwt.decode(
            id_token, key=key, algorithms=["RS256"], audience=audience, issuer=issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise ProofingError(f"id token rejected: {exc}") from None
    if claims.get("nonce") != nonce:
        raise ProofingError("id token nonce mismatch")
    birthdate = claims.get("birthdate")
    try:
        return date.fromisoformat(birthdate)
    except (TypeError, ValueError):
        raise ProofingError("id token missing or malformed birthdate") from None


class OidcProofing:
    """Authorization Code + PKCE against a configured IdP."""

    def __init__(
        self,
        config: OidcConfig,
        http: httpx.Client,
        sessions: ProofingSessionStore | None = None,
    ) -> None:
        self._config = config
        self._http = http
        self._sessions = sessions or ProofingSessionStore()
        self._discovery: dict | None = None
        self._jwks: dict | None = None

    def _discover(self) -> dict:
        if self._discovery is None:
            resp = self._http.get(
                f"{self._config.idp_base_url}/.well-known/openid-configuration"
            )
            if resp.status_code != 200:
                raise ProofingError(f"IdP discovery failed ({resp.status_code})")
            self._discovery = resp.json()
        return self._discovery

    def _get_jwks(self) -> dict:
        if self._jwks is None:
            resp = self._http.get(self._discover()["jwks_uri"])
            if resp.status_code != 200:
                raise ProofingError(f"IdP JWKS fetch failed ({resp.status_code})")
            self._jwks = resp.json()
        return self._jwks

    def authorize_redirect_url(self) -> str:
        session = self._sessions.create()
        query = urlencode({
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
            "scope": "openid",
            "state": session.state,
            "nonce": session.nonce,
            "code_challenge": code_challenge_s256(session.verifier),
            "code_challenge_method": "S256",
        })
        return f"{self._discover()['authorization_endpoint']}?{query}"

    def handle_callback(self, code: str, state: str) -> date:
        session = self._sessions.consume(state)
        if session is None:
            raise ProofingError("unknown, expired, or reused state")
        resp = self._http.post(self._discover()["token_endpoint"], data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._config.redirect_uri,
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code_verifier": session.verifier,
        })
        if resp.status_code != 200:
            raise ProofingError(f"token exchange failed ({resp.status_code})")
        id_token = resp.json().get("id_token")
        if not isinstance(id_token, str):
            raise ProofingError("no id_token in token response")
        return validate_id_token(
            id_token, self._get_jwks(),
            issuer=self._discover()["issuer"],
            audience=self._config.client_id,
            nonce=session.nonce,
        )
