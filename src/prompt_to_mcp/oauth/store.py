"""Persistence for the OAuth proxy.

Three record kinds:

``ProxyClient``
    The long-lived mapping between the synthetic client Gemini Enterprise uses
    and the real upstream client the proxy uses.
``AuthSession``
    Short-lived state spanning ``/authorize`` -> upstream -> ``/callback``.
``AuthCode``
    Short-lived one-time code spanning ``/callback`` -> ``/token``.

Cloud Run scales to zero and runs many instances, so in-process state is not an
option; the Firestore backend is the real one. The in-memory backend exists for
tests and local runs.
"""

from __future__ import annotations

import abc
import hashlib
import hmac
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any

#: Authorization codes and pending sessions are deliberately short-lived.
SESSION_TTL_SECONDS = 600
CODE_TTL_SECONDS = 120


def new_id(prefix: str, nbytes: int = 16) -> str:
    return f"{prefix}{secrets.token_urlsafe(nbytes)}"


def hash_secret(secret: str, salt: str) -> str:
    """PBKDF2 hash. We never persist a proxy client secret in the clear."""
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), salt.encode(), 200_000).hex()


def verify_secret(secret: str, salt: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret, salt), expected_hash)


@dataclass(slots=True)
class ProxyClient:
    """Synthetic client presented to Gemini Enterprise + real upstream client."""

    client_id: str
    client_secret_hash: str
    client_secret_salt: str
    mcp_id: str
    display_name: str

    # Upstream authorization server.
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str | None = None

    # Upstream client credentials. The secret lives in Secret Manager; this is
    # the resource name, not the value.
    upstream_client_id: str = ""
    upstream_client_secret_ref: str | None = None
    upstream_token_endpoint_auth_method: str = "client_secret_basic"
    dynamically_registered: bool = False

    scopes: list[str] = field(default_factory=list)
    #: Exact redirect URIs Gemini Enterprise is allowed to send us.
    allowed_redirect_uris: list[str] = field(default_factory=list)
    #: When true, any https redirect_uri is accepted. Gemini Enterprise does not
    #: publish a stable redirect URI, so this starts true and is pinned to the
    #: first observed value on first use (trust-on-first-use).
    pin_redirect_on_first_use: bool = True
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuthSession:
    """State held while the user is away at the upstream authorization server."""

    session_id: str
    client_id: str
    #: Where to send the user back to (Gemini Enterprise).
    downstream_redirect_uri: str
    downstream_state: str | None
    #: PKCE challenge Gemini Enterprise gave us; verified at /token.
    downstream_code_challenge: str | None
    downstream_code_challenge_method: str | None
    #: PKCE verifier the proxy generated for the *upstream* leg.
    upstream_code_verifier: str
    scopes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def expired(self) -> bool:
        return time.time() - self.created_at > SESSION_TTL_SECONDS

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuthCode:
    """One-time code the proxy issues to Gemini Enterprise."""

    code: str
    client_id: str
    #: The upstream code we will exchange once the downstream side redeems this.
    upstream_code: str
    upstream_code_verifier: str
    downstream_redirect_uri: str
    downstream_code_challenge: str | None
    downstream_code_challenge_method: str | None
    scopes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def expired(self) -> bool:
        return time.time() - self.created_at > CODE_TTL_SECONDS

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Store(abc.ABC):
    @abc.abstractmethod
    async def put_client(self, client: ProxyClient) -> None: ...

    @abc.abstractmethod
    async def get_client(self, client_id: str) -> ProxyClient | None: ...

    @abc.abstractmethod
    async def delete_client(self, client_id: str) -> None:
        """Revoke a proxy client.

        Required by teardown. A client left behind after its MCP is deleted is
        not inert: it still resolves, still redirects to the upstream, and
        still carries a dynamically-registered upstream client id -- a live
        credential the operator believes they removed.
        """

    @abc.abstractmethod
    async def put_session(self, session: AuthSession) -> None: ...

    @abc.abstractmethod
    async def pop_session(self, session_id: str) -> AuthSession | None: ...

    @abc.abstractmethod
    async def put_code(self, code: AuthCode) -> None: ...

    @abc.abstractmethod
    async def pop_code(self, code: str) -> AuthCode | None: ...


class MemoryStore(Store):
    """Non-durable backend for tests and local development."""

    def __init__(self) -> None:
        self._clients: dict[str, ProxyClient] = {}
        self._sessions: dict[str, AuthSession] = {}
        self._codes: dict[str, AuthCode] = {}

    async def put_client(self, client: ProxyClient) -> None:
        self._clients[client.client_id] = client

    async def get_client(self, client_id: str) -> ProxyClient | None:
        return self._clients.get(client_id)

    async def delete_client(self, client_id: str) -> None:
        self._clients.pop(client_id, None)

    async def put_session(self, session: AuthSession) -> None:
        self._sessions[session.session_id] = session

    async def pop_session(self, session_id: str) -> AuthSession | None:
        session = self._sessions.pop(session_id, None)
        return None if session is None or session.expired else session

    async def put_code(self, code: AuthCode) -> None:
        self._codes[code.code] = code

    async def pop_code(self, code: str) -> AuthCode | None:
        rec = self._codes.pop(code, None)
        return None if rec is None or rec.expired else rec


class FirestoreStore(Store):
    """Durable backend. Codes and sessions are deleted on read (single use)."""

    CLIENTS = "p2m_oauth_clients"
    SESSIONS = "p2m_oauth_sessions"
    CODES = "p2m_oauth_codes"

    def __init__(self, project_id: str, database: str = "(default)") -> None:
        from google.cloud import firestore

        self._db = firestore.AsyncClient(project=project_id, database=database)

    async def put_client(self, client: ProxyClient) -> None:
        await self._db.collection(self.CLIENTS).document(client.client_id).set(client.to_dict())

    async def get_client(self, client_id: str) -> ProxyClient | None:
        snap = await self._db.collection(self.CLIENTS).document(client_id).get()
        if not snap.exists:
            return None
        return ProxyClient(**snap.to_dict())

    async def delete_client(self, client_id: str) -> None:
        await self._db.collection(self.CLIENTS).document(client_id).delete()

    async def put_session(self, session: AuthSession) -> None:
        await self._db.collection(self.SESSIONS).document(session.session_id).set(session.to_dict())

    async def pop_session(self, session_id: str) -> AuthSession | None:
        ref = self._db.collection(self.SESSIONS).document(session_id)
        snap = await ref.get()
        if not snap.exists:
            return None
        await ref.delete()
        session = AuthSession(**snap.to_dict())
        return None if session.expired else session

    async def put_code(self, code: AuthCode) -> None:
        await self._db.collection(self.CODES).document(code.code).set(code.to_dict())

    async def pop_code(self, code: str) -> AuthCode | None:
        ref = self._db.collection(self.CODES).document(code)
        snap = await ref.get()
        if not snap.exists:
            return None
        # Deleting before use makes redemption single-shot even under
        # concurrent requests hitting different Cloud Run instances.
        await ref.delete()
        rec = AuthCode(**snap.to_dict())
        return None if rec.expired else rec
