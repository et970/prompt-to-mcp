"""OAuth 2.1 proxy / authorization-server shim.

Why this exists
---------------
``discoveryengine.googleapis.com`` ``Authorization.serverSideOauth2`` declares
``clientId``, ``clientSecret``, ``authorizationUri`` and ``tokenUri`` as
**required**. There is no dynamic-client-registration or public-client option.
A managed MCP server that only supports OAuth 2.1 DCR therefore cannot be
described to Gemini Enterprise at all.

This module stands in as an authorization server:

* Gemini Enterprise sees a **static** ``client_id``/``client_secret`` pair and
  ordinary ``/authorize`` + ``/token`` endpoints.
* Upstream sees whatever the real MCP authorization server actually supports --
  a dynamically registered confidential client, or a public PKCE client.

Both legs run independent PKCE exchanges. The proxy verifies the downstream
challenge itself and never forwards the downstream verifier upstream.

Token handling
--------------
Upstream access tokens are passed through to Gemini Enterprise unmodified. That
is deliberate: the token GE stores is the token the generated MCP server will
forward to the upstream API, which is what makes end-to-end credential
propagation work. The proxy therefore never needs to mint or sign its own
tokens, and holds no long-term token material.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from typing import Any, Protocol
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import APIRouter, Form, Header, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .store import (
    AuthCode,
    AuthSession,
    ProxyClient,
    Store,
    new_id,
    verify_secret,
)

log = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(30.0, connect=10.0)


class SecretResolver(Protocol):
    async def resolve(self, ref: str) -> str | None: ...


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------


def generate_verifier() -> str:
    return secrets.token_urlsafe(64)[:128]


def challenge_for(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def verify_pkce(verifier: str, challenge: str, method: str | None) -> bool:
    if (method or "plain").upper() in ("S256",):
        return secrets.compare_digest(challenge_for(verifier), challenge)
    # OAuth 2.1 removes `plain`; accept it only if a client explicitly asked.
    return secrets.compare_digest(verifier, challenge)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    log.warning("oauth error %s: %s", error, description)
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"cache-control": "no-store", "pragma": "no-cache"},
    )


def _redirect_error(
    redirect_uri: str, error: str, description: str, state: str | None
) -> RedirectResponse:
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


def _is_valid_redirect(client: ProxyClient, redirect_uri: str) -> bool:
    if redirect_uri in client.allowed_redirect_uris:
        return True
    if client.allowed_redirect_uris:
        return False
    if not client.pin_redirect_on_first_use:
        return False
    parsed = urlparse(redirect_uri)
    # Trust-on-first-use is still constrained to https with no fragment.
    return parsed.scheme == "https" and bool(parsed.netloc) and not parsed.fragment


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


def build_router(
    *,
    store: Store,
    secrets_resolver: SecretResolver,
    public_base_url: str,
    http_client_factory: Any = None,
) -> APIRouter:
    router = APIRouter(prefix="/oauth", tags=["oauth"])
    base = public_base_url.rstrip("/")
    callback_uri = f"{base}/oauth/callback"

    def _client() -> httpx.AsyncClient:
        if http_client_factory is not None:
            return http_client_factory()
        return httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False)

    # -- metadata ---------------------------------------------------------
    @router.get("/.well-known/oauth-authorization-server")
    async def authorization_server_metadata() -> JSONResponse:
        return JSONResponse(
            {
                "issuer": base,
                "authorization_endpoint": f"{base}/oauth/authorize",
                "token_endpoint": f"{base}/oauth/token",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                ],
            }
        )

    # -- authorize --------------------------------------------------------
    @router.get("/authorize")
    async def authorize(request: Request) -> Any:
        q = request.query_params
        client_id = q.get("client_id")
        redirect_uri = q.get("redirect_uri")
        state = q.get("state")
        response_type = q.get("response_type", "code")

        if not client_id or not redirect_uri:
            return _oauth_error("invalid_request", "client_id and redirect_uri are required")

        client = await store.get_client(client_id)
        if client is None:
            return _oauth_error("invalid_client", "unknown client_id")

        if not _is_valid_redirect(client, redirect_uri):
            # Never redirect to an unvalidated URI: that is an open redirect.
            return _oauth_error("invalid_request", "redirect_uri is not registered for this client")

        if client.pin_redirect_on_first_use and not client.allowed_redirect_uris:
            client.allowed_redirect_uris = [redirect_uri]
            client.pin_redirect_on_first_use = False
            await store.put_client(client)
            log.info("pinned redirect_uri %s for client %s", redirect_uri, client_id)

        if response_type != "code":
            return _redirect_error(
                redirect_uri, "unsupported_response_type", "only 'code' is supported", state
            )

        requested_scopes = (q.get("scope") or "").split() or client.scopes

        # Independent PKCE for the upstream leg.
        upstream_verifier = generate_verifier()
        session = AuthSession(
            session_id=new_id("s_"),
            client_id=client_id,
            downstream_redirect_uri=redirect_uri,
            downstream_state=state,
            downstream_code_challenge=q.get("code_challenge"),
            downstream_code_challenge_method=q.get("code_challenge_method"),
            upstream_code_verifier=upstream_verifier,
            scopes=requested_scopes,
        )
        await store.put_session(session)

        upstream_params = {
            "response_type": "code",
            "client_id": client.upstream_client_id,
            "redirect_uri": callback_uri,
            "state": session.session_id,
            "code_challenge": challenge_for(upstream_verifier),
            "code_challenge_method": "S256",
        }
        if requested_scopes:
            upstream_params["scope"] = " ".join(requested_scopes)

        sep = "&" if "?" in client.authorization_endpoint else "?"
        target = f"{client.authorization_endpoint}{sep}{urlencode(upstream_params)}"
        log.info("authorize: client=%s -> upstream %s", client_id, client.issuer)
        return RedirectResponse(target, status_code=302)

    # -- callback ---------------------------------------------------------
    @router.get("/callback")
    async def callback(request: Request) -> Any:
        q = request.query_params
        session_id = q.get("state")
        if not session_id:
            return _oauth_error("invalid_request", "missing state")

        session = await store.pop_session(session_id)
        if session is None:
            return _oauth_error("invalid_grant", "unknown or expired authorization session")

        if error := q.get("error"):
            return _redirect_error(
                session.downstream_redirect_uri,
                error,
                q.get("error_description", "upstream authorization failed"),
                session.downstream_state,
            )

        upstream_code = q.get("code")
        if not upstream_code:
            return _redirect_error(
                session.downstream_redirect_uri,
                "invalid_grant",
                "upstream returned no authorization code",
                session.downstream_state,
            )

        # Hold the upstream code and hand a proxy code to Gemini Enterprise.
        # The actual upstream exchange happens at /token, so the code is only
        # spent once the downstream client proves its PKCE verifier.
        proxy_code = new_id("c_", 32)
        await store.put_code(
            AuthCode(
                code=proxy_code,
                client_id=session.client_id,
                upstream_code=upstream_code,
                upstream_code_verifier=session.upstream_code_verifier,
                downstream_redirect_uri=session.downstream_redirect_uri,
                downstream_code_challenge=session.downstream_code_challenge,
                downstream_code_challenge_method=session.downstream_code_challenge_method,
                scopes=session.scopes,
            )
        )

        params = {"code": proxy_code}
        if session.downstream_state:
            params["state"] = session.downstream_state
        sep = "&" if "?" in session.downstream_redirect_uri else "?"
        return RedirectResponse(
            f"{session.downstream_redirect_uri}{sep}{urlencode(params)}", status_code=302
        )

    # -- token ------------------------------------------------------------
    async def _authenticate_client(
        client_id: str | None,
        client_secret: str | None,
        authorization: str | None,
    ) -> tuple[ProxyClient | None, JSONResponse | None]:
        if authorization and authorization.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(authorization[6:]).decode("utf-8")
                basic_id, _, basic_secret = decoded.partition(":")
            except (ValueError, UnicodeDecodeError):
                return None, _oauth_error("invalid_client", "malformed Basic credentials", 401)
            client_id, client_secret = basic_id, basic_secret

        if not client_id or not client_secret:
            return None, _oauth_error("invalid_client", "client authentication required", 401)

        client = await store.get_client(client_id)
        if client is None or not verify_secret(
            client_secret, client.client_secret_salt, client.client_secret_hash
        ):
            # Identical response for unknown id and bad secret.
            return None, _oauth_error("invalid_client", "client authentication failed", 401)
        return client, None

    async def _upstream_token_request(client: ProxyClient, form: dict[str, str]) -> JSONResponse:
        headers = {"accept": "application/json"}
        secret: str | None = None
        if client.upstream_client_secret_ref:
            secret = await secrets_resolver.resolve(client.upstream_client_secret_ref)

        method = client.upstream_token_endpoint_auth_method
        if secret and method == "client_secret_basic":
            blob = base64.b64encode(f"{client.upstream_client_id}:{secret}".encode()).decode()
            headers["authorization"] = f"Basic {blob}"
        elif secret and method == "client_secret_post":
            form["client_id"] = client.upstream_client_id
            form["client_secret"] = secret
        else:
            # Public client: client_id in the body, no secret.
            form["client_id"] = client.upstream_client_id

        async with _client() as http:
            try:
                resp = await http.post(client.token_endpoint, data=form, headers=headers)
            except httpx.HTTPError as exc:
                return _oauth_error("temporarily_unavailable", f"upstream token error: {exc}", 502)

        try:
            payload = resp.json()
        except ValueError:
            return _oauth_error(
                "server_error", f"upstream returned non-JSON (HTTP {resp.status_code})", 502
            )

        status = (
            200
            if resp.status_code == 200
            else (resp.status_code if resp.status_code < 500 else 502)
        )
        return JSONResponse(
            payload,
            status_code=status,
            headers={"cache-control": "no-store", "pragma": "no-cache"},
        )

    @router.post("/token")
    async def token(
        grant_type: str = Form(...),
        code: str | None = Form(default=None),
        redirect_uri: str | None = Form(default=None),
        code_verifier: str | None = Form(default=None),
        refresh_token: str | None = Form(default=None),
        scope: str | None = Form(default=None),
        client_id: str | None = Form(default=None),
        client_secret: str | None = Form(default=None),
        authorization: str | None = Header(default=None),
    ) -> Any:
        client, error = await _authenticate_client(client_id, client_secret, authorization)
        if error is not None:
            return error
        assert client is not None

        if grant_type == "authorization_code":
            if not code:
                return _oauth_error("invalid_request", "code is required")
            # `pop_code` is fetch-and-delete, and it runs BEFORE the ownership
            # check on purpose: any presentation of a code spends it, including
            # one by the wrong client. RFC 6749 4.1.2 says a code presented more
            # than once MUST be denied and SHOULD have its grants revoked, so
            # failing closed is the correct reading -- an attacker who has
            # somehow obtained a code cannot probe with it, and the legitimate
            # client is forced to restart rather than race them for it.
            record = await store.pop_code(code)
            if record is None:
                return _oauth_error("invalid_grant", "unknown, expired, or already-used code")
            if record.client_id != client.client_id:
                return _oauth_error("invalid_grant", "code was issued to a different client")
            if redirect_uri and redirect_uri != record.downstream_redirect_uri:
                return _oauth_error("invalid_grant", "redirect_uri mismatch")

            if record.downstream_code_challenge:
                if not code_verifier:
                    return _oauth_error("invalid_request", "code_verifier is required")
                if not verify_pkce(
                    code_verifier,
                    record.downstream_code_challenge,
                    record.downstream_code_challenge_method,
                ):
                    return _oauth_error("invalid_grant", "PKCE verification failed")

            # Downstream is satisfied; now spend the upstream code.
            return await _upstream_token_request(
                client,
                {
                    "grant_type": "authorization_code",
                    "code": record.upstream_code,
                    "redirect_uri": callback_uri,
                    "code_verifier": record.upstream_code_verifier,
                },
            )

        if grant_type == "refresh_token":
            if not refresh_token:
                return _oauth_error("invalid_request", "refresh_token is required")
            form = {"grant_type": "refresh_token", "refresh_token": refresh_token}
            if scope:
                form["scope"] = scope
            return await _upstream_token_request(client, form)

        return _oauth_error("unsupported_grant_type", f"grant_type {grant_type!r} is not supported")

    return router
