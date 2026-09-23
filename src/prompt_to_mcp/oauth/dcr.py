"""RFC 7591 Dynamic Client Registration against an upstream authorization server.

This is the piece that closes the gap described in the design notes: Gemini
Enterprise's ``Authorization.serverSideOauth2`` marks ``clientId`` and
``clientSecret`` as *required*, but an OAuth 2.1 MCP server may only support
dynamically registered or public PKCE clients. We register on the operator's
behalf, keep whatever real credentials come back, and let the proxy present a
stable synthetic pair to Gemini Enterprise.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from ..ingest.fetcher import assert_safe_url
from .metadata import AuthServerMetadata

log = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(20.0, connect=8.0)


class DCRError(RuntimeError):
    pass


@dataclass(slots=True)
class UpstreamClient:
    """Credentials the proxy uses when talking to the upstream AS."""

    client_id: str
    client_secret: str | None
    #: How we authenticate at the token endpoint.
    token_endpoint_auth_method: str = "client_secret_basic"
    registration_access_token: str | None = None
    registration_client_uri: str | None = None
    #: True when the credentials came from DCR rather than the operator.
    dynamically_registered: bool = False

    @property
    def is_public(self) -> bool:
        return not self.client_secret or self.token_endpoint_auth_method == "none"


def _choose_auth_method(metadata: AuthServerMetadata, has_secret: bool) -> str:
    supported = metadata.token_endpoint_auth_methods_supported
    if not has_secret:
        return "none"
    for preferred in ("client_secret_basic", "client_secret_post"):
        if not supported or preferred in supported:
            return preferred
    return supported[0]


async def register_client(
    metadata: AuthServerMetadata,
    *,
    redirect_uri: str,
    client_name: str,
    scopes: list[str] | None = None,
    initial_access_token: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> UpstreamClient:
    """Perform RFC 7591 registration. Raises :class:`DCRError` on failure."""
    if not metadata.registration_endpoint:
        raise DCRError("authorization server advertises no registration_endpoint")

    assert_safe_url(metadata.registration_endpoint)

    payload: dict[str, Any] = {
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "application_type": "web",
    }
    if scopes:
        payload["scope"] = " ".join(scopes)

    headers = {"content-type": "application/json", "accept": "application/json"}
    if initial_access_token:
        headers["authorization"] = f"Bearer {initial_access_token}"

    owns = client is None
    client = client or httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False)
    try:
        resp = await client.post(metadata.registration_endpoint, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        raise DCRError(f"registration request failed: {exc}") from exc
    finally:
        if owns:
            await client.aclose()

    if resp.status_code not in (200, 201):
        raise DCRError(f"registration rejected with HTTP {resp.status_code}: {resp.text[:500]}")

    try:
        data = resp.json()
    except ValueError as exc:
        raise DCRError("registration response was not JSON") from exc

    client_id = data.get("client_id")
    if not client_id:
        raise DCRError("registration response contained no client_id")

    secret = data.get("client_secret")
    method = data.get("token_endpoint_auth_method") or _choose_auth_method(
        metadata, has_secret=bool(secret)
    )

    log.info(
        "dynamically registered upstream client %s (public=%s) at %s",
        client_id,
        not secret,
        metadata.registration_endpoint,
    )
    return UpstreamClient(
        client_id=client_id,
        client_secret=secret,
        token_endpoint_auth_method=method,
        registration_access_token=data.get("registration_access_token"),
        registration_client_uri=data.get("registration_client_uri"),
        dynamically_registered=True,
    )


async def resolve_upstream_client(
    metadata: AuthServerMetadata,
    *,
    redirect_uri: str,
    client_name: str,
    scopes: list[str] | None = None,
    provided_client_id: str | None = None,
    provided_client_secret: str | None = None,
    initial_access_token: str | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> UpstreamClient:
    """Pick the best available way to authenticate to the upstream AS.

    Priority:

    1. Operator-supplied static credentials (nothing to solve).
    2. RFC 7591 dynamic registration, when advertised.
    3. Public PKCE client, when the AS permits ``token_endpoint_auth_method=none``.

    Otherwise we fail loudly rather than deploying something that cannot work.
    """
    if provided_client_id:
        return UpstreamClient(
            client_id=provided_client_id,
            client_secret=provided_client_secret,
            token_endpoint_auth_method=_choose_auth_method(
                metadata, has_secret=bool(provided_client_secret)
            ),
        )

    if metadata.supports_dcr:
        try:
            return await register_client(
                metadata,
                redirect_uri=redirect_uri,
                client_name=client_name,
                scopes=scopes,
                initial_access_token=initial_access_token,
                client=http_client,
            )
        except DCRError as exc:
            log.warning("dynamic registration failed, considering public client: %s", exc)

    if metadata.allows_public_client and metadata.supports_pkce:
        log.info("falling back to public PKCE client against %s", metadata.issuer)
        return UpstreamClient(
            client_id=f"public-{client_name}",
            client_secret=None,
            token_endpoint_auth_method="none",
        )

    raise DCRError(
        f"authorization server {metadata.issuer} offers no usable client acquisition path: "
        "no registration_endpoint, no public-client support, and no static credentials were "
        "supplied. Provide upstream_client_id/upstream_client_secret explicitly."
    )
