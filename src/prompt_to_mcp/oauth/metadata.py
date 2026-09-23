"""Discovery of an upstream MCP server's OAuth 2.1 authorization server.

MCP's authorization spec layers RFC 9728 (protected resource metadata) on top
of RFC 8414 (authorization server metadata). A well-behaved MCP server answers
an unauthenticated request with ``401`` plus a ``WWW-Authenticate`` header
naming its resource metadata document; that document names the authorization
server; the authorization server's metadata names the endpoints we need.

We implement the full chain with fallbacks, because real servers implement
varying subsets of it.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ..ingest.fetcher import assert_safe_url

log = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(15.0, connect=6.0)


@dataclass(slots=True)
class AuthServerMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None = None
    revocation_endpoint: str | None = None
    scopes_supported: list[str] = field(default_factory=list)
    grant_types_supported: list[str] = field(default_factory=list)
    code_challenge_methods_supported: list[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def supports_dcr(self) -> bool:
        return bool(self.registration_endpoint)

    @property
    def supports_pkce(self) -> bool:
        # RFC 8414 says omitting the field means unknown. OAuth 2.1 mandates
        # PKCE, so absence is treated as "assume S256" rather than "no".
        return not self.code_challenge_methods_supported or (
            "S256" in self.code_challenge_methods_supported
        )

    @property
    def allows_public_client(self) -> bool:
        methods = self.token_endpoint_auth_methods_supported
        return "none" in methods if methods else False


def _parse_www_authenticate(header: str) -> dict[str, str]:
    """Extract quoted parameters from a ``WWW-Authenticate`` challenge."""
    return {m.group(1).lower(): m.group(2) for m in re.finditer(r'(\w+)="([^"]*)"', header)}


def _metadata_urls(issuer: str) -> list[str]:
    """Candidate RFC 8414 / OIDC discovery URLs for an issuer.

    RFC 8414 inserts the well-known segment *before* the issuer path, while
    OIDC appends it. Both appear in the wild, so try both.
    """
    parsed = urlparse(issuer)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    urls = [
        f"{origin}/.well-known/oauth-authorization-server{path}",
        f"{origin}/.well-known/openid-configuration{path}",
    ]
    if path:
        urls += [
            f"{issuer.rstrip('/')}/.well-known/oauth-authorization-server",
            f"{issuer.rstrip('/')}/.well-known/openid-configuration",
        ]
    else:
        urls.append(f"{origin}/.well-known/oauth-authorization-server")
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(urls))


async def _get_json(client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
    try:
        assert_safe_url(url)
    except ValueError as exc:
        log.warning("refusing to fetch metadata from %s: %s", url, exc)
        return None
    try:
        resp = await client.get(url, headers={"accept": "application/json"})
    except httpx.HTTPError as exc:
        log.debug("metadata fetch failed for %s: %s", url, exc)
        return None
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _build(data: dict[str, Any], fallback_issuer: str) -> AuthServerMetadata | None:
    auth_ep = data.get("authorization_endpoint")
    token_ep = data.get("token_endpoint")
    if not auth_ep or not token_ep:
        return None
    return AuthServerMetadata(
        issuer=data.get("issuer") or fallback_issuer,
        authorization_endpoint=auth_ep,
        token_endpoint=token_ep,
        registration_endpoint=data.get("registration_endpoint"),
        revocation_endpoint=data.get("revocation_endpoint"),
        scopes_supported=list(data.get("scopes_supported") or []),
        grant_types_supported=list(data.get("grant_types_supported") or []),
        code_challenge_methods_supported=list(data.get("code_challenge_methods_supported") or []),
        token_endpoint_auth_methods_supported=list(
            data.get("token_endpoint_auth_methods_supported") or []
        ),
        raw=data,
    )


async def discover_from_issuer(
    issuer: str, *, client: httpx.AsyncClient | None = None
) -> AuthServerMetadata | None:
    owns = client is None
    client = client or httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True)
    try:
        for url in _metadata_urls(issuer):
            data = await _get_json(client, url)
            if data and (md := _build(data, issuer)):
                log.info("discovered authorization server metadata at %s", url)
                return md
        return None
    finally:
        if owns:
            await client.aclose()


async def discover_for_mcp(
    mcp_url: str, *, client: httpx.AsyncClient | None = None
) -> AuthServerMetadata | None:
    """Full discovery chain starting from an MCP server endpoint."""
    owns = client is None
    client = client or httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True)
    try:
        issuers: list[str] = []

        # 1. Unauthenticated probe -> WWW-Authenticate -> resource metadata.
        try:
            assert_safe_url(mcp_url)
            probe = await client.post(
                mcp_url,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={"accept": "application/json, text/event-stream"},
            )
            if probe.status_code == 401:
                params = _parse_www_authenticate(probe.headers.get("www-authenticate", ""))
                prm_url = params.get("resource_metadata")
                if prm_url:
                    prm = await _get_json(client, prm_url)
                    if prm:
                        issuers += [
                            s
                            for s in (prm.get("authorization_servers") or [])
                            if isinstance(s, str)
                        ]
        except (httpx.HTTPError, ValueError) as exc:
            log.debug("MCP auth probe failed for %s: %s", mcp_url, exc)

        # 2. RFC 9728 well-known on the resource origin.
        parsed = urlparse(mcp_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not issuers:
            prm = await _get_json(client, urljoin(origin, "/.well-known/oauth-protected-resource"))
            if prm:
                issuers += [
                    s for s in (prm.get("authorization_servers") or []) if isinstance(s, str)
                ]

        # 3. Last resort: assume the resource is its own authorization server.
        issuers.append(origin)

        for issuer in dict.fromkeys(issuers):
            md = await discover_from_issuer(issuer, client=client)
            if md:
                return md
        return None
    finally:
        if owns:
            await client.aclose()
