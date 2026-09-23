"""SSRF-hardened document fetching.

Doc URLs come from user prompts, so a naive ``httpx.get`` would let a caller
make the control plane read the GCE metadata server or internal VPC addresses.
Every hop of every redirect is validated against resolved IPs before we connect.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import NamedTuple
from urllib.parse import urlparse

import httpx

MAX_BYTES = 8 * 1024 * 1024
MAX_REDIRECTS = 5
TIMEOUT = httpx.Timeout(20.0, connect=8.0)

#: Sent when we expect a machine-readable spec. Servers that content-negotiate
#: will hand us JSON instead of their rendered documentation page.
SPEC_ACCEPT = "application/json, application/yaml, text/yaml, text/plain;q=0.5, */*;q=0.1"

_BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata",
    "localhost",
}


class FetchError(ValueError):
    pass


class FetchedDoc(NamedTuple):
    """A fetched document plus the metadata needed to sanity-check it."""

    text: str
    #: Lowercased media type with parameters stripped, e.g. ``text/html``.
    content_type: str
    #: The URL the body actually came from, after redirects.
    url: str

    def is_html(self) -> bool:
        return self.content_type in ("text/html", "application/xhtml+xml")


def _ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def assert_safe_url(url: str, allowed_hosts: list[str] | None = None) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise FetchError(f"only https URLs are allowed, got {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise FetchError("URL has no host")
    if host in _BLOCKED_HOSTNAMES:
        raise FetchError(f"host {host!r} is blocked")
    if allowed_hosts and host not in {h.lower() for h in allowed_hosts}:
        raise FetchError(f"host {host!r} is not in the allowlist")

    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError(f"could not resolve {host!r}: {exc}") from exc

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not _ip_is_public(ip):
            raise FetchError(f"host {host!r} resolves to non-public address {ip}")


async def fetch_document(
    url: str,
    *,
    allowed_hosts: list[str] | None = None,
    accept: str = "*/*",
) -> FetchedDoc:
    """GET a document, enforcing the URL policy on every redirect hop.

    Returns the body alongside its media type and final URL so callers can tell
    a spec from a rendered documentation page before trying to parse it.
    """
    current = url
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            assert_safe_url(current, allowed_hosts)
            resp = await client.get(current, headers={"accept": accept})
            if resp.is_redirect:
                location = resp.headers.get("location")
                if not location:
                    raise FetchError("redirect without Location header")
                current = str(httpx.URL(current).join(location))
                continue
            resp.raise_for_status()
            body = resp.content[: MAX_BYTES + 1]
            if len(body) > MAX_BYTES:
                raise FetchError(f"document exceeds {MAX_BYTES} bytes")
            ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            return FetchedDoc(
                text=body.decode(resp.encoding or "utf-8", errors="replace"),
                content_type=ctype,
                url=current,
            )
    raise FetchError("too many redirects")


async def fetch_text(url: str, *, allowed_hosts: list[str] | None = None) -> str:
    """Body-only convenience wrapper around :func:`fetch_document`."""
    doc = await fetch_document(url, allowed_hosts=allowed_hosts)
    return doc.text
