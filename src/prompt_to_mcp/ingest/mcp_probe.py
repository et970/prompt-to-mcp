"""Read the tool catalog from an MCP server that already exists.

When the operator points at a running MCP server rather than API docs, there is
nothing to generate: the server is authoritative about its own tools. We ask it
via ``tools/list`` and publish the answer to Agent Registry verbatim.

Some servers require authentication before they will answer. Google's hosted
MCP servers do not -- ``drivemcp.googleapis.com/mcp/v1`` returns its full
catalog unauthenticated -- but others will 401, in which case we register with
``NO_SPEC`` rather than failing the whole run.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from .fetcher import assert_safe_url

log = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(30.0, connect=10.0)
PROTOCOL_VERSION = "2025-06-18"


@dataclass(slots=True)
class McpProbeResult:
    url: str
    reachable: bool
    tools: list[dict[str, Any]] = field(default_factory=list)
    server_name: str | None = None
    requires_auth: bool = False
    error: str | None = None

    @property
    def tool_spec(self) -> dict[str, Any] | None:
        return {"tools": self.tools} if self.tools else None

    @property
    def tool_names(self) -> list[str]:
        return [t.get("name", "?") for t in self.tools]


def _parse_body(resp: httpx.Response) -> dict[str, Any] | None:
    """Handle both `application/json` and SSE-framed JSON-RPC replies."""
    ctype = resp.headers.get("content-type", "")
    text = resp.text
    if "text/event-stream" in ctype:
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except ValueError:
                    continue
        return None
    try:
        return resp.json()
    except ValueError:
        return None


async def probe(
    url: str,
    *,
    access_token: str | None = None,
    client: httpx.AsyncClient | None = None,
    allowed_hosts: list[str] | None = None,
) -> McpProbeResult:
    """Best-effort ``tools/list`` against a remote MCP server."""
    try:
        assert_safe_url(url, allowed_hosts)
    except ValueError as exc:
        return McpProbeResult(url=url, reachable=False, error=str(exc))

    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": PROTOCOL_VERSION,
    }
    if access_token:
        headers["authorization"] = f"Bearer {access_token}"

    owns = client is None
    client = client or httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True)
    try:
        # Many servers accept a bare tools/list; those that insist on a
        # handshake are handled by the initialize retry below.
        resp = await client.post(
            url,
            headers=headers,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )

        if resp.status_code == 401:
            return McpProbeResult(
                url=url,
                reachable=True,
                requires_auth=True,
                error="server requires authentication for tools/list",
            )

        payload = _parse_body(resp)
        tools = (payload or {}).get("result", {}).get("tools")

        if not tools:
            # Retry behind a proper initialize handshake.
            init = await client.post(
                url,
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "prompt-to-mcp", "version": "0.1.0"},
                    },
                },
            )
            init_payload = _parse_body(init) or {}
            server_name = (
                init_payload.get("result", {}).get("serverInfo", {}).get("name")
            )
            session = init.headers.get("mcp-session-id")
            if session:
                headers["mcp-session-id"] = session
            resp2 = await client.post(
                url,
                headers=headers,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            )
            payload2 = _parse_body(resp2) or {}
            tools = payload2.get("result", {}).get("tools") or []
            if not tools:
                detail = (
                    payload2.get("error", {}).get("message")
                    or f"HTTP {resp.status_code}"
                )
                return McpProbeResult(
                    url=url,
                    reachable=resp.status_code < 500,
                    server_name=server_name,
                    error=f"server returned no tools ({detail})",
                )
            return McpProbeResult(
                url=url, reachable=True, tools=tools, server_name=server_name
            )

        return McpProbeResult(url=url, reachable=True, tools=tools)

    except httpx.HTTPError as exc:
        return McpProbeResult(url=url, reachable=False, error=f"{type(exc).__name__}: {exc}")
    finally:
        if owns:
            await client.aclose()
