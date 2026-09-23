"""Detect documentation that describes an *existing* MCP server.

Pasting a provider's "configure the MCP server" page into the generate-from-docs
flow is a natural mistake: the page looks like API documentation, but it does
not describe an API to wrap -- it describes an MCP server that already exists.
Generating a wrapper from it produces something meaningless.

Rather than failing, we detect the standard ``mcpServers`` client-configuration
block that every such page contains and switch modes automatically, saying so.

Example, from Google's Drive MCP guide:

.. code-block:: json

    {"mcpServers": {"drive": {"serverUrl": "https://drivemcp.googleapis.com/mcp/v1",
                              "oauth": {"clientId": "...", "clientSecret": "..."}}}}
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Keys used for the endpoint inside an mcpServers entry, across clients.
_URL_KEYS = ("serverUrl", "server_url", "url", "endpoint", "httpUrl")

_URL_RE = re.compile(
    r'"(?:' + "|".join(_URL_KEYS) + r')"\s*:\s*"(https://[^"\s]+)"',
    re.IGNORECASE,
)
#: Anchors that indicate the surrounding text really is MCP client config.
_ANCHOR_RE = re.compile(r'"?mcp[_-]?servers"?\s*[:=]', re.IGNORECASE)

#: A URL that looks like an MCP endpoint even without a config block.
_MCP_URL_RE = re.compile(
    r"https://[a-z0-9.\-]*mcp[a-z0-9.\-]*\.[a-z]{2,}/[^\s\"'<>]*", re.IGNORECASE
)


@dataclass(slots=True)
class DetectedMcp:
    url: str
    reason: str


def detect_mcp_server_url(text: str) -> DetectedMcp | None:
    """Find an existing MCP server endpoint described by this documentation.

    Returns ``None`` unless the evidence is strong, because a false positive
    silently changes what gets built.
    """
    if not text:
        return None

    anchor = _ANCHOR_RE.search(text)
    if anchor:
        # Prefer a URL near the mcpServers block: docs often contain many URLs.
        window = text[anchor.start() : anchor.start() + 4000]
        match = _URL_RE.search(window)
        if match:
            return DetectedMcp(
                url=match.group(1),
                reason="the documentation contains an `mcpServers` client configuration block",
            )
        # Anchor present but no keyed URL; fall back to an MCP-looking URL nearby.
        loose = _MCP_URL_RE.search(window)
        if loose:
            return DetectedMcp(
                url=loose.group(0).rstrip(".,);"),
                reason="the documentation contains an `mcpServers` block naming this endpoint",
            )

    # No anchor: only trust an explicit serverUrl key, which is unambiguous.
    match = re.search(
        r'"(?:serverUrl|server_url)"\s*:\s*"(https://[^"\s]+)"', text, re.IGNORECASE
    )
    if match:
        return DetectedMcp(
            url=match.group(1),
            reason="the documentation declares a `serverUrl` for an MCP server",
        )
    return None
