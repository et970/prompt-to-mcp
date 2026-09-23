"""Generic, manifest-driven MCP server.

One container image serves *any* :class:`ToolManifest`. The manifest arrives at
boot via ``P2M_MANIFEST`` (inline JSON) or ``P2M_MANIFEST_GCS`` (a gs:// URI),
and is turned into MCP tools that proxy to the documented upstream API. No
model-authored code is ever compiled or executed here -- the manifest is pure
declarative data.

Credential propagation
----------------------
Gemini Enterprise obtains an end-user access token through the Discovery Engine
authorization resource and presents it as ``Authorization: Bearer <token>``.
When the manifest declares ``auth.kind == "oauth_user"`` we forward that exact
token upstream, so the upstream API sees the *end user* rather than a shared
service identity. The token is read per-request from the HTTP request that the
MCP SDK attaches to the handler context; it is never logged and never cached.

Written against the mcp 2.x lowlevel API (``on_list_tools`` / ``on_call_tool``
constructor callbacks). The 1.x decorator API is not compatible.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any
from urllib.parse import quote

import httpx
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.server import ServerRequestContext
from starlette.responses import JSONResponse
from starlette.routing import Route

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("p2m.runtime")

UPSTREAM_TIMEOUT = httpx.Timeout(float(os.getenv("P2M_UPSTREAM_TIMEOUT", "45")), connect=10.0)
MAX_RESPONSE_BYTES = int(os.getenv("P2M_MAX_RESPONSE_BYTES", str(1024 * 1024)))

#: Headers a tool argument may never set, because they would let a caller
#: impersonate another principal or redirect the request.
FORBIDDEN_HEADERS = {"authorization", "cookie", "host", "proxy-authorization"}


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------


def load_manifest() -> dict[str, Any]:
    inline = os.getenv("P2M_MANIFEST")
    if inline:
        return json.loads(inline)

    gcs_uri = os.getenv("P2M_MANIFEST_GCS")
    if gcs_uri:
        if not gcs_uri.startswith("gs://"):
            raise ValueError(f"P2M_MANIFEST_GCS must be a gs:// URI, got {gcs_uri!r}")
        from google.cloud import storage

        bucket_name, _, blob_name = gcs_uri[5:].partition("/")
        data = storage.Client().bucket(bucket_name).blob(blob_name).download_as_bytes()
        return json.loads(data)

    path = os.getenv("P2M_MANIFEST_FILE", "/etc/p2m/manifest.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    raise RuntimeError("no manifest: set P2M_MANIFEST, P2M_MANIFEST_GCS, or P2M_MANIFEST_FILE")


def load_api_key() -> str | None:
    """The upstream API key, for manifests declaring ``api_key`` auth.

    Cloud Run populates ``P2M_API_KEY`` from Secret Manager at start-up, so the
    key exists only in this process's environment. It is deliberately *not* in
    the manifest: that is persisted to Firestore, injected as a plain env var
    and served verbatim in the downloadable package, so a key stored there
    would be exposed three separate ways. The manifest carries only a Secret
    Manager reference, which is safe to read.
    """
    return os.getenv("P2M_API_KEY") or None


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------


class UpstreamError(RuntimeError):
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"upstream returned HTTP {status}: {body[:2000]}")


def _set_body_path(body: dict[str, Any], path: str, value: Any) -> None:
    """Assign ``value`` into ``body`` at a dotted ``path``."""
    parts = [p for p in path.split(".") if p]
    cursor = body
    for part in parts[:-1]:
        nxt = cursor.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[part] = nxt
        cursor = nxt
    cursor[parts[-1]] = value


class ToolInvoker:
    """Builds and issues the upstream HTTP call for one tool."""

    def __init__(
        self,
        manifest: dict[str, Any],
        client: httpx.AsyncClient,
        *,
        api_key: str | None = None,
    ) -> None:
        self.base_url: str = manifest["base_url"].rstrip("/")
        self.auth: dict[str, Any] = manifest.get("auth") or {}
        self.client = client
        self.api_key = api_key
        self.tools: dict[str, dict[str, Any]] = {t["name"]: t for t in manifest.get("tools", [])}

    def _require_api_key(self) -> str:
        if not self.api_key:
            raise PermissionError(
                "this server is configured for API-key authentication but no key is "
                "present. Cloud Run populates P2M_API_KEY from Secret Manager; check "
                "that the service still has its secret binding and that its service "
                "account can read the secret."
            )
        return self.api_key

    # -- auth ------------------------------------------------------------
    def auth_headers(self, inbound_token: str | None) -> dict[str, str]:
        kind = self.auth.get("kind", "none")
        if kind == "none":
            return {}

        if kind == "oauth_user":
            if not inbound_token:
                raise PermissionError(
                    "this tool requires an end-user credential, but the request carried no "
                    "Authorization bearer token. Check that the Gemini Enterprise "
                    "authorization resource is attached and that the user has consented."
                )
            header = self.auth.get("header") or "Authorization"
            scheme = self.auth.get("scheme") or "Bearer"
            return {header: f"{scheme} {inbound_token}".strip()}

        if kind == "api_key":
            # A query-placed key is added by auth_params instead; returning {}
            # here keeps the two paths from both writing the credential.
            if self.auth.get("key_location") == "query":
                return {}
            header = self.auth.get("header") or "Authorization"
            scheme = self.auth.get("scheme") or ""
            key = self._require_api_key()
            return {header: f"{scheme} {key}".strip() if scheme else key}

        if kind == "google_id_token":
            import google.auth.transport.requests
            import google.oauth2.id_token

            token = google.oauth2.id_token.fetch_id_token(
                google.auth.transport.requests.Request(), self.base_url
            )
            return {"Authorization": f"Bearer {token}"}

        raise ValueError(f"unsupported auth kind {kind!r}")

    def auth_params(self) -> dict[str, str]:
        """Query-string credentials. Empty for every auth kind but ``api_key``.

        Some APIs accept a key only as ``?key=``; Google's Generative Language
        API accepts either that or ``x-goog-api-key``.
        """
        if self.auth.get("kind") != "api_key" or self.auth.get("key_location") != "query":
            return {}
        return {self.auth.get("query_param") or "key": self._require_api_key()}

    # -- request building -------------------------------------------------
    def build_request(
        self, tool: dict[str, Any], args: dict[str, Any]
    ) -> tuple[str, str, dict[str, Any], dict[str, str], dict[str, Any] | None]:
        path: str = tool["path"]
        query: dict[str, Any] = {}
        headers: dict[str, str] = dict(tool.get("headers") or {})
        body: dict[str, Any] = {}
        raw_body: Any = None
        has_body = False

        declared = {p["name"]: p for p in tool.get("params", [])}
        unknown = set(args) - set(declared)
        if unknown:
            raise ValueError(f"unknown argument(s): {', '.join(sorted(unknown))}")

        for name, param in declared.items():
            if name not in args or args[name] is None:
                if param.get("required"):
                    raise ValueError(f"missing required argument {name!r}")
                continue
            value = args[name]
            location = param["location"]

            if location == "path":
                # quote() stops an argument escaping its own path segment.
                encoded = quote(str(value), safe="")
                path = path.replace("{" + name + "}", encoded)
                if original := param.get("origin_name"):
                    path = path.replace("{" + original + "}", encoded)
            elif location == "query":
                query[param.get("origin_name") or name] = value
            elif location == "header":
                header_name = param.get("origin_name") or name
                if header_name.lower() in FORBIDDEN_HEADERS:
                    raise ValueError(f"parameter {name!r} may not set the {header_name} header")
                headers[header_name] = str(value)
            elif location == "body":
                has_body = True
                body_path = param.get("body_path")
                if body_path in (None, ""):
                    raw_body = value
                else:
                    _set_body_path(body, body_path, value)

        if leftover := re.findall(r"\{([^}]+)\}", path):
            raise ValueError(f"unfilled path placeholder(s): {', '.join(leftover)}")

        payload: dict[str, Any] | None = None
        if has_body:
            payload = raw_body if raw_body is not None else body

        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        return tool["method"], url, query, headers, payload

    # -- invocation -------------------------------------------------------
    async def invoke(
        self, name: str, args: dict[str, Any], *, inbound_token: str | None = None
    ) -> str:
        tool = self.tools.get(name)
        if tool is None:
            raise ValueError(f"unknown tool {name!r}")

        method, url, query, headers, payload = self.build_request(tool, args)
        # Credentials are applied last so a tool argument can never shadow them.
        headers.update(self.auth_headers(inbound_token))
        query.update(self.auth_params())
        headers.setdefault("accept", "application/json")

        resp = await self.client.request(
            method,
            url,
            params=query or None,
            headers=headers,
            json=payload if payload is not None else None,
        )

        content = resp.content[: MAX_RESPONSE_BYTES + 1]
        truncated = len(content) > MAX_RESPONSE_BYTES
        text = content[:MAX_RESPONSE_BYTES].decode(resp.encoding or "utf-8", errors="replace")

        if resp.status_code >= 400:
            raise UpstreamError(resp.status_code, text)
        if truncated:
            text += f"\n\n[truncated at {MAX_RESPONSE_BYTES} bytes]"
        return text


# ---------------------------------------------------------------------------
# MCP wiring
# ---------------------------------------------------------------------------


def input_schema_for(tool: dict[str, Any]) -> dict[str, Any]:
    props: dict[str, Any] = {}
    required: list[str] = []
    for p in tool.get("params", []):
        entry = dict(p.get("schema") or {"type": "string"})
        if p.get("description"):
            entry.setdefault("description", p["description"])
        props[p["name"]] = entry
        if p.get("required"):
            required.append(p["name"])
    schema: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


def bearer_from_request(request: Any) -> str | None:
    """Extract the end-user bearer token from the inbound HTTP request."""
    if request is None:
        return None
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    value = headers.get("authorization") or ""
    if value[:7].lower() == "bearer ":
        return value[7:].strip() or None
    return None


def build_app(manifest: dict[str, Any] | None = None, api_key: str | None = None):  # noqa: ANN201
    manifest = manifest or load_manifest()
    server_name = manifest.get("name", "generated-mcp")
    tools_cfg: list[dict[str, Any]] = manifest.get("tools", [])
    auth_cfg: dict[str, Any] = manifest.get("auth") or {}
    api_key = api_key if api_key is not None else load_api_key()

    # Whether a key is present, never the key. An API-key server that boots
    # without its key fails on the first tool call with an upstream 401, which
    # looks like a bad key rather than a missing one; saying so at start-up is
    # the difference between a one-line answer and a debugging session.
    log.info(
        "loaded manifest %s: %d tool(s) -> %s (auth=%s%s)",
        server_name,
        len(tools_cfg),
        manifest.get("base_url"),
        auth_cfg.get("kind", "none"),
        (
            f", api_key={'present' if api_key else 'MISSING'}"
            if auth_cfg.get("kind") == "api_key"
            else ""
        ),
    )
    if auth_cfg.get("kind") == "api_key" and not api_key:
        log.error(
            "manifest declares api_key auth but P2M_API_KEY is empty; every tool "
            "call will fail until the Cloud Run secret binding is restored"
        )

    client = httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT, follow_redirects=False)
    invoker = ToolInvoker(manifest, client, api_key=api_key)

    mcp_tools = [
        types.Tool(
            name=t["name"],
            description=t.get("description") or f"{t['method']} {t['path']}",
            inputSchema=input_schema_for(t),
            annotations=types.ToolAnnotations(
                title=t["name"].replace("_", " ").title(),
                readOnlyHint=bool(t.get("read_only", True)),
                idempotentHint=bool(t.get("idempotent", True)),
                destructiveHint=bool(t.get("destructive", False)),
                openWorldHint=True,
            ),
        )
        for t in tools_cfg
    ]

    async def on_list_tools(
        ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=mcp_tools)

    async def on_call_tool(
        ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        token = bearer_from_request(ctx.request)
        try:
            result = await invoker.invoke(
                params.name, dict(params.arguments or {}), inbound_token=token
            )
        except PermissionError as exc:
            return _error(f"Authorization error: {exc}")
        except UpstreamError as exc:
            return _error(f"Upstream API error (HTTP {exc.status}): {exc.body[:4000]}")
        except (ValueError, httpx.HTTPError) as exc:
            return _error(f"Tool error: {exc}")
        return types.CallToolResult(content=[types.TextContent(type="text", text=result)])

    def _error(message: str) -> types.CallToolResult:
        # isError lets the model see and recover from the failure rather than
        # the transport surfacing an opaque protocol error.
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=message)], isError=True
        )

    server: Server[None] = Server(
        server_name,
        version="0.1.0",
        title=manifest.get("display_name") or server_name,
        instructions=manifest.get("description") or None,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )

    async def healthz(_request: Any) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "server": server_name,
                "tools": len(tools_cfg),
                "auth": auth_cfg.get("kind", "none"),
                # Presence only. Lets an operator confirm the secret binding
                # survived a redeploy without exposing the credential.
                **(
                    {"api_key": "present" if api_key else "missing"}
                    if auth_cfg.get("kind") == "api_key"
                    else {}
                ),
            }
        )

    # DNS-rebinding protection defends browsers against attacks on *localhost*
    # servers. On Cloud Run the Host header is set by Google's frontend and the
    # service is not browser-reachable as a local origin, so the check only
    # causes harm.
    #
    # This must be passed EXPLICITLY. In mcp 2.x, `transport_security=None`
    # does not mean "disabled": `streamable_http_app` defaults `host` to
    # "127.0.0.1" and auto-enables protection with a localhost-only allowlist.
    # Every Cloud Run request then fails with 421 Misdirected Request. (This
    # differs from mcp 1.x, where None meant disabled.)
    from mcp.server.transport_security import TransportSecuritySettings

    allowed = [h.strip() for h in os.getenv("P2M_ALLOWED_HOSTS", "").split(",") if h.strip()]
    if allowed:
        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed,
            allowed_origins=[f"https://{h}" for h in allowed],
        )
    else:
        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )

    return server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        transport_security=transport_security,
        custom_starlette_routes=[
            Route("/healthz", healthz, methods=["GET"]),
            Route("/", healthz, methods=["GET"]),
        ],
    )


def main() -> None:
    import uvicorn

    uvicorn.run(
        build_app(),
        host="0.0.0.0",  # noqa: S104 - Cloud Run requires binding all interfaces
        port=int(os.getenv("PORT", "8080")),
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()
