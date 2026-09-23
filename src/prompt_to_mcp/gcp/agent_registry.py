"""Agent Registry (``agentregistry.googleapis.com`` v1alpha) client.

Shapes here were read off the live discovery document and cross-checked against
really-existing services in a project, not inferred:

* You register by creating a **Service** with ``mcpServerSpec``. ``mcpServers``
  is read-only and derived; there is no ``mcpServers.create``.
* ``mcpServerSpec.type`` is ``NO_SPEC`` or ``TOOL_SPEC``. For ``TOOL_SPEC`` the
  ``content`` payload is shaped exactly like an MCP ``tools/list`` response and
  is capped at 10KB.
* ``interfaces[].protocolBinding`` is one of ``JSONRPC`` / ``GRPC`` /
  ``HTTP_JSON``. Streamable-HTTP MCP servers are ``JSONRPC``.
* ``Service`` carries **no** authentication fields whatsoever. Auth for Gemini
  Enterprise is configured separately via Discovery Engine authorizations.
* Supported locations are ``global`` and ``us-central1`` only.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .base import GoogleApiClient, GoogleApiError

log = logging.getLogger(__name__)

BASE = "https://agentregistry.googleapis.com/v1alpha"


class DuplicateInterfaceUrl(RuntimeError):
    """Raised when the interface URL is already claimed by another Service."""


class AgentRegistryClient:
    def __init__(self, api: GoogleApiClient, project_id: str, location: str) -> None:
        self.api = api
        self.project_id = project_id
        self.location = location

    @property
    def parent(self) -> str:
        return f"projects/{self.project_id}/locations/{self.location}"

    # -- services ---------------------------------------------------------
    @staticmethod
    def _spec_bytes(spec: dict[str, Any]) -> int:
        return len(json.dumps(spec, separators=(",", ":")).encode())

    @staticmethod
    def _strip_schema_text(schema: Any) -> Any:
        """Recursively drop human-readable prose from a JSON Schema."""
        if isinstance(schema, list):
            return [AgentRegistryClient._strip_schema_text(x) for x in schema]
        if not isinstance(schema, dict):
            return schema
        return {
            k: AgentRegistryClient._strip_schema_text(v)
            for k, v in schema.items()
            if k not in ("description", "title", "examples", "example", "default")
        }

    @staticmethod
    def _minimal_schema(schema: Any) -> dict[str, Any]:
        """Types and required-ness only -- the least a model needs to call a tool."""
        if not isinstance(schema, dict):
            return {"type": "object"}
        props = schema.get("properties")
        out: dict[str, Any] = {"type": schema.get("type", "object")}
        if isinstance(props, dict):
            out["properties"] = {
                name: {"type": (spec or {}).get("type", "string")}
                if isinstance(spec, dict)
                else {"type": "string"}
                for name, spec in props.items()
            }
        if schema.get("required"):
            out["required"] = schema["required"]
        return out

    @classmethod
    def fit_tool_spec(
        cls, tool_spec: dict[str, Any], max_bytes: int
    ) -> tuple[dict[str, Any] | None, str]:
        """Shrink a tools/list payload to fit Agent Registry's 10KB cap.

        Degrades progressively, and **preserves the tool count for as long as
        possible**. A truncated catalog is actively misleading -- publishing 4 of
        Google Drive's 8 tools implies Drive has 4 tools -- so detail is
        sacrificed before any tool is dropped. Dropping tools is the last step
        before falling back to NO_SPEC.

        Returns the fitted spec (or None for NO_SPEC) and a human-readable note.
        """
        tools = tool_spec.get("tools") or []
        if not tools:
            return None, "no tools"

        if cls._spec_bytes({"tools": tools}) <= max_bytes:
            return {"tools": tools}, f"published all {len(tools)} tool(s) in full"

        stages: list[tuple[str, Any]] = [
            (
                "shortened descriptions",
                lambda t: {**t, "description": (t.get("description") or "")[:200]},
            ),
            (
                "stripped schema prose",
                lambda t: {
                    **t,
                    "description": (t.get("description") or "")[:200],
                    "inputSchema": cls._strip_schema_text(t.get("inputSchema") or {}),
                },
            ),
            (
                "dropped annotations and extras",
                lambda t: {
                    "name": t.get("name"),
                    "description": (t.get("description") or "")[:200],
                    "inputSchema": cls._strip_schema_text(t.get("inputSchema") or {}),
                },
            ),
            (
                "minimal schemas",
                lambda t: {
                    "name": t.get("name"),
                    "description": (t.get("description") or "")[:80],
                    "inputSchema": cls._minimal_schema(t.get("inputSchema") or {}),
                },
            ),
            (
                "names only",
                lambda t: {"name": t.get("name"), "description": (t.get("description") or "")[:60]},
            ),
        ]

        for note, transform in stages:
            candidate = [transform(t) for t in tools]
            if cls._spec_bytes({"tools": candidate}) <= max_bytes:
                return (
                    {"tools": candidate},
                    f"published all {len(tools)} tool(s) ({note} to fit the {max_bytes}B cap)",
                )

        # Only now start losing tools.
        candidate = [stages[-1][1](t) for t in tools]
        while candidate and cls._spec_bytes({"tools": candidate}) > max_bytes:
            candidate.pop()
        if candidate:
            return (
                {"tools": candidate},
                f"published {len(candidate)} of {len(tools)} tool(s); the rest did not fit",
            )
        return None, "tool spec too large even as names; registered with NO_SPEC"

    def build_service_body(
        self,
        display_name: str,
        description: str,
        mcp_url: str,
        tool_spec: dict[str, Any] | None,
        *,
        max_spec_bytes: int = 10_000,
    ) -> dict[str, Any]:
        """Assemble the Service payload.

        ``tool_spec`` is a ``tools/list`` shaped payload -- either derived from a
        generated manifest or read straight off an existing MCP server. ``None``
        registers with ``NO_SPEC``.
        """
        base = {
            "displayName": display_name[:63],
            "description": description[:2048],
            "interfaces": [{"url": mcp_url, "protocolBinding": "JSONRPC"}],
        }

        if not tool_spec or not tool_spec.get("tools"):
            return {**base, "mcpServerSpec": {"type": "NO_SPEC"}}

        fitted, note = self.fit_tool_spec(tool_spec, max_spec_bytes)
        if fitted is None:
            log.warning("%s", note)
            return {**base, "mcpServerSpec": {"type": "NO_SPEC"}}

        original = len(tool_spec["tools"])
        if len(fitted["tools"]) < original or "cap" in note:
            log.info(
                "%s (the MCP server still serves all %d via tools/list)", note, original
            )
        return {**base, "mcpServerSpec": {"type": "TOOL_SPEC", "content": fitted}}

    async def create_service(
        self,
        service_id: str,
        *,
        display_name: str,
        description: str,
        mcp_url: str,
        tool_spec: dict[str, Any] | None,
    ) -> dict[str, Any]:
        body = self.build_service_body(display_name, description, mcp_url, tool_spec)
        url = f"{BASE}/{self.parent}/services"
        try:
            result = await self.api.post(url, json=body, params={"serviceId": service_id})
        except GoogleApiError as exc:
            if exc.status == 409:
                log.info("service %s already exists; updating instead", service_id)
                return await self.update_service(
                    service_id,
                    display_name=display_name,
                    description=description,
                    mcp_url=mcp_url,
                    tool_spec=tool_spec,
                )
            raise await self._explain(exc, mcp_url) from exc

        # services.create is an LRO in v1alpha.
        if isinstance(result, dict) and "name" in result and result.get("done") is not True:
            if "/operations/" in result["name"]:
                try:
                    result = await self.api.poll_operation(f"{BASE}/{result['name']}")
                except GoogleApiError as exc:
                    raise await self._explain(exc, mcp_url) from exc
        return result

    async def _explain(self, exc: GoogleApiError, mcp_url: str) -> Exception:
        """Turn an opaque registry error into something actionable."""
        message = str(exc)
        if "already in use by another service" not in message:
            return exc
        owner = await self.service_using_url(mcp_url)
        if owner is None:
            return DuplicateInterfaceUrl(
                f"Agent Registry already has a service bound to {mcp_url}. "
                "Interface URLs must be unique within a location; delete the existing "
                "registration or register a different endpoint."
            )
        name = owner.get("name", "").rsplit("/", 1)[-1]
        return DuplicateInterfaceUrl(
            f"{mcp_url} is already registered in Agent Registry as "
            f"'{owner.get('displayName') or name}' (service '{name}'). Interface URLs must be "
            "unique within a location. Delete that entry first, or point this at a different "
            "endpoint."
        )

    async def update_service(
        self,
        service_id: str,
        *,
        display_name: str,
        description: str,
        mcp_url: str,
        tool_spec: dict[str, Any] | None,
    ) -> dict[str, Any]:
        body = self.build_service_body(display_name, description, mcp_url, tool_spec)
        url = f"{BASE}/{self.parent}/services/{service_id}"
        result = await self.api.patch(
            url,
            json=body,
            params={"updateMask": "displayName,description,interfaces,mcpServerSpec"},
        )
        if isinstance(result, dict) and "/operations/" in result.get("name", ""):
            result = await self.api.poll_operation(f"{BASE}/{result['name']}")
        return result

    async def get_service(self, service_id: str) -> dict[str, Any]:
        return await self.api.get(f"{BASE}/{self.parent}/services/{service_id}")

    async def list_services(self) -> list[dict[str, Any]]:
        payload = await self.api.get(f"{BASE}/{self.parent}/services")
        return payload.get("services", [])

    async def service_using_url(self, mcp_url: str) -> dict[str, Any] | None:
        """Find an existing Service already bound to this interface URL.

        Agent Registry enforces uniqueness on the interface URL within a
        location. Registering a duplicate fails with
        ``Interface URL '...' is already in use by another service`` -- returned
        as a **500 inside the LRO**, not a 409, so it cannot be handled by
        status code alone.
        """
        target = mcp_url.rstrip("/")
        try:
            services = await self.list_services()
        except GoogleApiError:
            return None
        for svc in services:
            for iface in svc.get("interfaces", []):
                if (iface.get("url") or "").rstrip("/") == target:
                    return svc
        return None

    async def delete_service(self, service_id: str) -> None:
        await self.api.delete(f"{BASE}/{self.parent}/services/{service_id}")

    # -- derived MCP server ------------------------------------------------
    async def get_mcp_server(self, resource_name: str) -> dict[str, Any]:
        """Fetch the read-only ``mcpServers/*`` projection of a service."""
        return await self.api.get(f"{BASE}/{resource_name}")

    async def resolve_registry_resource(self, service_id: str) -> str | None:
        """Return the ``mcpServers/*`` name a service produced, if any."""
        service = await self.get_service(service_id)
        return service.get("registryResource")
