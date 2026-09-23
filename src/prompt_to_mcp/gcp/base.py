"""Shared authenticated REST helper for Google Cloud APIs.

We call ``agentregistry`` and ``discoveryengine`` v1alpha over raw REST rather
than through generated client libraries: the resources we need (MCP server
services, ``custom_mcp`` data connectors) are v1alpha surfaces that the stable
Python clients either lag behind or omit entirely.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import google.auth
import google.auth.transport.requests
import httpx
from google.auth.credentials import Credentials

log = logging.getLogger(__name__)

SCOPE = "https://www.googleapis.com/auth/cloud-platform"
TIMEOUT = httpx.Timeout(120.0, connect=15.0)


class GoogleApiError(RuntimeError):
    def __init__(self, status: int, payload: Any, url: str) -> None:
        self.status = status
        self.payload = payload
        self.url = url
        message = payload
        if isinstance(payload, dict):
            message = payload.get("error", {}).get("message", payload)
        super().__init__(f"{status} from {url}: {message}")


class GoogleApiClient:
    """Thin async REST client that refreshes ADC tokens as needed."""

    def __init__(self, project_id: str, credentials: Credentials | None = None) -> None:
        self.project_id = project_id
        self._credentials = credentials
        self._lock = asyncio.Lock()

    async def _token(self) -> str:
        async with self._lock:
            if self._credentials is None:
                creds, _ = await asyncio.to_thread(google.auth.default, scopes=[SCOPE])
                self._credentials = creds
            creds = self._credentials
            if not creds.valid:
                request = google.auth.transport.requests.Request()
                await asyncio.to_thread(creds.refresh, request)
            return creds.token  # type: ignore[return-value]

    async def request(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> Any:
        headers = {
            "authorization": f"Bearer {await self._token()}",
            # Required when running under user ADC; harmless with a service
            # account. Without it, discoveryengine returns
            # "API requires a quota project, which is not set by default".
            "x-goog-user-project": self.project_id,
            "content-type": "application/json",
        }
        owns = client is None
        client = client or httpx.AsyncClient(timeout=TIMEOUT)
        try:
            resp = await client.request(method, url, json=json, params=params, headers=headers)
        finally:
            if owns:
                await client.aclose()

        try:
            payload = resp.json() if resp.content else {}
        except ValueError:
            payload = {"raw": resp.text[:2000]}

        if resp.status_code >= 400:
            raise GoogleApiError(resp.status_code, payload, url)
        return payload

    async def get(self, url: str, **kw: Any) -> Any:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> Any:
        return await self.request("POST", url, **kw)

    async def patch(self, url: str, **kw: Any) -> Any:
        return await self.request("PATCH", url, **kw)

    async def delete(self, url: str, **kw: Any) -> Any:
        return await self.request("DELETE", url, **kw)

    async def poll_operation(
        self,
        operation_url: str,
        *,
        interval: float = 3.0,
        timeout: float = 900.0,
    ) -> dict[str, Any]:
        """Poll an LRO until done. Returns the ``response`` (or raises)."""
        waited = 0.0
        while waited < timeout:
            op = await self.get(operation_url)
            if op.get("done"):
                if "error" in op:
                    raise GoogleApiError(500, op["error"], operation_url)
                return op.get("response", {})
            await asyncio.sleep(interval)
            waited += interval
        raise TimeoutError(f"operation {operation_url} did not finish within {timeout}s")
