"""Secret Manager wrapper.

Upstream client secrets and the synthetic secrets we hand to Gemini Enterprise
never touch Firestore in plaintext; only Secret Manager resource names are
persisted alongside a PBKDF2 hash for verification.
"""

from __future__ import annotations

import asyncio
import logging
import re

log = logging.getLogger(__name__)

_SECRET_ID_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def secret_id_for(mcp_id: str, purpose: str) -> str:
    """Secret Manager IDs allow only [A-Za-z0-9_-] and max 255 chars."""
    return _SECRET_ID_RE.sub("-", f"p2m-{mcp_id}-{purpose}")[:255]


class SecretManager:
    def __init__(self, project_id: str, client: object | None = None) -> None:
        self.project_id = project_id
        self._client = client

    def _get_client(self):  # noqa: ANN202
        if self._client is None:
            from google.cloud import secretmanager

            self._client = secretmanager.SecretManagerServiceClient()
        return self._client

    async def create_or_update(self, secret_id: str, value: str) -> str:
        """Store ``value`` and return the pinned version resource name."""
        return await asyncio.to_thread(self._create_or_update_sync, secret_id, value)

    def _create_or_update_sync(self, secret_id: str, value: str) -> str:
        from google.api_core import exceptions

        client = self._get_client()
        parent = f"projects/{self.project_id}"
        name = f"{parent}/secrets/{secret_id}"
        try:
            client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {"replication": {"automatic": {}}},
                }
            )
        except exceptions.AlreadyExists:
            pass

        version = client.add_secret_version(
            request={"parent": name, "payload": {"data": value.encode("utf-8")}}
        )
        return version.name

    async def resolve(self, ref: str) -> str | None:
        """Read a secret by version resource name (or ``.../secrets/x`` + latest)."""
        if not ref:
            return None
        try:
            return await asyncio.to_thread(self._resolve_sync, ref)
        except Exception as exc:  # noqa: BLE001 - never leak secret material
            log.error("failed to resolve secret %s: %s", ref, type(exc).__name__)
            return None

    def _resolve_sync(self, ref: str) -> str:
        client = self._get_client()
        name = ref if "/versions/" in ref else f"{ref}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("utf-8")

    async def delete(self, secret_id: str) -> None:
        await asyncio.to_thread(self._delete_sync, secret_id)

    def _delete_sync(self, secret_id: str) -> None:
        from google.api_core import exceptions

        try:
            self._get_client().delete_secret(
                request={"name": f"projects/{self.project_id}/secrets/{secret_id}"}
            )
        except exceptions.NotFound:
            pass
