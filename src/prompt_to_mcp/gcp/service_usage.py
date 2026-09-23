"""Service Usage: check and enable the Google APIs a run depends on.

Enabling APIs is one of the few setup steps that is genuinely automatable, so
the app does it rather than telling the operator to go run `gcloud`.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import GoogleApiClient, GoogleApiError

log = logging.getLogger(__name__)

BASE = "https://serviceusage.googleapis.com/v1"


class ServiceUsageClient:
    def __init__(self, api: GoogleApiClient, project_id: str) -> None:
        self.api = api
        self.project_id = project_id

    @property
    def parent(self) -> str:
        return f"projects/{self.project_id}"

    async def enabled_state(self, services: list[str]) -> dict[str, bool]:
        """Return ``{service: is_enabled}``.

        A service the caller cannot read is reported as ``False`` rather than
        raising, so a missing `serviceusage.services.get` permission degrades to
        "we could not confirm" instead of failing the whole preflight.
        """
        if not services:
            return {}
        names = [f"{self.parent}/services/{s}" for s in services]
        try:
            payload = await self.api.get(
                f"{BASE}/{self.parent}/services:batchGet", params={"names": names}
            )
        except GoogleApiError as exc:
            log.warning("could not read service state (%s); assuming not enabled", exc)
            return dict.fromkeys(services, False)

        state: dict[str, bool] = dict.fromkeys(services, False)
        for svc in payload.get("services", []):
            name = svc.get("name", "").rsplit("/", 1)[-1]
            if name in state:
                state[name] = svc.get("state") == "ENABLED"
        return state

    async def enable(self, services: list[str], *, wait: bool = True) -> dict[str, Any]:
        """Enable services that are not already on. Idempotent."""
        if not services:
            return {"enabled": [], "already_enabled": []}

        current = await self.enabled_state(services)
        todo = [s for s, on in current.items() if not on]
        already = [s for s, on in current.items() if on]
        if not todo:
            return {"enabled": [], "already_enabled": already}

        log.info("enabling services: %s", ", ".join(todo))
        operation = await self.api.post(
            f"{BASE}/{self.parent}/services:batchEnable", json={"serviceIds": todo}
        )
        if wait and "/operations/" in operation.get("name", ""):
            await self.api.poll_operation(
                f"https://serviceusage.googleapis.com/v1/{operation['name']}",
                interval=3.0,
                timeout=300.0,
            )
        return {"enabled": todo, "already_enabled": already}
