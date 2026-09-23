"""The OAuth 2.1 proxy, as its own Cloud Run service.

Why it is separate
------------------
Through 1.0.1 the proxy shared a process with the provisioning API. That forced
a single exposure decision onto two components whose requirements are exact
opposites:

* The **provisioning API** acts as a service account that can create Cloud Run
  services, act as other service accounts and write Secret Manager versions. It
  must never accept an unauthenticated request.
* The **OAuth proxy** exists to be reached by parties who have no credential
  yet. Gemini Enterprise redirects the end user's *browser* to
  ``/oauth/authorize``; the upstream provider redirects that browser back to
  ``/oauth/callback``. Neither hop can carry a Google-signed ID token for this
  project, because the whole point of the exchange is to obtain a credential.

Co-locating them meant the only way to keep the consent flow working was to
publish the provisioning API to the internet, which is exactly how V-01
happened. Splitting them lets each get the posture it actually needs: the
control plane is deployed with no public access at all, and this service is
deployed ``--allow-unauthenticated`` on purpose, having nothing to steal.

What this service can do
------------------------
Read and write OAuth proxy client records in Firestore, and read the Secret
Manager secrets holding upstream client secrets. That is all -- ``bootstrap.sh``
gives it its own service account with two roles, rather than the ten the
control plane needs. It cannot deploy anything, cannot touch Discovery Engine,
and cannot create secrets.

Its own protections are unchanged and are not weakened by being public: PKCE on
both legs, single-use authorization codes deleted before the ownership check
(``proxy.py:360-371``), and client authentication against a PBKDF2-hashed
secret at ``/token``.

Deployment note
---------------
The URLs this service serves are written into Discovery Engine
``Authorization`` resources at provisioning time and cannot be changed
afterwards without rebuilding the connector. It therefore has to exist, and
have a stable URL, *before* the first MCP is provisioned -- which is why
``deploy.sh`` deploys it first and passes its URL to the control plane as
``P2M_OAUTH_BASE_URL``.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI

from .config import Settings, get_settings
from .gcp.secrets import SecretManager
from .oauth.proxy import build_router
from .oauth.store import FirestoreStore, MemoryStore, Store

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("p2m.oauth")


def create_oauth_app(settings: Settings | None = None, store: Store | None = None) -> FastAPI:
    """The public OAuth proxy service.

    ``store`` is injectable so tests, and a single-process local run, can hand
    in the same :class:`~prompt_to_mcp.oauth.store.Store` the control plane
    uses. In Cloud Run both services talk to the same Firestore database, which
    is what makes the split invisible to a provisioning run: the control plane
    writes a proxy client, this service reads it.
    """
    settings = settings or get_settings()

    use_memory = os.getenv("P2M_USE_MEMORY_STORE", "").lower() in ("1", "true", "yes")
    if store is None:
        store = (
            MemoryStore()
            if use_memory
            else FirestoreStore(settings.project_id, settings.firestore_database)
        )

    app = FastAPI(
        title="prompt-to-mcp OAuth proxy",
        description=(
            "OAuth 2.1 authorization-server shim bridging Gemini Enterprise's static "
            "client requirement to upstreams that only offer dynamic registration or "
            "public PKCE clients."
        ),
        # No interactive docs. This service is deliberately public, so there is
        # no reason to also publish a browsable map of it; the endpoints it
        # serves are already described by RFC 8414 metadata at
        # /oauth/.well-known/oauth-authorization-server.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.store = store

    app.include_router(
        build_router(
            store=store,
            secrets_resolver=SecretManager(settings.project_id),
            public_base_url=settings.oauth_public_base_url,
        )
    )

    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, Any]:
        return {"status": "ok"}

    log.info("OAuth proxy issuing under %s", settings.oauth_public_base_url)
    return app


def main() -> None:  # pragma: no cover - process entrypoint
    import uvicorn

    uvicorn.run(
        create_oauth_app(),
        host="0.0.0.0",  # noqa: S104 - Cloud Run requires binding all interfaces
        port=int(os.getenv("PORT", "8080")),
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    main()
