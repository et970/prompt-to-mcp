"""Control plane: FastAPI app hosting the provisioning API and the UI.

The OAuth proxy used to live here too. It no longer does -- it is its own Cloud
Run service (:mod:`prompt_to_mcp.oauth_app`).

The original reason for co-locating them still stands on its own terms: the
proxy's endpoints must be stable, publicly reachable URLs, because they are
baked into Discovery Engine ``Authorization`` resources at provisioning time,
and one service is one URL to configure and one thing to keep alive. What that
reasoning missed is that "publicly reachable" is not a property the two halves
can share. This service acts as a service account that can create Cloud Run
services, act as other service accounts and write Secret Manager versions; the
proxy has to answer a browser that holds no credential at all. Keeping them
together meant the only way to make consent work was to publish the
provisioning API to the internet, which is precisely what happened in 1.0.1.

So: every route here requires a verified, allowlisted principal
(:mod:`prompt_to_mcp.auth`), and ``deploy.sh`` no longer passes
``--allow-unauthenticated``. The proxy is deployed separately and publicly,
holding nothing worth stealing. ``settings.oauth_base_url`` is how this service
knows where it went.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import pathlib
import secrets
from dataclasses import dataclass
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .auth import allow_unauthenticated, authenticate, require_principal, warn_if_unauthenticated
from .build_info import read_build_info
from .bundle import BundleError, build_bundle
from .canary import run_canary
from .config import Settings, get_settings
from .contract_agent import ContractAgent, ContractFinding, ProbeHarness
from .deployer.cloud_run import CloudRunDeployer
from .diagnose import Diagnosis, diagnose
from .gcp.agent_registry import AgentRegistryClient
from .gcp.base import GoogleApiClient
from .gcp.discovery_engine import DiscoveryEngineClient
from .gcp.records import FirestoreRecordStore, MemoryRecordStore, RecordStore
from .gcp.secrets import SecretManager, secret_id_for
from .gcp.service_usage import ServiceUsageClient
from .ingest import INGEST_INPUT_ERRORS, build_manifest_from_request
from .models import CreateMcpRequest, McpRecord, ResumeMcpRequest, slugify
from .oauth import metadata as md_mod
from .oauth.store import FirestoreStore, MemoryStore, Store
from .pipeline import (
    Dependencies,
    Pipeline,
    ResumeError,
    rehydrate_request,
    request_snapshot,
)
from .requirements import Preflight, evaluate
from .resolve import ResolvedPlan, ResolveRequest
from .resolve import resolve as resolve_input

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("p2m")


def _version() -> str:
    """The installed package version.

    Read from package metadata rather than hardcoded: the literal here drifted
    from ``pyproject.toml`` (0.1.0 against a 1.0.0 release) precisely because
    nothing failed when it did.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("prompt-to-mcp")
    except PackageNotFoundError:  # pragma: no cover - running from a bare tree
        return "unknown"


VERSION = _version()


def _asset_version(static_dir: pathlib.Path) -> str:
    """Content fingerprint of the UI assets, for cache-busting."""
    digest = hashlib.sha256()
    for name in ("app.js", "styles.css"):
        path = static_dir / name
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def _index_html(static_dir: pathlib.Path) -> str:
    """index.html with the asset URLs fingerprinted by content.

    A ``Cache-Control`` header only governs requests made after it shipped, so
    it cannot rescue a browser that already holds an old ``app.js``. That case
    is not hypothetical: it produces fresh markup driven by stale script, whose
    symptoms (a dead health indicator, errors naming controls that no longer
    exist) look nothing like a caching problem and send you hunting the wrong
    bug entirely.

    Appending a content hash makes the pairing impossible to get wrong. New
    markup necessarily requests a URL the browser has never seen, so the two
    can never come from different builds. The hash is computed per request:
    these are two small files, and being able to edit the UI without bouncing
    the process is worth more here than the read.
    """
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    version = _asset_version(static_dir)
    return html.replace('"./app.js"', f'"./app.js?v={version}"').replace(
        '"./styles.css"', f'"./styles.css?v={version}"'
    )


class _RevalidatingStatic(StaticFiles):
    """Serve the UI with ``Cache-Control: no-cache``.

    Starlette sends ``ETag`` and ``Last-Modified`` but no ``Cache-Control``.
    Absent an explicit directive browsers apply *heuristic* caching -- commonly
    a fraction of the time since ``Last-Modified`` -- and will happily serve a
    stale ``app.js`` without revalidating. After a UI deploy that presents as
    the new interface being broken: markup from one build driven by script from
    another, with errors referring to controls that no longer exist.

    ``no-cache`` means "revalidate before use", not "do not store": the ETag
    still yields a 304, so this costs a conditional request rather than a
    re-download. The UI is a handful of small files on the same origin as the
    API, so that is the right trade.
    """

    def file_response(self, *args: Any, **kwargs: Any) -> Any:
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        """Authenticate before serving an asset.

        A ``mount`` is an ASGI sub-application, so route-level and app-level
        dependencies never run for it -- the guard on every ``@app.get`` below
        would leave ``/ui/app.js`` readable by anyone. The UI is not secret,
        but it is a precise description of the API surface, and an exception
        carved out for convenience is how the next one gets justified.
        """
        if scope["type"] != "http":  # pragma: no cover - no websockets here
            await super().__call__(scope, receive, send)
            return
        request = Request(scope, receive)
        try:
            await authenticate(request)
        except HTTPException as exc:
            response = JSONResponse(
                {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
            )
            await response(scope, receive, send)
            return
        await super().__call__(scope, receive, send)


@dataclass(slots=True)
class AppState:
    settings: Settings
    pipeline: Pipeline
    records: RecordStore
    store: Store
    secrets: SecretManager


def build_state(settings: Settings) -> AppState:
    """Wire concrete implementations. Swap to in-memory with P2M_USE_MEMORY_STORE=1."""
    use_memory = os.getenv("P2M_USE_MEMORY_STORE", "").lower() in ("1", "true", "yes")

    api = GoogleApiClient(settings.project_id)
    runtime_image = os.getenv(
        "P2M_RUNTIME_IMAGE",
        f"{settings.run_region}-docker.pkg.dev/{settings.project_id}"
        f"/{settings.artifact_repo}/mcp-runtime:latest",
    )

    store: Store = (
        MemoryStore()
        if use_memory
        else FirestoreStore(settings.project_id, settings.firestore_database)
    )
    records: RecordStore = (
        MemoryRecordStore()
        if use_memory
        else FirestoreRecordStore(settings.project_id, settings.firestore_database)
    )
    secrets = SecretManager(settings.project_id)

    deps = Dependencies(
        settings=settings,
        deployer=CloudRunDeployer(
            api,
            settings.project_id,
            settings.run_region,
            runtime_image=runtime_image,
            service_account=settings.mcp_service_account,
            manifest_bucket=os.getenv("P2M_MANIFEST_BUCKET"),
        ),
        registry=AgentRegistryClient(api, settings.project_id, settings.agent_registry_location),
        discovery=DiscoveryEngineClient(
            api, settings.project_id, settings.discovery_engine_location
        ),
        secrets=secrets,
        store=store,
        service_usage=ServiceUsageClient(api, settings.project_id),
    )

    return AppState(
        settings=settings,
        pipeline=Pipeline(deps),
        records=records,
        store=store,
        secrets=secrets,
    )


def create_app(settings: Settings | None = None, state: AppState | None = None) -> FastAPI:
    settings = settings or get_settings()
    state = state or build_state(settings)

    warn_if_unauthenticated()
    dev_mode = allow_unauthenticated()

    app = FastAPI(
        title="prompt-to-mcp",
        version=VERSION,
        description=(
            "Turn a prompt plus API documentation into a deployed MCP server on Cloud Run, "
            "registered in Agent Registry and connected to a Gemini Enterprise app."
        ),
        # Every route requires a verified, allowlisted principal. Declared on
        # the app rather than per-route so the default for anything added later
        # is "protected"; /healthz opts out by path inside the dependency, and
        # that exemption list is deliberately one entry long.
        dependencies=[Depends(require_principal)],
        # The interactive docs are a complete, indexed map of the attack
        # surface, and /openapi.json is the same thing in machine-readable
        # form. Off unless the development escape hatch is set, in which case
        # authentication is off anyway and there is nothing left to protect.
        docs_url="/docs" if dev_mode else None,
        redoc_url="/redoc" if dev_mode else None,
        openapi_url="/openapi.json" if dev_mode else None,
    )
    app.state.p2m = state
    # Read by prompt_to_mcp.auth.settings_for: the auth check must consult the
    # same Settings the rest of the app was built with, not the process-wide
    # cached one.
    app.state.settings = settings

    # Static single-page UI. Served from the same origin as the API so there
    # is no CORS surface and nothing extra to deploy or keep alive.
    static_dir = pathlib.Path(__file__).parent / "static"
    if static_dir.is_dir():
        # index.html is served by hand so the asset URLs can be fingerprinted;
        # registered before the mount because Starlette matches in order.
        @app.get("/ui/", include_in_schema=False)
        @app.get("/ui/index.html", include_in_schema=False)
        async def ui_index() -> HTMLResponse:
            return HTMLResponse(
                _index_html(static_dir), headers={"Cache-Control": "no-cache"}
            )

        app.mount("/ui", _RevalidatingStatic(directory=static_dir, html=True), name="ui")
    else:  # pragma: no cover - only if package data is missing from the image
        log.warning("static UI directory not found at %s; /ui will 404", static_dir)

    def st(request: Request) -> AppState:
        return request.app.state.p2m  # type: ignore[no-any-return]

    # -- root -----------------------------------------------------------
    @app.get("/", tags=["health"], include_in_schema=False)
    async def root(request: Request) -> Any:
        """Service index.

        Without this, opening the Cloud Run URL in a browser just yields
        FastAPI's bare `{"detail":"Not Found"}`, which looks like a broken
        deployment. Browsers get the UI; everything else gets a
        machine-readable index.
        """
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return RedirectResponse(url="/ui/", status_code=307)

        base = settings.public_base_url
        oauth_base = settings.oauth_public_base_url
        return {
            "service": "prompt-to-mcp",
            "version": VERSION,
            "description": (
                "Turns a prompt plus API documentation into a deployed MCP server on "
                "Cloud Run, registered in Agent Registry and connected to Gemini "
                "Enterprise."
            ),
            "ui": f"{base}/ui/",
            # Absent in production: the interactive docs are only mounted when
            # the development escape hatch is set. Advertising a 404 reads as a
            # broken deployment, which is the thing this route exists to avoid.
            "docs": f"{base}/docs" if dev_mode else None,
            "endpoints": {
                "provision_mcp": "POST /v1/mcps",
                "list_mcps": "GET /v1/mcps",
                "get_mcp": "GET /v1/mcps/{mcp_id}",
                "get_mcp_bundle": "GET /v1/mcps/{mcp_id}/bundle",
                "download_mcp_bundle": "GET /v1/mcps/{mcp_id}/bundle.zip",
                "resume_mcp": "POST /v1/mcps/{mcp_id}/resume",
                "delete_mcp": "DELETE /v1/mcps/{mcp_id}",
                "resolve": "POST /v1/resolve",
                "inspect_oauth": "POST /v1/inspect/oauth",
                "inspect_manifest": "POST /v1/inspect/manifest",
                "canary": "GET /v1/canary",
                "investigate_contract": "POST /v1/contract/investigate",
                "build_info": "GET /v1/buildinfo",
                "health": "GET /healthz",
                "readiness": "GET /readyz",
            },
            # A separate Cloud Run service, deliberately public where this one
            # is not. See prompt_to_mcp.oauth_app for why they were split.
            "oauth_proxy": {
                "issuer": oauth_base,
                "metadata": f"{oauth_base}/oauth/.well-known/oauth-authorization-server",
                "authorization_endpoint": f"{oauth_base}/oauth/authorize",
                "token_endpoint": f"{oauth_base}/oauth/token",
                "note": (
                    "Hosted by the prompt-to-mcp-oauth service, not this one."
                    if oauth_base != base
                    else "Served in-process; set P2M_OAUTH_BASE_URL in deployment."
                ),
            },
        }

    # -- health ---------------------------------------------------------
    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, Any]:
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"])
    async def readyz() -> dict[str, Any]:
        """Bare readiness signal.

        This used to return the project id, every region setting, the public
        base URL and the build fingerprint. All of that is genuinely useful and
        none of it belongs on a liveness endpoint: it is a free reconnaissance
        summary of the deployment. It moved, intact, to ``/v1/buildinfo``, which
        is authenticated like everything else.
        """
        return {"status": "ok"}

    @app.get("/v1/buildinfo", tags=["diagnostics"])
    async def buildinfo() -> dict[str, Any]:
        """Which code is running, and against what configuration.

        Compare ``build.fingerprint`` against a local
        ``python -m prompt_to_mcp.build_info`` to answer "is my fix actually
        live?" -- a question that has already cost an hour once.
        ``make check-deployed`` does exactly that.
        """
        return {
            "status": "ok",
            "version": VERSION,
            "build": read_build_info().to_dict(),
            "project": settings.project_id,
            "public_base_url": settings.public_base_url,
            "oauth_base_url": settings.oauth_public_base_url,
            "run_region": settings.run_region,
            "agent_registry_location": settings.agent_registry_location,
            "discovery_engine_location": settings.discovery_engine_location,
        }

    @app.get("/v1/canary", tags=["diagnostics"])
    async def canary(request: Request) -> Any:
        """Check that the connector API still wants what this app sends.

        Meant to be called on a schedule. The failure this guards against is
        not a bug in our code -- it is a v1alpha API changing shape underneath
        code that never changed -- so no pre-deploy test can catch it and no
        amount of unit testing helps. Only asking the live API does.

        Returns 503 on drift so an uptime check or Cloud Scheduler job alerts
        without anyone parsing the body.
        """
        result = await run_canary(st(request).pipeline.d.discovery)
        return JSONResponse(result.to_dict(), status_code=200 if result.ok else 503)

    @app.post(
        "/v1/contract/investigate", tags=["diagnostics"], response_model=ContractFinding
    )
    async def investigate_contract(
        request: Request, mcp_id: str | None = None
    ) -> ContractFinding:
        """Work out what the connector API currently accepts, and report back.

        Runs the bounded probe loop described in
        :mod:`prompt_to_mcp.contract_agent`. Read-only with respect to your
        project: every probe omits the setup token, so validation rejects it
        whatever else it contains and no resource is ever created.

        **Propose only.** The result is a finding with its evidence. Nothing
        here changes how connectors are built; applying it is a code change you
        make deliberately.

        Pass ``mcp_id`` to hand the agent a specific failed run for context.
        """
        s = st(request)
        context = ""
        if mcp_id:
            record = await s.records.get(mcp_id)
            if record is None:
                raise HTTPException(status_code=404, detail=f"no MCP with id {mcp_id!r}")
            sent = (record.config.get("connect") or {}).get("request_body")
            context = json.dumps(
                {"error": record.error, "sent": sent}, indent=2, default=str
            )[:6000]

        harness = ProbeHarness(s.pipeline.d.discovery)
        agent = ContractAgent(settings)
        # The genai SDK is synchronous and the loop is long; keep the event loop
        # free for the provisioning runs happening alongside it.
        finding = await agent.investigate(harness, context=context)
        log.info("contract investigation: %s", finding.summary)
        return finding

    # -- provisioning ----------------------------------------------------
    @app.post("/v1/mcps", tags=["mcps"], status_code=202)
    async def create_mcp(
        req: CreateMcpRequest, background: BackgroundTasks, request: Request, wait: bool = False
    ) -> Any:
        """Provision an MCP server from a prompt.

        Asynchronous by default: a full run (Cloud Run deploy plus Gemini
        Enterprise connector setup) routinely takes several minutes, well past
        any sane HTTP timeout. Use ``?wait=true`` for synchronous test runs.

        The identifier is allocated here rather than inside the pipeline, so the
        caller gets a stable handle to poll immediately. The pipeline persists
        the record after every stage, which is what lets the UI show live
        progress instead of a spinner.
        """
        s = st(request)
        mcp_id = f"{slugify(req.name or req.description[:40])}-{secrets.token_hex(3)}"

        async def on_progress(record: McpRecord) -> None:
            await s.records.put(record)

        async def run_and_store() -> McpRecord:
            record = await s.pipeline.run(req, mcp_id=mcp_id, on_progress=on_progress)
            await s.records.put(record)
            return record

        if wait:
            record = await run_and_store()
            ok = record.state.startswith(("READY", "STOPPED", "PARTIAL"))
            return JSONResponse(record.model_dump(mode="json"), status_code=200 if ok else 500)

        # Persist a RUNNING record up front so a poll immediately after the 202
        # never 404s. The request goes on it now rather than when the pipeline
        # gets around to starting, so the config view is populated from the
        # first render instead of appearing a few seconds later.
        await s.records.put(
            McpRecord(
                id=mcp_id,
                display_name=req.name or req.description[:60],
                description=req.description,
                state="RUNNING",
                request=request_snapshot(req),
            )
        )

        async def task() -> None:
            try:
                record = await run_and_store()
                log.info("provisioning finished: %s -> %s", record.id, record.state)
            except Exception:
                log.exception("background provisioning crashed")
                existing = await s.records.get(mcp_id)
                record = existing or McpRecord(id=mcp_id, display_name=mcp_id)
                record.state = "PARTIAL" if record.usable else "FAILED"
                record.error = "internal error; see Cloud Logging"
                await s.records.put(record)

        background.add_task(task)
        return JSONResponse(
            {
                "id": mcp_id,
                "state": "RUNNING",
                "poll": f"/v1/mcps/{mcp_id}",
                "note": "Provisioning continues in the background; poll for live stage progress.",
            },
            status_code=202,
        )

    @app.get("/v1/mcps", tags=["mcps"])
    async def list_mcps(request: Request, limit: int = 50) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in await st(request).records.list(limit)]

    @app.get("/v1/mcps/{mcp_id}", tags=["mcps"])
    async def get_mcp(mcp_id: str, request: Request) -> dict[str, Any]:
        record = await st(request).records.get(mcp_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"no MCP with id {mcp_id!r}")
        return record.model_dump(mode="json")

    async def _bundle_for(mcp_id: str, request: Request) -> Any:
        """Shared lookup for the two package routes.

        A missing manifest is the caller's situation, not a server fault, so it
        is a 400 carrying the bundler's explanation rather than a 500.
        """
        record = await st(request).records.get(mcp_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"no MCP with id {mcp_id!r}")
        try:
            return build_bundle(record, settings=settings)
        except BundleError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/mcps/{mcp_id}/bundle", tags=["mcps"])
    async def get_bundle(
        mcp_id: str, request: Request, include_content: bool = True
    ) -> dict[str, Any]:
        """The generated package as JSON, for reviewing it without downloading.

        Contents are inlined by default because the UI renders them in place;
        the whole package is tens of kilobytes. Pass ``include_content=false``
        for just the file list, sizes and hashes.
        """
        bundle = await _bundle_for(mcp_id, request)
        try:
            return bundle.to_dict(include_content=include_content)  # type: ignore[no-any-return]
        except BundleError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc

    @app.get(
        "/v1/mcps/{mcp_id}/bundle.zip",
        tags=["mcps"],
        response_class=Response,
        responses={200: {"content": {"application/zip": {}}}},
    )
    async def download_bundle(mcp_id: str, request: Request) -> Response:
        """The generated package as a zip.

        Built per request rather than cached: it is cheap (a few file reads and
        a JSON dump), and a cache would let a package outlive the record it
        describes -- handing someone a stale manifest while the UI shows the
        current one is the exact confusion this feature exists to remove.
        """
        bundle = await _bundle_for(mcp_id, request)
        return Response(
            content=bundle.to_zip(),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{bundle.filename}"',
                # The fingerprint is the package's identity; exposing it as an
                # ETag lets a browser skip an unchanged re-download and makes
                # "is this the same package I reviewed?" answerable with curl -I.
                "ETag": f'"{bundle.fingerprint}"',
                "Cache-Control": "no-cache",
            },
        )

    @app.post("/v1/mcps/{mcp_id}/resume", tags=["mcps"], status_code=202)
    async def resume_mcp(
        mcp_id: str,
        background: BackgroundTasks,
        request: Request,
        body: ResumeMcpRequest | None = None,
        wait: bool = False,
    ) -> Any:
        """Continue a run that stopped part-way, reusing what it already built.

        Starting over is not an equivalent option. A partial run has already
        created a Cloud Run service, an Agent Registry entry and possibly an
        OAuth client; Agent Registry interface URLs are unique per location, so
        a fresh run against the same endpoint fails at `register` no matter what
        was wrong the first time. Resuming skips the stages whose output exists
        and retries only what did not.
        """
        s = st(request)
        record = await s.records.get(mcp_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"no MCP with id {mcp_id!r}")
        if record.state == "RUNNING":
            raise HTTPException(
                status_code=409, detail=f"{mcp_id} is still running; wait for it to finish"
            )
        if record.state == "READY":
            raise HTTPException(
                status_code=400, detail=f"{mcp_id} completed successfully; nothing to resume"
            )

        overrides = dict((body.overrides if body else None) or {})
        # A run that was deliberately stopped early is being asked to continue,
        # so the instruction that stopped it must not be replayed.
        overrides.setdefault("stop_after", None)
        try:
            req = rehydrate_request(record, overrides)
        except ResumeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        async def on_progress(rec: McpRecord) -> None:
            await s.records.put(rec)

        async def run_and_store() -> McpRecord:
            result = await s.pipeline.run(
                req, mcp_id=mcp_id, on_progress=on_progress, resume=record
            )
            await s.records.put(result)
            return result

        if wait:
            result = await run_and_store()
            ok = result.state.startswith(("READY", "STOPPED", "PARTIAL"))
            return JSONResponse(result.model_dump(mode="json"), status_code=200 if ok else 500)

        record.state = "RUNNING"
        await s.records.put(record)

        async def task() -> None:
            try:
                result = await run_and_store()
                log.info("resume finished: %s -> %s", result.id, result.state)
            except Exception:
                log.exception("background resume crashed")
                existing = await s.records.get(mcp_id)
                failed = existing or McpRecord(id=mcp_id, display_name=mcp_id)
                failed.state = "PARTIAL" if failed.usable else "FAILED"
                failed.error = "internal error; see Cloud Logging"
                await s.records.put(failed)

        background.add_task(task)
        return JSONResponse(
            {
                "id": mcp_id,
                "state": "RUNNING",
                "poll": f"/v1/mcps/{mcp_id}",
                "resuming_from": record.failed_stage,
                "reusing": record.completed_stages,
            },
            status_code=202,
        )

    @app.post("/v1/mcps/{mcp_id}/diagnose", tags=["mcps"], response_model=Diagnosis)
    async def diagnose_mcp(
        mcp_id: str, request: Request, refresh: bool = False
    ) -> Diagnosis:
        """Explain a failed run in terms of what to do about it.

        Known failures are matched against hand-written rules for free; anything
        else is sent to Gemini for a structured explanation. The result is
        cached on the record, because a finished run's cause cannot change and
        the model call is not free.
        """
        s = st(request)
        record = await s.records.get(mcp_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"unknown mcp id {mcp_id!r}")
        if not record.error:
            raise HTTPException(
                status_code=400,
                detail="this run did not fail; there is nothing to diagnose",
            )

        # A diagnosis from a hand-written rule is already final; only the
        # fallback placeholder is worth re-running against the model.
        cached = record.diagnosis
        if cached and not refresh and cached.get("source") != "none":
            return Diagnosis.model_validate(cached)

        # The genai SDK is synchronous, so keep it off the event loop.
        result = await asyncio.to_thread(diagnose, record.model_dump(mode="json"), settings)
        record.diagnosis = result.model_dump(mode="json", by_alias=True)
        try:
            await s.records.put(record)
        except Exception:  # noqa: BLE001 - caching is best-effort
            log.warning("could not cache diagnosis for %s", mcp_id, exc_info=True)
        return result

    @app.delete("/v1/mcps/{mcp_id}", tags=["mcps"])
    async def delete_mcp(mcp_id: str, request: Request) -> dict[str, Any]:
        """Tear down what a run created.

        Best-effort and order-independent: one stuck resource must not strand
        the rest, so every failure is collected and reported rather than raised.
        """
        s = st(request)
        record = await s.records.get(mcp_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"no MCP with id {mcp_id!r}")

        deps = s.pipeline.d
        errors: list[str] = []

        async def attempt(label: str, coro: Any) -> None:
            try:
                await coro
            except Exception as exc:  # noqa: BLE001 - collected, not swallowed
                errors.append(f"{label}: {exc}")

        # Order matters here, unlike everything below it. A data store still
        # listed on an engine makes its collection permanently undeletable
        # ("DataStore ... currently exists in list at index N of Engine ..."),
        # so the detach has to happen before the collection is touched.
        engine_id = (record.request or {}).get("gemini_enterprise_engine_id")
        if engine_id and record.datastore:
            await attempt(
                "detach_from_engine",
                deps.discovery.detach_datastore_from_engine(engine_id, record.datastore),
            )
        if record.collection:
            await attempt(
                "collection",
                deps.discovery.delete_collection(record.collection.rstrip("/").split("/")[-1]),
            )

        if record.registry_service:
            await attempt(
                "agent_registry",
                deps.registry.delete_service(record.registry_service.split("/")[-1]),
            )
        if record.authorization:
            await attempt(
                "authorization",
                deps.discovery.delete_authorization(record.authorization.split("/")[-1]),
            )

        # The OAuth proxy client and its secrets. Skipping these leaves a live
        # credential behind: the client still resolves, still redirects to the
        # upstream, and still carries its dynamically-registered upstream id,
        # long after the operator was told everything was removed.
        if record.proxy_client_id:
            await attempt("proxy_client", s.store.delete_client(record.proxy_client_id))
            for purpose in ("downstream", "upstream"):
                await attempt(
                    f"secret_{purpose}",
                    deps.secrets.delete(secret_id_for(mcp_id, purpose)),
                )

        # The upstream API key, for api_key runs. Same reasoning as the OAuth
        # secrets above: the Cloud Run service that read it is about to go, but
        # the key itself stays valid at the upstream until someone revokes it.
        if record.api_key_secret:
            await attempt("secret_apikey", deps.secrets.delete(secret_id_for(mcp_id, "apikey")))

        await attempt("cloud_run", deps.deployer.delete(f"mcp-{mcp_id}"[:49]))

        await s.records.delete(mcp_id)
        # Only report what actually survived. Claiming a resource needs manual
        # cleanup when it was just deleted sends people to the console to look
        # for something that is not there.
        stranded = [record.collection] if (record.collection and any(
            e.startswith(("collection:", "detach_from_engine:")) for e in errors
        )) else []
        return {
            "deleted": mcp_id,
            "errors": errors,
            "manual_cleanup_required": stranded,
            "note": (
                "The Gemini Enterprise collection could not be removed; delete it from "
                "the console."
                if stranded
                else "Everything this run created has been removed."
            ),
        }

    # -- diagnostics -----------------------------------------------------
    @app.post("/v1/preflight", tags=["diagnostics"], response_model=Preflight)
    async def preflight(req: CreateMcpRequest, request: Request) -> Preflight:
        """Report what this run needs before anything is created.

        Splits prerequisites into what the app will handle itself and what only
        you can do, with exact console links and values to paste.
        """
        s = st(request)
        return await evaluate(
            req,
            project_id=settings.project_id,
            proxy_redirect_uri=f"{settings.oauth_public_base_url}/oauth/callback",
            service_usage=s.pipeline.d.service_usage,
            registry=s.pipeline.d.registry,
            invoker_principals=settings.default_mcp_invokers,
        )

    @app.post("/v1/resolve", tags=["diagnostics"], response_model=ResolvedPlan)
    async def resolve_endpoint(payload: ResolveRequest, request: Request) -> ResolvedPlan:
        """Work out everything derivable from one input, and ask only the rest.

        Replaces the old approach of making the caller pre-answer eighteen form
        fields. Send a URL or pasted documentation; get back a complete request,
        the inferences made and why, and only the questions that genuinely
        remain. Answer them via ``overrides`` and call again until ``ready``.

        Creates nothing, so it is safe to call on every edit.
        """
        s = st(request)
        return await resolve_input(
            payload,
            settings,
            service_usage=s.pipeline.d.service_usage,
            registry=s.pipeline.d.registry,
            engines=s.pipeline.d.discovery,
        )

    @app.post("/v1/inspect/oauth", tags=["diagnostics"])
    async def inspect_oauth(payload: dict[str, str]) -> dict[str, Any]:
        """Probe a URL's OAuth support without provisioning anything.

        Answers "does this MCP actually need the proxy?" before you commit.
        """
        url = payload.get("url")
        if not url:
            raise HTTPException(status_code=400, detail="`url` is required")

        md = await md_mod.discover_for_mcp(url)
        if md is None:
            return {
                "discovered": False,
                "url": url,
                "verdict": "No authorization server found. Use auth_kind=none, or supply "
                "static credentials.",
            }
        return {
            "discovered": True,
            "issuer": md.issuer,
            "authorization_endpoint": md.authorization_endpoint,
            "token_endpoint": md.token_endpoint,
            "supports_dynamic_registration": md.supports_dcr,
            "allows_public_client": md.allows_public_client,
            "supports_pkce": md.supports_pkce,
            "scopes_supported": md.scopes_supported,
            "proxy_required": not md.supports_dcr and not md.allows_public_client,
            "verdict": (
                "Upstream supports RFC 7591; the proxy will register dynamically and expose "
                "a static client_id/secret to Gemini Enterprise."
                if md.supports_dcr
                else (
                    "Upstream allows public PKCE clients; the proxy will bridge them to a "
                    "static pair."
                    if md.allows_public_client
                    else "Upstream offers neither DCR nor public clients. Supply static "
                    "credentials explicitly."
                )
            ),
        }

    @app.post("/v1/inspect/manifest", tags=["diagnostics"])
    async def inspect_manifest(req: CreateMcpRequest) -> dict[str, Any]:
        """Run ingestion only, returning the manifest that would be deployed.

        Unusable documentation is the expected failure here, not an exception:
        report it as 400 with the parser's message so the caller can fix the
        input, rather than a 500 that reads like the service is broken.
        """
        if req.docs is None:
            raise HTTPException(
                status_code=400,
                detail="`docs` is required to inspect a manifest; `mcp_url` registers an "
                "existing server, whose tools come from its own tools/list.",
            )
        try:
            manifest = await build_manifest_from_request(req, settings)
        except INGEST_INPUT_ERRORS as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "manifest": manifest.model_dump(mode="json", by_alias=True),
            "agent_registry_tool_spec": manifest.to_mcp_tool_spec(),
        }

    return app


def main() -> None:
    import uvicorn

    uvicorn.run(
        create_app(),
        host="0.0.0.0",  # noqa: S104 - Cloud Run requires binding all interfaces
        port=int(os.getenv("PORT", "8080")),
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()
