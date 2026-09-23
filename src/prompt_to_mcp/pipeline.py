"""End-to-end provisioning pipeline.

Stages, in order (``preflight`` runs first and creates nothing):

1. ``ingest``        prompt + docs            -> validated ToolManifest
2. ``deploy``        manifest                 -> Cloud Run MCP service
3. ``oauth``         upstream AS discovery    -> DCR + synthetic static client
4. ``register``      manifest + URL           -> Agent Registry Service/McpServer
5. ``authorize``     synthetic client         -> Discovery Engine Authorization
6. ``connect``       MCP URL + authorization  -> Gemini Enterprise collection/datastore
7. ``attach``        datastore                -> Gemini Enterprise app (Engine)

Each stage records a :class:`StageResult`. A failure stops the run but leaves
every prior stage's output on the record, so a partially provisioned MCP can be
inspected and cleaned up rather than silently leaking resources.
"""

from __future__ import annotations

import logging
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Settings
from .deployer.cloud_run import CloudRunDeployer
from .gcp.agent_registry import AgentRegistryClient
from .gcp.discovery_engine import SUPPORTED_ACTION_PARAMS, DiscoveryEngineClient
from .gcp.secrets import SecretManager, secret_id_for
from .ingest import build_manifest_from_request, mcp_probe
from .ingest.detect import detect_mcp_server_url
from .ingest.fetcher import fetch_text
from .models import (
    OAUTH_PRESETS,
    AuthKind,
    CreateMcpRequest,
    DocSource,
    McpRecord,
    ProxyMode,
    StageResult,
    ToolManifest,
    UpstreamOAuth,
    holds_static_credential,
    preset_for_url,
    public_exposure_refusal,
    slugify,
)
from .oauth import dcr, metadata
from .oauth.store import ProxyClient, Store, hash_secret
from .redact import redact
from .requirements import apply_provider_defaults, evaluate, required_apis

log = logging.getLogger(__name__)

STAGES = (
    "preflight",
    "ingest",
    "deploy",
    "oauth",
    "register",
    "authorize",
    "connect",
    "attach",
)

#: Awaited after each stage so callers (the UI) can follow a run live.
ProgressCallback = Callable[[McpRecord], Awaitable[None]]


def _blocking_message(blocking: list[Any]) -> str:
    """Render unmet manual prerequisites as instructions, not as an error."""
    lines = [
        f"{len(blocking)} step(s) need you before this can run.",
        "",
    ]
    for req in blocking:
        lines.append(f"{req.title}: {req.detail}")
        for action in req.actions:
            lines.append(f"  - {action.text}")
            if action.url:
                lines.append(f"    {action.url}")
            if action.copy_value:
                lines.append(f"    value: {action.copy_value}")
            if action.cli:
                lines.append(f"    $ {action.cli}")
        lines.append("")
    lines.append("Nothing was created. Re-run once these are done.")
    return "\n".join(lines)


#: Doc sources are pasted by hand and can be megabytes; a Firestore document
#: caps at 1 MiB and the record has to fit alongside the manifest. Enough is
#: kept to identify the input and spot an obvious paste error.
DOC_SOURCE_PREVIEW = 4000


def _one_doc_summary(source: DocSource) -> dict[str, Any]:
    """Which documentation input was used, and (a prefix of) its value."""
    value = source.value
    summary: dict[str, Any] = {"kind": source.kind, "length": len(value)}
    if len(value) > DOC_SOURCE_PREVIEW:
        summary["value"] = value[:DOC_SOURCE_PREVIEW]
        summary["truncated"] = True
    else:
        summary["value"] = value
    return summary


def _doc_source_summaries(req: CreateMcpRequest) -> list[dict[str, Any]] | None:
    """One summary per doc source, in the order they were supplied."""
    if not req.docs:
        return None
    return [_one_doc_summary(s) for s in req.docs]


def _as_summary_list(docs: Any) -> list[dict[str, Any]]:
    """Read a persisted doc summary written by either shape.

    Records created before merging support stored a single dict. They are still
    in Firestore and still resumable, so both shapes are accepted on read.
    """
    if isinstance(docs, dict):
        return [docs]
    if isinstance(docs, list):
        return [d for d in docs if isinstance(d, dict)]
    return []


def request_snapshot(req: CreateMcpRequest) -> dict[str, Any]:
    """The submitted request, safe to persist and to render.

    Secrets are fingerprinted and the doc source is capped, so this can be
    written to Firestore and shipped to a browser as-is.
    """
    snapshot = req.model_dump(mode="json", by_alias=True, exclude_none=True)
    if req.docs is not None:
        snapshot["docs"] = _doc_source_summaries(req)
    return redact(snapshot)


class ResumeError(RuntimeError):
    """A run cannot be resumed without something the record does not hold."""


def _is_fingerprint(value: Any) -> bool:
    """Whether a snapshot value is a redaction rather than a real secret."""
    return isinstance(value, str) and value.startswith("***")


def _drop_fingerprints(value: Any) -> Any:
    """Remove redacted leaves so validation sees an absent field, not a lie.

    A fingerprint is deliberately not a usable value. Leaving one in place
    would produce a request that validates and then fails at the far end of an
    OAuth handshake with something unrecognisable.
    """
    if isinstance(value, dict):
        cleaned = {k: _drop_fingerprints(v) for k, v in value.items()}
        return {k: v for k, v in cleaned.items() if not _is_fingerprint(v)}
    if isinstance(value, list):
        return [_drop_fingerprints(v) for v in value]
    return value


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        elif value is not None:
            merged[key] = value
    return merged


def rehydrate_request(
    record: McpRecord, override: dict[str, Any] | None = None
) -> CreateMcpRequest:
    """Rebuild the request that produced ``record``, for a resumed run.

    The persisted snapshot is redacted and its doc source is truncated, so this
    is a reconstruction rather than a copy. That is sound because resume skips
    the stages whose inputs went missing: the manifest is already on the record
    by the time the doc source stops being recoverable, and a fingerprinted
    secret is only needed by a stage that already succeeded. ``override`` is how
    a caller resupplies anything that genuinely is needed again.
    """
    snapshot = _drop_fingerprints(dict(record.request or {}))

    # `docs` was stored as a summary, not as a DocSource. It is restored even
    # when truncated, because the request will not validate without it -- but a
    # truncated value must never reach the synthesiser, so `run` refuses to
    # re-ingest from one. See `_check_resumable_docs`.
    docs = snapshot.pop("docs", None)
    restored = [{d["kind"]: d.get("value")} for d in _as_summary_list(docs) if d.get("kind")]
    if restored:
        snapshot["docs"] = restored

    if override:
        snapshot = _deep_merge(snapshot, override)
    try:
        return CreateMcpRequest.model_validate(snapshot)
    except Exception as exc:  # noqa: BLE001 - re-raised as an actionable message
        raise ResumeError(
            f"cannot rebuild the original request for {record.id}: {exc}. "
            "Pass the missing fields in the resume request body."
        ) from exc


def _docs_were_truncated(record: McpRecord) -> bool:
    """True if *any* stored source was capped; re-ingesting would lose content."""
    return any(d.get("truncated") for d in _as_summary_list((record.request or {}).get("docs")))


def _strip_html(text: str) -> str:
    """Crude tag removal so detection works on rendered documentation pages."""
    import html as _html

    body = re.sub(r"<script.*?</script>", " ", text, flags=re.S | re.I)
    body = re.sub(r"<style.*?</style>", " ", body, flags=re.S | re.I)
    return _html.unescape(re.sub(r"<[^>]+>", " ", body))


class PipelineError(RuntimeError):
    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        super().__init__(f"[{stage}] {message}")


@dataclass(slots=True)
class Dependencies:
    settings: Settings
    deployer: CloudRunDeployer
    registry: AgentRegistryClient
    discovery: DiscoveryEngineClient
    secrets: SecretManager
    store: Store
    service_usage: Any | None = None


class Pipeline:
    def __init__(self, deps: Dependencies) -> None:
        self.d = deps
        self._on_progress: ProgressCallback | None = None

    # ------------------------------------------------------------------
    def _should_stop(self, req: CreateMcpRequest, stage: str) -> bool:
        if not req.stop_after:
            return False
        try:
            return STAGES.index(stage) >= STAGES.index(req.stop_after)
        except ValueError:
            return False

    async def _reuse_stage(
        self, record: McpRecord, stage: str, detail: str, **data: Any
    ) -> None:
        """Mark a stage satisfied by a previous run's output.

        Recorded as a distinct outcome rather than a silent skip: "reused" and
        "created" are different facts about what exists in the project, and the
        difference matters when someone is deciding what to clean up.
        """
        record.stages.append(
            StageResult(stage=stage, ok=True, detail=f"reused: {detail}", data=redact(data))
        )
        log.info("[%s] reused: %s", stage, detail)
        await self._emit(record)

    async def _record_stage(
        self, record: McpRecord, stage: str, detail: str, **data: Any
    ) -> None:
        record.stages.append(
            StageResult(stage=stage, ok=True, detail=detail, data=redact(data))
        )
        log.info("[%s] %s", stage, detail)
        await self._emit(record)

    @staticmethod
    def _record_config(record: McpRecord, stage: str, **config: Any) -> None:
        """Attach the effective configuration of a stage to the record.

        Written *before* the call it describes, so a stage that fails still
        leaves behind the exact inputs that produced the failure -- which is
        the whole point. Secrets are fingerprinted, never stored in the clear:
        this ends up in Firestore and in a browser.
        """
        bucket = dict(record.config.get(stage) or {})
        bucket.update(redact(config))
        record.config[stage] = bucket

    async def _emit(self, record: McpRecord) -> None:
        """Publish intermediate state so a UI can follow a run live."""
        if self._on_progress is None:
            return
        try:
            await self._on_progress(record)
        except Exception:  # noqa: BLE001 - progress reporting must never fail a run
            log.warning("progress callback failed", exc_info=True)

    # ------------------------------------------------------------------
    async def run(
        self,
        req: CreateMcpRequest,
        *,
        mcp_id: str | None = None,
        on_progress: ProgressCallback | None = None,
        resume: McpRecord | None = None,
    ) -> McpRecord:
        """Execute the pipeline.

        `mcp_id` lets the caller fix the identifier up front so a UI has a
        stable handle to poll from the moment the request is accepted, rather
        than a throwaway token that is later swapped for a different id.

        `on_progress` is awaited after every stage, which is what makes a live
        progress view possible.

        `resume` continues a run that stopped part-way instead of starting a
        new one. Stages whose output is already on the record are reused rather
        than repeated: they created real, uniquely-named cloud resources, and
        redoing them would at best cost money and at worst collide with
        themselves (Agent Registry interface URLs are unique per location, so a
        fresh run against an already-registered endpoint cannot succeed).
        """
        settings = self.d.settings
        base_name = slugify(req.name or req.description[:40])
        self._on_progress = on_progress

        if resume is not None:
            mcp_id = resume.id
            record = resume
            record.state = "RUNNING"
            # The previous failure is being retried, not remembered. Leaving it
            # in place would make a successful resume still render as broken.
            record.error = None
            record.failed_stage = None
            record.diagnosis = None
        else:
            mcp_id = mcp_id or f"{base_name}-{secrets.token_hex(3)}"
            record = McpRecord(
                id=mcp_id,
                display_name=req.name or base_name,
                description=req.description,
                state="RUNNING",
                # The inputs, including the doc source. Persisted so a run can
                # be diffed against another, or reproduced, without the
                # operator having to remember what they typed.
                request=request_snapshot(req),
            )
        # Stage outputs already on the record. Consulted per stage rather than
        # trusted wholesale: `stages` records that a stage ran, the resource
        # fields record that it produced something, and only the latter is
        # safe to reuse.
        done = set(record.completed_stages) if resume is not None else set()
        await self._emit(record)

        # Tracks the executing stage so an exception raised by a client library
        # -- not just an explicit PipelineError -- is still attributed to the
        # right stage. Must be bound before the try, or a failure in `ingest`
        # would raise NameError inside the exception handler.
        current = "preflight"

        try:
            # -- 0. preflight ---------------------------------------------
            # Resolve the target and fill in everything inferable BEFORE doing
            # any work, so a missing prerequisite fails here rather than after
            # a Cloud Run service has already been created.
            existing_url: str | None = req.mcp_url
            auto_switch: Any = None
            if not existing_url and req.docs is not None:
                auto_switch = await self._detect_existing_mcp(req, settings)
                if auto_switch is not None:
                    existing_url = auto_switch.url

            # The app already knows a recognised provider's endpoints and
            # scopes; asking the operator to restate them would be withholding
            # information we have.
            req = apply_provider_defaults(req, mcp_url=existing_url)

            notes: list[str] = []
            apis = required_apis(req)
            if apis and self.d.service_usage is not None:
                try:
                    result = await self.d.service_usage.enable(apis)
                    newly = result.get("enabled") or []
                    notes.append(
                        f"enabled {', '.join(newly)}"
                        if newly
                        else f"required API(s) already enabled: {', '.join(apis)}"
                    )
                except Exception as exc:  # noqa: BLE001 - advisory, not fatal
                    notes.append(
                        f"could not enable {', '.join(apis)} automatically ({exc}); "
                        f"run: gcloud services enable {' '.join(apis)} "
                        f"--project {settings.project_id}"
                    )
            if req.oauth and req.oauth.preset and req.oauth.has_endpoints:
                notes.append(f"applied the '{req.oauth.preset}' OAuth preset automatically")

            # `req` is no longer what was submitted: presets and provider
            # defaults have been folded in. Record the resolved form separately
            # so the difference between "what I asked for" and "what actually
            # ran" is visible instead of inferred.
            self._record_config(
                record,
                "preflight",
                resolved_request=request_snapshot(req),
                required_apis=apis,
                project_id=settings.project_id,
                run_region=settings.run_region,
                agent_registry_location=settings.agent_registry_location,
                discovery_engine_location=settings.discovery_engine_location,
                public_base_url=settings.public_base_url,
                oauth_base_url=settings.oauth_public_base_url,
                detected_existing_mcp_url=existing_url,
            )

            preflight = await evaluate(
                req,
                project_id=settings.project_id,
                proxy_redirect_uri=f"{settings.oauth_public_base_url}/oauth/callback",
                service_usage=self.d.service_usage,
                registry=self.d.registry,
                invoker_principals=settings.default_mcp_invokers,
            )
            # Serialise: the record is persisted to Firestore and rendered by
            # the UI, so it must hold plain JSON, not Pydantic objects.
            record.requirements = [
                r.model_dump(mode="json", by_alias=True) for r in preflight.requirements
            ]

            await self._record_stage(
                record,
                "preflight",
                "; ".join(notes) if notes else preflight.summary,
                apis=apis,
                ready=preflight.ready,
            )

            blocking = preflight.blocking_manual
            if blocking:
                # Fail here, before creating anything, and say exactly what is
                # needed rather than surfacing it later as a discovery error.
                raise PipelineError("preflight", _blocking_message(blocking))

            if self._should_stop(req, "preflight"):
                record.state = "STOPPED_AFTER_PREFLIGHT"
                await self._emit(record)
                return record

            # -- 1. ingest ------------------------------------------------
            current = "ingest"
            manifest = None
            tool_spec: dict[str, Any] | None = None

            self._record_config(
                record,
                "ingest",
                mode="existing" if existing_url else "generate",
                # Which doc inputs were used, and their values. Truncated: a
                # pasted OpenAPI document can be megabytes, and Firestore
                # documents cap at 1 MiB.
                #
                # `doc_source` stays the first source so that readers predating
                # merge support -- the failure diagnoser, stored records, the
                # UI -- keep working; `doc_sources` carries the full list.
                doc_source=(_doc_source_summaries(req) or [None])[0],
                doc_sources=_doc_source_summaries(req),
                mcp_url=existing_url,
                base_url_override=req.base_url,
                include_operations=req.include_operations,
                allowed_upstream_hosts=settings.allowed_upstream_hosts,
                gemini_model=settings.gemini_model,
                max_tools=settings.max_tools,
            )

            if auto_switch is not None:
                await self._record_stage(
                    record,
                    "ingest",
                    f"these docs describe an MCP server that already exists at "
                    f"{auto_switch.url} -- switching to register-existing mode because "
                    f"{auto_switch.reason}",
                    mode="auto-switched",
                    detected_url=auto_switch.url,
                )

            if "ingest" in done and record.manifest is not None and not existing_url:
                # Re-synthesising would call Gemini again and could produce a
                # different tool set than the one already deployed.
                manifest = record.manifest
                tool_spec = manifest.to_mcp_tool_spec()
                await self._reuse_stage(
                    record,
                    "ingest",
                    f"manifest with {len(manifest.tools)} tool(s) from the original run",
                    tools=[t.name for t in manifest.tools],
                )
            elif resume is not None and not existing_url and _docs_were_truncated(record):
                # Re-synthesising from a truncated paste would produce a
                # different tool set than the one this record describes, which
                # is worse than refusing.
                raise ResumeError(
                    f"{mcp_id} has no manifest to reuse and its documentation was too "
                    "large to store in full, so it cannot be re-ingested. Resupply "
                    "`docs` in the resume request body, or start a new run."
                )
            elif existing_url:
                # The server is authoritative about its own tools; there is
                # nothing to synthesise.
                probe_result = await mcp_probe.probe(
                    existing_url,
                    allowed_hosts=settings.allowed_upstream_hosts or None,
                )
                if not probe_result.reachable:
                    raise PipelineError(
                        "ingest",
                        f"could not reach MCP server {existing_url}: {probe_result.error}",
                    )
                tool_spec = probe_result.tool_spec
                record.display_name = req.name or probe_result.server_name or base_name
                detail = (
                    f"read {len(probe_result.tools)} tool(s) from the existing MCP server"
                    if probe_result.tools
                    else f"MCP server reachable but exposed no catalog ({probe_result.error}); "
                    "registering with NO_SPEC"
                )
                await self._record_stage(
                    record,
                    "ingest",
                    detail,
                    mode="existing",
                    mcp_url=existing_url,
                    tools=probe_result.tool_names,
                    requires_auth=probe_result.requires_auth,
                )
            else:
                manifest = await build_manifest_from_request(req, settings)
                record.manifest = manifest
                record.display_name = manifest.display_name
                tool_spec = manifest.to_mcp_tool_spec()
                self._record_config(
                    record,
                    "ingest",
                    manifest_source=manifest.source,
                    manifest_base_url=manifest.base_url,
                    manifest_auth=manifest.auth.model_dump(mode="json"),
                )
                await self._record_stage(
                    record,
                    "ingest",
                    f"derived {len(manifest.tools)} tool(s) from "
                    f"{manifest.source.get('kind')} source",
                    mode="generate",
                    tools=[t.name for t in manifest.tools],
                    base_url=manifest.base_url,
                )
            if self._should_stop(req, "ingest"):
                record.state = "STOPPED_AFTER_INGEST"
                await self._emit(record)
                return record

            # -- 2. deploy ------------------------------------------------
            current = "deploy"
            if existing_url:
                mcp_endpoint = existing_url
                await self._record_stage(
                    record,
                    "deploy",
                    f"skipped: registering the existing server at {mcp_endpoint}",
                    mcp_endpoint=mcp_endpoint,
                )
            elif "deploy" in done and record.mcp_endpoint:
                # Cloud Run deploys are idempotent, but redeploying would churn
                # a revision for no reason and the URL is what matters here.
                mcp_endpoint = record.mcp_endpoint
                await self._reuse_stage(
                    record,
                    "deploy",
                    f"MCP already live at {mcp_endpoint}",
                    mcp_endpoint=mcp_endpoint,
                )
            else:
                assert manifest is not None
                service_id = f"mcp-{mcp_id}"[:49]

                # An API key has to exist in Secret Manager before the service
                # that reads it is created, and `deploy` runs two stages ahead
                # of `oauth`, so this cannot wait for the credential stage.
                api_key_secret = await self._store_api_key(req, manifest, mcp_id)

                # Who may invoke the finished service. Decided here, from the
                # manifest, and passed explicitly -- the deployer defaults to
                # refusing public access, and this is the only place that knows
                # enough to overrule it.
                public, invokers = self._exposure(req, manifest, mcp_id)

                self._record_config(
                    record,
                    "deploy",
                    service_id=service_id,
                    region=settings.run_region,
                    runtime_image=self.d.deployer.runtime_image,
                    service_account=settings.mcp_service_account,
                    labels={"p2m-id": mcp_id[:63]},
                    # Safe to record: a Secret Manager resource name, not a key.
                    api_key_secret=api_key_secret,
                    allow_public_unauthenticated=public,
                    invoker_principals=invokers,
                    manifest=manifest.model_dump(mode="json", by_alias=True),
                )
                deployment = await self.d.deployer.deploy(
                    service_id=service_id,
                    manifest=manifest.model_dump(mode="json", by_alias=True),
                    description=manifest.description,
                    labels={"p2m-id": mcp_id[:63]},
                    api_key_secret=api_key_secret,
                    allow_unauthenticated=public,
                    invoker_principals=invokers,
                )
                mcp_endpoint = deployment.mcp_endpoint
                record.cloud_run_url = deployment.uri
                record.image = self.d.deployer.runtime_image
                record.api_key_secret = api_key_secret
                await self._record_stage(
                    record,
                    "deploy",
                    f"MCP live at {deployment.mcp_endpoint}",
                    uri=deployment.uri,
                    mcp_endpoint=deployment.mcp_endpoint,
                    manifest_location=deployment.manifest_location,
                )
            if self._should_stop(req, "deploy"):
                record.state = "STOPPED_AFTER_DEPLOY"
                await self._emit(record)
                return record

            # -- 3. oauth -------------------------------------------------
            current = "oauth"
            proxy_client: ProxyClient | None = None
            plain_secret: str | None = None
            direct: UpstreamOAuth | None = None

            self._record_config(
                record,
                "oauth",
                auth_kind=str(req.auth_kind),
                use_proxy=str(req.use_proxy),
                scopes=req.scopes,
                supplied=(
                    req.oauth.model_dump(mode="json", exclude_none=True) if req.oauth else None
                ),
                proxy_redirect_uri=f"{settings.oauth_public_base_url}/oauth/callback",
            )

            if req.auth_kind is AuthKind.OAUTH_USER and "oauth" in done and record.proxy_client_id:
                # The synthetic client is already minted and already referenced
                # by an Authorization resource. Re-minting would rotate the
                # secret out from under it.
                proxy_client, plain_secret = await self._rehydrate_oauth(record)
                await self._reuse_stage(
                    record,
                    "oauth",
                    f"existing synthetic client {record.proxy_client_id}",
                    proxy_client_id=record.proxy_client_id,
                )
            elif req.auth_kind is AuthKind.OAUTH_USER:
                direct = self._direct_oauth(req)
                if direct is not None:
                    # Static credentials already exist, so the proxy would add a
                    # hop and a failure mode without solving anything. Point
                    # Gemini Enterprise straight at the upstream.
                    self._record_config(
                        record,
                        "oauth",
                        mode="direct",
                        effective=direct.model_dump(mode="json", exclude_none=True),
                    )
                    await self._record_stage(
                        record,
                        "oauth",
                        "using operator-supplied static credentials; OAuth proxy not needed",
                        mode="direct",
                        issuer=direct.issuer,
                        authorization_endpoint=direct.authorization_endpoint,
                        token_endpoint=direct.token_endpoint,
                    )
                else:
                    # The resource that needs credentials is the UPSTREAM, not
                    # our own server. In generate mode the MCP we just deployed
                    # is a pass-through, so probing it for an authorization
                    # server is meaningless -- probe the API it wraps.
                    auth_target = (
                        existing_url if existing_url else (manifest.base_url if manifest else "")
                    )
                    self._record_config(
                        record, "oauth", mode="proxy", discovery_target=auth_target
                    )
                    proxy_client, plain_secret = await self._provision_oauth(
                        req, auth_target, mcp_id, record
                    )
                    record.proxy_client_id = proxy_client.client_id
            elif req.auth_kind is AuthKind.API_KEY:
                # The credential was stored during `deploy`, because Cloud Run
                # needs it when the service is created. Nothing to negotiate:
                # there is no authorization server and no per-user consent.
                await self._record_stage(
                    record,
                    "oauth",
                    "not applicable: the upstream is called with a stored API key",
                    mode="api_key",
                    api_key_secret=record.api_key_secret,
                )
            else:
                await self._record_stage(
                    record, "oauth", f"skipped: auth kind is {req.auth_kind}"
                )
            if self._should_stop(req, "oauth"):
                record.state = "STOPPED_AFTER_OAUTH"
                await self._emit(record)
                return record

            # -- 4. register ----------------------------------------------
            current = "register"
            service_id = f"mcp-{mcp_id}"[:63]
            if "register" in done and record.registry_service:
                # Interface URLs are unique per location, so this is the stage
                # that makes a naive retry impossible. Reusing the existing
                # registration is what lets a resume get past it at all.
                await self._reuse_stage(
                    record,
                    "register",
                    f"already registered as {record.registry_resource or record.registry_service}",
                    service=record.registry_service,
                    mcp_server=record.registry_resource,
                )
            else:
                self._record_config(
                    record,
                    "register",
                    service_id=service_id,
                    location=settings.agent_registry_location,
                    mcp_url=mcp_endpoint,
                    tool_spec=tool_spec,
                )
                service = await self.d.registry.create_service(
                    service_id,
                    display_name=record.display_name,
                    description=req.description,
                    mcp_url=mcp_endpoint,
                    tool_spec=tool_spec,
                )
                record.registry_service = service.get(
                    "name", f"{self.d.registry.parent}/services/{service_id}"
                )
                record.registry_resource = service.get("registryResource")
                if not record.registry_resource:
                    # The projection can lag the create by a moment.
                    record.registry_resource = await self.d.registry.resolve_registry_resource(
                        service_id
                    )
                await self._record_stage(
                    record,
                    "register",
                    "registered in Agent Registry as "
                    f"{record.registry_resource or record.registry_service}",
                    service=record.registry_service,
                    mcp_server=record.registry_resource,
                )
            if self._should_stop(req, "register"):
                record.state = "STOPPED_AFTER_REGISTER"
                await self._emit(record)
                return record

            # -- 5. authorize ---------------------------------------------
            current = "authorize"
            authorization_name: str | None = None
            auth_uri = token_uri = auth_client_id = auth_client_secret = ""
            auth_scopes: list[str] = []

            # The Authorization resource wants a complete authorization
            # *request* URL; the connector wants the bare endpoint plus the
            # extra query string separately. Both are derived here so neither
            # has to unpick the other's format.
            auth_endpoint = ""
            auth_uri_params = ""

            if direct is not None:
                auth_uri = self._direct_authorization_uri(direct)
                auth_endpoint = direct.authorization_endpoint or ""
                auth_uri_params = "&access_type=offline&prompt=consent"
                token_uri = direct.token_endpoint or ""
                auth_client_id = direct.client_id or ""
                auth_client_secret = direct.client_secret or ""
                auth_scopes = direct.scopes or req.scopes
            elif proxy_client is not None and plain_secret is not None:
                auth_uri = self._authorization_uri(proxy_client)
                auth_endpoint = f"{self.d.settings.oauth_public_base_url}/oauth/authorize"
                token_uri = f"{self.d.settings.oauth_public_base_url}/oauth/token"
                auth_client_id = proxy_client.client_id
                auth_client_secret = plain_secret
                auth_scopes = proxy_client.scopes

            self._record_config(
                record,
                "authorize",
                authorization_id=f"p2m-{mcp_id}"[:63],
                client_id=auth_client_id or None,
                client_secret=auth_client_secret or None,
                authorization_uri=auth_uri or None,
                token_uri=token_uri or None,
                scopes=auth_scopes,
                pkce=True,
                source="direct" if direct is not None else ("proxy" if proxy_client else "none"),
            )

            if auth_client_id and "authorize" in done and record.authorization:
                authorization_name = record.authorization
                await self._reuse_stage(
                    record,
                    "authorize",
                    f"existing authorization {authorization_name}",
                    authorization=authorization_name,
                )
            elif auth_client_id:
                authorization_name = await self._create_authorization(
                    mcp_id,
                    display_name=record.display_name,
                    client_id=auth_client_id,
                    client_secret=auth_client_secret,
                    authorization_uri=auth_uri,
                    token_uri=token_uri,
                    scopes=auth_scopes,
                    record=record,
                )
                record.authorization = authorization_name
            else:
                await self._record_stage(record, "authorize", "skipped: no OAuth required")
            if self._should_stop(req, "authorize"):
                record.state = "STOPPED_AFTER_AUTHORIZE"
                await self._emit(record)
                return record

            # -- 6. connect -------------------------------------------------
            current = "connect"
            if "connect" in done and record.datastore:
                await self._reuse_stage(
                    record,
                    "connect",
                    f"existing data store {record.datastore}",
                    collection=record.collection,
                    datastore=record.datastore,
                )
            else:
                # A resumed connect reuses the collection the failed attempt
                # named, rather than stranding it and creating a second one.
                collection_id = (
                    (record.collection or "").rsplit("/", 1)[-1]
                    or f"{slugify(base_name, 40)}-{int(time.time())}"[:63]
                )
                setup_access_token = secrets.token_urlsafe(24)
                # The connector carries its own OAuth configuration, as a
                # complete group or not at all. This is separate from -- and in
                # addition to -- the Authorization resource created above.
                oauth_action_params = DiscoveryEngineClient.build_oauth_action_params(
                    client_id=auth_client_id,
                    client_secret=auth_client_secret,
                    authorization_endpoint=auth_endpoint,
                    token_endpoint=token_uri,
                    scopes=auth_scopes,
                    authorization_uri_params=auth_uri_params,
                )
                connector = DiscoveryEngineClient.build_mcp_connector(
                    mcp_url=mcp_endpoint,
                    # Gemini Enterprise demands a "Private App Access Token" at
                    # setup time even when the connector needs no credentials.
                    # The generated MCP is a pass-through that requires no token
                    # to serve tools/list, so a fresh opaque placeholder
                    # satisfies the check without minting a real credential.
                    # Per-user tokens for tool calls arrive later from the
                    # Authorization resource.
                    setup_access_token=setup_access_token,
                    oauth_action_params=oauth_action_params,
                )
                # Values the negotiation loop may put into `params` if the
                # server asks for them, so a shape change is answered from what
                # this run already holds rather than failing a user who has
                # nothing left to configure. Only keys named in a 400 are ever
                # sent; the pool is not a body.
                #
                # OAuth credentials are deliberately absent. They belong in
                # `actionParams`, and `params` rejects them outright -- offering
                # them here would make the loop chase a contradiction that the
                # server states in two mutually exclusive error messages.
                param_pool: dict[str, Any] = {
                    "oauth_access_token": setup_access_token,
                    "instance_uri": mcp_endpoint,
                }

                negotiation: list[dict[str, Any]] = []
                # The exact body, recorded before the call. This stage fails
                # more often than any other and its 400s name a single field, so
                # the request that produced one has to survive the failure.
                self._record_config(
                    record,
                    "connect",
                    endpoint=f"{self.d.discovery.parent}:setUpDataConnector",
                    collection_id=collection_id,
                    request_body={
                        "collectionId": collection_id,
                        "collectionDisplayName": record.display_name,
                        "dataConnector": connector,
                    },
                    supported_action_params=sorted(SUPPORTED_ACTION_PARAMS),
                    negotiable_params=sorted(param_pool),
                    credential_propagation=(
                        f"via authorization {authorization_name}"
                        if authorization_name
                        else "none: no Authorization resource was created"
                    ),
                )

                def note_attempt(entry: dict[str, Any]) -> None:
                    # Persisted whether or not the call ends up succeeding: a
                    # run that only worked on the second shape is the earliest
                    # warning that the API moved, and it should not take a
                    # failure to see it.
                    negotiation.append(entry)
                    self._record_config(record, "connect", negotiation=list(negotiation))

                try:
                    await self.d.discovery.set_up_mcp_connector(
                        collection_id=collection_id,
                        display_name=record.display_name,
                        connector=connector,
                        param_pool=param_pool,
                        on_attempt=note_attempt,
                    )
                finally:
                    if len(negotiation) > 1:
                        log.warning(
                            "connector shape negotiated over %d attempts for %s; "
                            "the API's required params have changed",
                            len(negotiation),
                            mcp_id,
                        )
                record.collection = f"{self.d.discovery.parent}/collections/{collection_id}"
                record.datastore = await self.d.discovery.wait_for_mcp_datastore(collection_id)
                await self._record_stage(
                    record,
                    "connect",
                    f"connected to Gemini Enterprise as data store {record.datastore}",
                    collection=record.collection,
                    datastore=record.datastore,
                )
            if self._should_stop(req, "connect"):
                record.state = "STOPPED_AFTER_CONNECT"
                await self._emit(record)
                return record

            # -- 7. attach --------------------------------------------------
            current = "attach"
            self._record_config(
                record,
                "attach",
                engine_id=req.gemini_enterprise_engine_id,
                datastore=record.datastore,
                collection="default_collection",
            )
            if req.gemini_enterprise_engine_id:
                await self.d.discovery.attach_datastore_to_engine(
                    req.gemini_enterprise_engine_id, record.datastore
                )
                await self._record_stage(
                    record,
                    "attach",
                    f"attached to Gemini Enterprise app {req.gemini_enterprise_engine_id}",
                    engine=req.gemini_enterprise_engine_id,
                )
            else:
                await self._record_stage(
                    record,
                    "attach",
                    "skipped: no gemini_enterprise_engine_id supplied; data store is created "
                    "but not bound to an app",
                )

            record.state = "READY"
            await self._emit(record)
            return record

        except Exception as exc:  # noqa: BLE001 - recorded and re-raised as a record
            stage = exc.stage if isinstance(exc, PipelineError) else current
            # A failure after `register` did not stop the user getting a working
            # MCP server -- it stopped it being wired into Gemini Enterprise.
            # Calling that FAILED is inaccurate and throws away something they
            # can use today, so the two outcomes are named differently.
            record.state = "PARTIAL" if record.usable else "FAILED"
            record.failed_stage = stage
            record.error = str(exc)
            record.stages.append(StageResult(stage=stage, ok=False, detail=str(exc)))
            log.exception("pipeline %s for %s at stage %s", record.state.lower(), mcp_id, stage)

            # Attach the deterministic explanation immediately: it is free and
            # instant, so a failed run is never presented as a bare stack of
            # API jargon. The model-backed explanation is requested separately
            # by the UI, since it costs money and most failures are known ones.
            try:
                from .diagnose import match_known

                known = match_known(record.model_dump(mode="json"))
                if known is not None:
                    record.diagnosis = known.model_dump(mode="json", by_alias=True)
            except Exception:  # noqa: BLE001 - explanation must never mask the failure
                log.warning("could not diagnose %s", mcp_id, exc_info=True)

            await self._emit(record)
            return record

    async def _detect_existing_mcp(self, req: CreateMcpRequest, settings: Settings):  # noqa: ANN201
        """Peek at the supplied docs for an existing MCP server endpoint.

        With several sources, one hit is enough: the whole request collapses to
        register-existing mode, so the remaining documents describe the same
        server and have nothing left to contribute.
        """
        for source in req.docs or []:
            # An explicit OpenAPI document describes an API to wrap, by definition.
            if source.is_openapi:
                continue
            try:
                if source.url:
                    text = await fetch_text(
                        source.url, allowed_hosts=settings.allowed_upstream_hosts or None
                    )
                else:
                    text = source.text or ""
            except Exception as exc:  # noqa: BLE001 - detection is advisory
                log.debug("could not fetch docs for MCP detection: %s", exc)
                continue
            found = detect_mcp_server_url(_strip_html(text))
            if found is not None:
                return found
        return None

    # ------------------------------------------------------------------
    def _exposure(
        self, req: CreateMcpRequest, manifest: ToolManifest, mcp_id: str
    ) -> tuple[bool, list[str]]:
        """Decide who may invoke the generated service.

        Returns ``(allow_unauthenticated, invoker_principals)``.

        The rule is the manifest's auth kind, not the request's: the manifest is
        what the runtime will actually obey, and ingest can settle a kind the
        request left implicit.

        Refusing is not silent. A private service that Gemini Enterprise cannot
        reach is an outage wearing a security fix's clothes, so the run stops
        here, before a Cloud Run service exists, with an error that names the
        problem and the ways out.
        """
        kind = manifest.auth.kind
        invokers = self.d.settings.default_mcp_invokers

        if not holds_static_credential(kind):
            return True, []

        if req.allow_public_unauthenticated:
            log.warning(
                "%s: publishing an auth_kind=%s MCP to allUsers because "
                "allow_public_unauthenticated was set. Its credential can be spent "
                "by anyone who finds the URL.",
                mcp_id,
                kind.value,
            )
            return True, []

        if invokers:
            log.info(
                "%s: auth_kind=%s deployed privately; run.invoker -> %s",
                mcp_id,
                kind.value,
                ", ".join(invokers),
            )
            return False, invokers

        raise PipelineError("deploy", public_exposure_refusal(mcp_id, kind, invokers))

    async def _store_api_key(
        self, req: CreateMcpRequest, manifest: ToolManifest, mcp_id: str
    ) -> str | None:
        """Persist the upstream API key and point the manifest at it.

        Returns the Secret Manager version name, or ``None`` when the run does
        not use API-key auth. Called from `deploy` rather than `oauth` because
        Cloud Run resolves the secret when the service is created, which is two
        stages earlier.

        The manifest is mutated to carry the *reference* before it is written
        anywhere. Order matters: the manifest is recorded in the stage config
        and injected as an environment variable moments later, so filling in
        ``secret_ref`` afterwards would publish a manifest that the runtime
        cannot authenticate with.
        """
        if req.auth_kind is not AuthKind.API_KEY:
            return None
        if not req.api_key:
            # Unreachable via the API (CreateMcpRequest rejects it), but a
            # resumed run rehydrates from a record whose key was fingerprinted.
            raise PipelineError(
                "deploy",
                "this run uses API-key authentication, but the key is not on the "
                "record -- it is fingerprinted, never stored. Resume with "
                '`{"overrides": {"api_key": "<the key>"}}`.',
            )

        secret_id = secret_id_for(mcp_id, "apikey")
        version = await self.d.secrets.create_or_update(secret_id, req.api_key)
        manifest.auth.secret_ref = version
        log.info("stored upstream API key for %s as %s", mcp_id, secret_id)
        return version

    async def _rehydrate_oauth(self, record: McpRecord) -> tuple[ProxyClient, str]:
        """Recover a previous run's synthetic client instead of minting a new one.

        The plaintext secret was never persisted on the record -- only its hash
        -- so it is read back from Secret Manager. Minting a replacement would
        be easier and wrong: the Authorization resource already created in the
        `authorize` stage holds the old one, and Gemini Enterprise would then
        present a secret the proxy no longer accepts.
        """
        client_id = record.proxy_client_id or ""
        client = await self.d.store.get_client(client_id)
        if client is None:
            raise ResumeError(
                f"the OAuth client {client_id!r} this run created is no longer in the "
                "store, so its credentials cannot be reused. Delete the run and start "
                "again."
            )
        ref = (
            f"projects/{self.d.settings.project_id}/secrets/"
            f"{secret_id_for(record.id, 'downstream')}"
        )
        secret = await self.d.secrets.resolve(ref)
        if not secret:
            raise ResumeError(
                f"the synthetic client secret for {client_id!r} could not be read back "
                f"from Secret Manager ({ref}). Delete the run and start again."
            )
        return client, secret

    async def _provision_oauth(
        self,
        req: CreateMcpRequest,
        upstream_url: str,
        mcp_id: str,
        record: McpRecord,
    ) -> tuple[ProxyClient, str]:
        """Discover the upstream AS, obtain real credentials, mint synthetic ones.

        Returns the persisted client and the plaintext synthetic secret. The
        plaintext is returned rather than stashed on ``self`` so that concurrent
        pipeline runs sharing one instance cannot clobber each other's secret.
        """
        settings = self.d.settings
        redirect_uri = f"{settings.oauth_public_base_url}/oauth/callback"
        configured = req.oauth
        display_name = record.display_name
        wanted_scopes = (configured.scopes if configured else None) or req.scopes

        async with httpx.AsyncClient(timeout=metadata.TIMEOUT, follow_redirects=True) as http:
            md: metadata.AuthServerMetadata | None = None

            # Explicit endpoints win: several providers (notably Google) serve
            # no RFC 9728 / RFC 8414 metadata at all and document their OAuth
            # configuration out of band.
            if configured and configured.has_endpoints:
                md = metadata.AuthServerMetadata(
                    issuer=configured.issuer or configured.authorization_endpoint or "",
                    authorization_endpoint=configured.authorization_endpoint or "",
                    token_endpoint=configured.token_endpoint or "",
                    scopes_supported=list(configured.scopes),
                )
            elif configured and configured.issuer:
                md = await metadata.discover_from_issuer(configured.issuer, client=http)

            if md is None:
                md = await metadata.discover_for_mcp(upstream_url, client=http)

            hint = preset_for_url(upstream_url)
            if md is None and hint:
                # Discovery failing against a host we already have endpoints for
                # is not new information. This lookup existed before, but only
                # to phrase the error -- so a run against any *.googleapis.com
                # API died three stages in, telling the user to supply a preset
                # the code had already identified. Apply it instead.
                preset = OAUTH_PRESETS[hint]
                md = metadata.AuthServerMetadata(
                    issuer=preset["issuer"],
                    authorization_endpoint=preset["authorization_endpoint"],
                    token_endpoint=preset["token_endpoint"],
                    scopes_supported=list(wanted_scopes),
                )
                self._record_config(record, "oauth", preset_applied=hint)
                log.info("applied %r OAuth preset for %s", hint, upstream_url)

            if md is None:
                raise PipelineError(
                    "oauth",
                    f"could not discover an OAuth authorization server for {upstream_url}."
                    " Supply `oauth.authorization_endpoint` and `oauth.token_endpoint`,"
                    " or set auth_kind=none if the API needs no user credentials,"
                    " or auth_kind=api_key with an `api_key` if it uses a static key.",
                )

            try:
                upstream = await dcr.resolve_upstream_client(
                    md,
                    redirect_uri=redirect_uri,
                    client_name=f"prompt-to-mcp {display_name}"[:100],
                    scopes=wanted_scopes or md.scopes_supported,
                    provided_client_id=configured.client_id if configured else None,
                    provided_client_secret=configured.client_secret if configured else None,
                    http_client=http,
                )
            except dcr.DCRError as exc:
                if hint:
                    # Named providers reach here for one reason only: they do
                    # not do dynamic registration, so the operator has to create
                    # the client. Say that, rather than repeating the generic
                    # "no usable client acquisition path".
                    raise PipelineError(
                        "oauth",
                        f"{hint.title()} does not support dynamic client registration, so "
                        "an OAuth client has to be created once by hand. Create an OAuth "
                        "2.0 Client ID of type 'Web application', add the redirect URI "
                        f"{redirect_uri}, and resume with "
                        f'`{{"overrides": {{"oauth": {{"preset": "{hint}", '
                        '"client_id": "...", "client_secret": "..."}}}`. '
                        "If the API is reached with a static key instead, use "
                        "auth_kind=api_key.",
                    ) from exc
                raise PipelineError("oauth", str(exc)) from exc

        # Persist the real upstream secret out of band.
        upstream_secret_ref: str | None = None
        if upstream.client_secret:
            upstream_secret_ref = await self.d.secrets.create_or_update(
                secret_id_for(mcp_id, "upstream"), upstream.client_secret
            )

        # Mint the synthetic static pair Gemini Enterprise demands.
        client_id = f"p2m-{mcp_id}"
        client_secret = secrets.token_urlsafe(40)
        salt = secrets.token_hex(16)

        await self.d.secrets.create_or_update(secret_id_for(mcp_id, "downstream"), client_secret)

        proxy_client = ProxyClient(
            client_id=client_id,
            client_secret_hash=hash_secret(client_secret, salt),
            client_secret_salt=salt,
            mcp_id=mcp_id,
            display_name=display_name,
            issuer=md.issuer,
            authorization_endpoint=md.authorization_endpoint,
            token_endpoint=md.token_endpoint,
            revocation_endpoint=md.revocation_endpoint,
            upstream_client_id=upstream.client_id,
            upstream_client_secret_ref=upstream_secret_ref,
            upstream_token_endpoint_auth_method=upstream.token_endpoint_auth_method,
            dynamically_registered=upstream.dynamically_registered,
            scopes=wanted_scopes or md.scopes_supported,
        )
        await self.d.store.put_client(proxy_client)

        how = (
            "dynamic client registration (RFC 7591)"
            if upstream.dynamically_registered
            else ("public PKCE client" if upstream.is_public else "operator-supplied credentials")
        )
        await self._record_stage(
            record,
            "oauth",
            f"upstream AS {md.issuer} resolved via {how}; minted static client {client_id} "
            "for Gemini Enterprise",
            issuer=md.issuer,
            supports_dcr=md.supports_dcr,
            dynamically_registered=upstream.dynamically_registered,
            proxy_client_id=client_id,
        )
        return proxy_client, client_secret

    def _authorization_uri(self, client: ProxyClient) -> str:
        """Full authorization request URL, as the Authorization resource requires.

        Discovery Engine overwrites ``redirect_uri``, so it is omitted here.
        """
        from urllib.parse import urlencode

        params = {
            "client_id": client.client_id,
            "response_type": "code",
        }
        if client.scopes:
            params["scope"] = " ".join(client.scopes)
        return f"{self.d.settings.oauth_public_base_url}/oauth/authorize?{urlencode(params)}"

    async def _create_authorization(
        self,
        mcp_id: str,
        *,
        display_name: str,
        client_id: str,
        client_secret: str,
        authorization_uri: str,
        token_uri: str,
        scopes: list[str],
        record: McpRecord,
    ) -> str:
        authorization_id = f"p2m-{mcp_id}"[:63]
        result = await self.d.discovery.create_authorization(
            authorization_id,
            display_name=f"{display_name} (prompt-to-mcp)",
            client_id=client_id,
            client_secret=client_secret,
            authorization_uri=authorization_uri,
            token_uri=token_uri,
            scopes=scopes,
            pkce=True,
        )
        name = result.get("name", f"{self.d.discovery.parent}/authorizations/{authorization_id}")
        await self._record_stage(
            record,
            "authorize",
            f"created Discovery Engine authorization {name}",
            authorization=name,
            token_uri=token_uri,
        )
        return name

    # ------------------------------------------------------------------
    @staticmethod
    def _direct_oauth(req: CreateMcpRequest) -> UpstreamOAuth | None:
        """Decide whether the proxy can be skipped.

        The proxy exists to manufacture a static client_id/secret for upstreams
        that cannot provide one. If the operator already has static credentials
        and endpoints, interposing it buys nothing and adds a hop, so we point
        Gemini Enterprise directly at the upstream instead.
        """
        if req.use_proxy is ProxyMode.ALWAYS:
            return None
        oauth = req.oauth
        if oauth is None:
            return None
        if not oauth.is_complete:
            return None
        if not oauth.scopes and req.scopes:
            oauth = oauth.model_copy(update={"scopes": req.scopes})
        return oauth

    def _direct_authorization_uri(self, oauth: UpstreamOAuth) -> str:
        """Full upstream authorization URL, as the Authorization resource wants.

        Discovery Engine overwrites `redirect_uri`, so it is omitted. Offline
        access plus forced consent is what yields a refresh token, without which
        propagation dies at the first token expiry.
        """
        from urllib.parse import urlencode

        params = {
            "client_id": oauth.client_id or "",
            "response_type": "code",
            "access_type": "offline",
            "prompt": "consent",
        }
        if oauth.scopes:
            params["scope"] = " ".join(oauth.scopes)
        base = oauth.authorization_endpoint or ""
        sep = "&" if "?" in base else "?"
        return f"{base}{sep}{urlencode(params)}"
