"""Domain models.

The central artifact is the :class:`ToolManifest`. It is a *declarative*
description of the MCP server we are about to deploy: every tool maps 1:1 onto
an HTTP operation against the documented upstream API. Nothing in the manifest
is executable, which is what lets us generate servers from untrusted prompt
input without ever running model-authored code.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

SLUG_RE = re.compile(r"[^a-z0-9-]+")
TOOL_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def slugify(value: str, max_len: int = 40) -> str:
    s = SLUG_RE.sub("-", value.strip().lower()).strip("-")
    s = re.sub(r"-{2,}", "-", s)
    return (s[:max_len].rstrip("-")) or "mcp"


class ParamLocation(StrEnum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    BODY = "body"


class ToolParam(BaseModel):
    """One input parameter of a tool, and where it goes in the HTTP request."""

    name: str
    location: ParamLocation
    required: bool = False
    description: str = ""
    #: JSON Schema fragment describing the value.
    schema_: dict[str, Any] = Field(default_factory=lambda: {"type": "string"}, alias="schema")
    #: For BODY params: dotted path within the JSON body. Defaults to `name`.
    body_path: str | None = None

    model_config = {"populate_by_name": True}


class ToolEvidence(StrEnum):
    """How much is actually known about a tool's HTTP operation.

    The default is deliberately the weakest value: a producer that forgets to
    set this under-claims rather than over-claims, which is the direction an
    error should fall in.
    """

    #: Read out of a machine-readable specification. Exact.
    SPEC = "spec"
    #: A live read-only request confirmed the path exists (or exists but is
    #: gated); see :mod:`prompt_to_mcp.sdk_agent`.
    PROBED = "probed"
    #: Derived by the model from prose or from SDK documentation, and not
    #: confirmed against anything. Plausible, unproven.
    INFERRED = "inferred"


class ToolDef(BaseModel):
    """A single MCP tool backed by one HTTP operation."""

    name: str
    description: str = ""
    #: Provenance of the method/path below. See :class:`ToolEvidence`.
    evidence: ToolEvidence = ToolEvidence.INFERRED
    #: One line saying what produced the evidence, e.g. ``"HEAD /v1/pets -> 401"``.
    evidence_note: str = ""
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] = "GET"
    #: Path template relative to the manifest's base_url, e.g. `/v1/users/{id}`.
    path: str
    params: list[ToolParam] = Field(default_factory=list)
    #: Static headers merged into every call (never secrets).
    headers: dict[str, str] = Field(default_factory=dict)
    #: Hints surfaced to the model via MCP tool annotations.
    read_only: bool = True
    idempotent: bool = True
    destructive: bool = False

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if not TOOL_NAME_RE.match(v):
            raise ValueError(f"tool name {v!r} must match {TOOL_NAME_RE.pattern}")
        return v

    @model_validator(mode="after")
    def _path_params_declared(self) -> ToolDef:
        placeholders = set(re.findall(r"\{([^}]+)\}", self.path))
        declared = {p.name for p in self.params if p.location is ParamLocation.PATH}
        missing = placeholders - declared
        if missing:
            raise ValueError(
                f"tool {self.name!r}: path placeholders {sorted(missing)} "
                "have no declared path param"
            )
        return self

    def input_schema(self) -> dict[str, Any]:
        """JSON Schema advertised to MCP clients for this tool."""
        props: dict[str, Any] = {}
        required: list[str] = []
        for p in self.params:
            entry = dict(p.schema_)
            if p.description:
                entry.setdefault("description", p.description)
            props[p.name] = entry
            if p.required:
                required.append(p.name)
        schema: dict[str, Any] = {
            "type": "object",
            "properties": props,
            "additionalProperties": False,
        }
        if required:
            schema["required"] = required
        return schema


class AuthKind(StrEnum):
    #: Upstream needs no credentials.
    NONE = "none"
    #: Forward the end-user's OAuth access token (credential propagation).
    #: This is the mode that makes Gemini Enterprise auth resources meaningful.
    OAUTH_USER = "oauth_user"
    #: Cloud Run service-to-service via the MCP's own Google identity token.
    GOOGLE_ID_TOKEN = "google_id_token"
    #: A single long-lived key held by the operator, presented on every call.
    #:
    #: Every caller reaches the upstream as the same principal, so this grants
    #: no per-user isolation and is strictly weaker than ``oauth_user``. It is
    #: supported because it is what most APIs actually offer, and because the
    #: alternative -- users pasting keys into a description field where nothing
    #: could act on them -- is worse in every respect.
    API_KEY = "api_key"


#: Auth kinds whose generated server is safe to publish to ``allUsers``.
#:
#: The distinction is simply whether the deployed service holds a credential of
#: its own. ``oauth_user`` and ``google_id_token`` do not: the first forwards a
#: token the caller brought, the second mints one per call from its own
#: metadata-server identity. Anonymous transport access to either yields no
#: credential and no data.
#:
#: ``api_key`` and ``none`` are the opposite, and publishing them is what V-02
#: was. See :mod:`prompt_to_mcp.deployer.cloud_run` for the full account.
PUBLISHABLE_AUTH_KINDS: frozenset[AuthKind] = frozenset(
    {AuthKind.OAUTH_USER, AuthKind.GOOGLE_ID_TOKEN}
)


def holds_static_credential(kind: AuthKind) -> bool:
    """Whether a server deployed for ``kind`` can be spent by an anonymous caller."""
    return kind not in PUBLISHABLE_AUTH_KINDS


def public_exposure_refusal(mcp_id: str, kind: AuthKind, invokers: list[str]) -> str:
    """Why this run will not publish the service, and what to do instead.

    Written out in full rather than as a one-line error because the operator
    hitting it has usually just been told their deploy failed for a reason that
    sounds like a bug in the tool. It is not: it is the tool declining to build
    something whose failure mode is a drained API quota or a leaked dataset.
    """
    what = (
        "holds your upstream API key in Secret Manager and attaches it to every "
        "request it makes"
        if kind is AuthKind.API_KEY
        else "forwards every request to the upstream base URL with no credential "
        "check of any kind"
    )
    lines = [
        f"refusing to publish {mcp_id} to the public internet.",
        "",
        f"This MCP server uses auth_kind={kind.value!r}, which means it {what}. "
        "Granting allUsers would make it an open proxy: anyone who found its "
        "Cloud Run URL could use it, as you, without authenticating.",
        "",
        "It has NOT been deployed publicly. Three ways forward:",
        "",
        "  1. Use auth_kind='oauth_user' so each end user presents their own "
        "credential. This is the only option that gives per-user isolation, and "
        "such servers are still published normally because they hold nothing.",
        "",
        "  2. Let Gemini Enterprise reach it privately: set "
        "P2M_MCP_INVOKER_PRINCIPALS (or P2M_PROJECT_NUMBER, which derives the "
        "Discovery Engine service agent) so roles/run.invoker can be granted to "
        "a named caller instead of to everyone.",
        "",
        "  3. Accept the exposure deliberately: set "
        '`"allow_public_unauthenticated": true` on the request. Reasonable for a '
        "free read-only key or a throwaway sandbox; not otherwise.",
    ]
    if invokers:
        lines.append("")
        lines.append(f"Configured invoker principals: {', '.join(invokers)}")
    return "\n".join(lines)


class KeyLocation(StrEnum):
    HEADER = "header"
    QUERY = "query"


class UpstreamAuth(BaseModel):
    kind: AuthKind = AuthKind.NONE
    #: Header used to present the propagated token, or the API key.
    header: str = "Authorization"
    #: Prefix, e.g. "Bearer ". Empty for API keys, which are sent bare.
    scheme: str = "Bearer"
    #: OAuth scopes the upstream expects.
    scopes: list[str] = Field(default_factory=list)
    #: Discovered/declared authorization server issuer for the upstream API.
    issuer: str | None = None

    # -- api_key only ---------------------------------------------------
    #: Where an API key goes. Some APIs only accept `?key=`, others only a
    #: header; Google's Generative Language API accepts either.
    key_location: KeyLocation = KeyLocation.HEADER
    #: Query parameter name when :attr:`key_location` is ``query``.
    query_param: str | None = None
    #: Secret Manager *resource name* of the key -- never the key itself.
    #:
    #: The manifest is stored in a Cloud Run environment variable, persisted to
    #: Firestore and served verbatim in the downloadable package, so a literal
    #: key here would be exposed three ways at once. The runtime resolves this
    #: reference at boot from an environment variable Cloud Run populates.
    secret_ref: str | None = None

    @model_validator(mode="after")
    def _api_key_is_presentable(self) -> UpstreamAuth:
        if self.kind is AuthKind.API_KEY:
            if self.key_location is KeyLocation.QUERY and not self.query_param:
                raise ValueError("api_key auth with key_location='query' needs a query_param")
            if self.key_location is KeyLocation.HEADER and not self.header:
                raise ValueError("api_key auth with key_location='header' needs a header name")
        return self


def build_upstream_auth(req: CreateMcpRequest, base_url: str) -> UpstreamAuth:
    """The manifest's auth block for ``req``, resolved against ``base_url``.

    Placement matters only for ``api_key`` and cannot be decided before the
    base URL is known, which is why this runs at ingest rather than resolve.
    The key itself is never set here: :class:`UpstreamAuth` carries a Secret
    Manager reference, filled in at deploy once the secret exists.
    """
    if req.auth_kind is not AuthKind.API_KEY:
        return UpstreamAuth(kind=req.auth_kind, scopes=req.scopes)

    if req.api_key_query_param:
        return UpstreamAuth(
            kind=AuthKind.API_KEY,
            key_location=KeyLocation.QUERY,
            query_param=req.api_key_query_param,
            scheme="",
            scopes=req.scopes,
        )

    header, scheme = default_api_key_placement(base_url)
    if req.api_key_header:
        header = req.api_key_header
        # An explicitly named header is presented bare unless it is the
        # standard one, where a bare key would be a malformed credential.
        scheme = "Bearer" if header.lower() == "authorization" else ""
    return UpstreamAuth(
        kind=AuthKind.API_KEY,
        key_location=KeyLocation.HEADER,
        header=header,
        scheme=scheme,
        scopes=req.scopes,
    )


class ToolManifest(BaseModel):
    """Everything the generic MCP runtime needs to serve an API."""

    name: str
    display_name: str
    description: str = ""
    base_url: str
    auth: UpstreamAuth = Field(default_factory=UpstreamAuth)
    tools: list[ToolDef] = Field(default_factory=list)
    #: Free-form provenance so a generated server can be traced back.
    source: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def _https(cls, v: str) -> str:
        v = v.rstrip("/")
        if not v.startswith("https://"):
            raise ValueError(f"base_url must be https, got {v!r}")
        return v

    @model_validator(mode="after")
    def _unique_tool_names(self) -> ToolManifest:
        seen: set[str] = set()
        for t in self.tools:
            if t.name in seen:
                raise ValueError(f"duplicate tool name {t.name!r}")
            seen.add(t.name)
        return self

    def to_mcp_tool_spec(self) -> dict[str, Any]:
        """Agent Registry ``McpServerSpec.content`` for ``type: TOOL_SPEC``.

        Verified shape: the payload is the same as an MCP ``tools/list``
        response, i.e. ``{"tools": [{name, description, inputSchema, ...}]}``.
        """
        return {
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema(),
                    "annotations": {
                        "title": t.name.replace("_", " ").title(),
                        "readOnlyHint": t.read_only,
                        "idempotentHint": t.idempotent,
                        "destructiveHint": t.destructive,
                        "openWorldHint": True,
                    },
                }
                for t in self.tools
            ]
        }


# --------------------------------------------------------------------------
# Control plane API
# --------------------------------------------------------------------------


#: The doc source fields, in the order they are probed.
DOC_SOURCE_FIELDS = ("openapi_url", "openapi_inline", "text", "url", "sdk")

#: Upper bound on how many documents one request may merge. Each source can be
#: an 8 MB fetch and a model call, so this is a cost bound rather than a
#: statement about what is reasonable to merge.
MAX_DOC_SOURCES = 10


class DocSource(BaseModel):
    """One place API documentation comes from.

    A single source carries exactly one kind of document. Several sources
    describing the *same* API can be merged into one manifest; see
    ``CreateMcpRequest.docs``.
    """

    #: Direct URL to an OpenAPI/Swagger document (json or yaml).
    openapi_url: str | None = None
    #: Inline OpenAPI document.
    openapi_inline: str | None = None
    #: Freeform documentation text (markdown, HTML, prose). Synthesised by Gemini.
    text: str | None = None
    #: URL to fetch freeform docs from.
    url: str | None = None
    #: A client library to work backwards from, as a docs URL, a git repository
    #: URL, or an ``ecosystem:name`` package reference such as ``pypi:stripe``.
    #:
    #: Handled by the ingest agent rather than by a parser, because an SDK
    #: describes method calls and a tool needs an HTTP method and path. That
    #: mapping is rarely written down, so it has to be looked for -- ideally by
    #: finding the OpenAPI document the SDK was generated from, which collapses
    #: the problem onto the deterministic parser.
    sdk: str | None = None

    @model_validator(mode="after")
    def _one_of(self) -> DocSource:
        provided = [f for f in DOC_SOURCE_FIELDS if getattr(self, f) is not None]
        if len(provided) != 1:
            raise ValueError(f"exactly one doc source required, got {provided or 'none'}")
        return self

    @property
    def kind(self) -> str:
        """Which of :data:`DOC_SOURCE_FIELDS` this source carries."""
        for field in DOC_SOURCE_FIELDS:
            if getattr(self, field) is not None:
                return field
        raise AssertionError("unreachable: _one_of guarantees a field is set")

    @property
    def value(self) -> str:
        return str(getattr(self, self.kind))

    @property
    def is_openapi(self) -> bool:
        return self.kind in ("openapi_url", "openapi_inline")

    def label(self) -> str:
        """Short identifier for error messages.

        Errors from a merge have to say *which* document caused them, and a URL
        is far more use than an index. Inline bodies have no name, so they fall
        back to their kind and size.
        """
        if self.kind in ("openapi_url", "url", "sdk"):
            return f"{self.kind}={self.value}"
        return f"{self.kind} ({len(self.value)} chars)"


#: Authorization-server presets for providers that do not implement the MCP
#: authorization discovery spec (RFC 9728 / RFC 8414) and instead document
#: their OAuth configuration out of band. Google is the notable case: its
#: hosted MCP servers answer `tools/list` unauthenticated, emit no
#: `WWW-Authenticate` challenge, and expect a static client ID and secret that
#: the operator creates in the Cloud console.
OAUTH_PRESETS: dict[str, dict[str, Any]] = {
    "google": {
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
    },
}


def preset_for_url(url: str) -> str | None:
    """Return a preset key for a well-known host, if any."""
    host = urlparse(url).hostname or ""
    if host.endswith(".googleapis.com") or host.endswith(".google.com"):
        return "google"
    return None


def default_api_key_placement(base_url: str) -> tuple[str, str]:
    """``(header, scheme)`` an API key should use for ``base_url``.

    ``Authorization: Bearer`` is the safe default because it is what most APIs
    accept, but it is wrong for Google: sending a raw API key as a bearer token
    to a ``*.googleapis.com`` host yields a 401 that reads like an invalid key
    rather than a misplaced one. Google wants a bare ``x-goog-api-key``.
    """
    host = urlparse(base_url).hostname or ""
    if host.endswith(".googleapis.com"):
        return "x-goog-api-key", ""
    return "Authorization", "Bearer"


class UpstreamOAuth(BaseModel):
    """Explicit OAuth configuration, bypassing automatic discovery.

    Required for providers that do not advertise authorization-server metadata.
    When ``client_id`` and ``client_secret`` are both present the credentials
    are already static, so the OAuth proxy is unnecessary and Gemini Enterprise
    can be pointed straight at the upstream endpoints.
    """

    #: Fill the endpoints from a named preset, e.g. "google".
    preset: str | None = None
    issuer: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _apply_preset(self) -> UpstreamOAuth:
        if self.preset:
            values = OAUTH_PRESETS.get(self.preset)
            if values is None:
                raise ValueError(
                    f"unknown oauth preset {self.preset!r}; known: {sorted(OAUTH_PRESETS)}"
                )
            for key, value in values.items():
                if getattr(self, key) is None:
                    setattr(self, key, value)
        return self

    @property
    def is_complete(self) -> bool:
        """True when this alone can drive an authorization code flow."""
        return bool(
            self.authorization_endpoint
            and self.token_endpoint
            and self.client_id
            and self.client_secret
        )

    @property
    def has_endpoints(self) -> bool:
        return bool(self.authorization_endpoint and self.token_endpoint)


class ProxyMode(StrEnum):
    #: Use the proxy only when the upstream cannot supply static credentials.
    AUTO = "auto"
    #: Always route through the proxy.
    ALWAYS = "always"
    #: Never use the proxy; requires complete static OAuth config.
    NEVER = "never"


class CreateMcpRequest(BaseModel):
    """The user prompt: what to build, and the docs to build it from.

    Two modes:

    * **generate** (default) -- wrap a documented HTTP API in a new MCP server.
      Requires ``docs``.
    * **register existing** -- ``mcp_url`` points at an MCP server that already
      runs somewhere (Google's hosted Drive MCP, a vendor's SaaS MCP, an
      internal deployment). Nothing is generated or deployed; the tool catalog
      is read from the server itself via ``tools/list``.
    """

    #: Natural-language description of the desired MCP server.
    description: str = Field(..., min_length=8, max_length=8000)

    #: Documentation to build the tools from. Accepts either a single source
    #: (``{"openapi_url": ...}``) or several (``[{...}, {...}]``); the single
    #: form is normalised to a one-element list, so the object shape that
    #: predates merging keeps working unchanged.
    #:
    #: Multiple sources must describe the **same** API: every tool resolves
    #: against one manifest-level ``base_url``, so the merge rejects sources
    #: that disagree about it rather than silently rebasing their paths.
    docs: list[DocSource] | None = None

    @field_validator("docs", mode="before")
    @classmethod
    def _accept_single_source(cls, v: Any) -> Any:
        if v is None or isinstance(v, list):
            return v
        return [v]

    #: Register an already-running MCP server instead of generating one.
    mcp_url: str | None = None

    #: Explicit upstream OAuth configuration; bypasses discovery.
    oauth: UpstreamOAuth | None = None

    #: Whether to interpose the OAuth proxy.
    use_proxy: ProxyMode = ProxyMode.AUTO
    #: Optional explicit name; derived from description otherwise.
    name: str | None = None
    #: Override the API base URL if the docs don't declare a usable server.
    base_url: str | None = None

    #: Optional bearer token the ingest agent may present when probing an
    #: ``sdk`` source's API to check an inferred endpoint exists.
    #:
    #: Entirely optional: unauthenticated probing already distinguishes a real
    #: path (401/403) from an invented one (404), which is the question that
    #: matters. A token buys real response bodies, and costs sending your
    #: credential to the upstream API from the control plane during ingest.
    #: It is fingerprinted in the record by the ``_token`` rule in
    #: :mod:`prompt_to_mcp.redact` and never persisted in usable form.
    probe_token: str | None = None
    #: Restrict generation to these operations (by operationId or path).
    include_operations: list[str] = Field(default_factory=list)

    auth_kind: AuthKind = AuthKind.OAUTH_USER
    scopes: list[str] = Field(default_factory=list)

    #: The upstream API key, when ``auth_kind`` is ``api_key``.
    #:
    #: Held only long enough to write it to Secret Manager during `deploy`;
    #: the manifest and the record carry a reference, never this value. The
    #: field is named ``api_key`` deliberately -- :mod:`prompt_to_mcp.redact`
    #: fingerprints it by name, so it cannot reach Firestore or the UI intact.
    api_key: str | None = None
    #: Where to put the key. Defaults are filled in per provider during
    #: resolution (Google wants ``x-goog-api-key``, most others a bearer).
    api_key_header: str | None = None
    api_key_query_param: str | None = None

    #: Publish this MCP to the public internet even though it holds a static
    #: credential. Anyone who finds the URL can spend that credential.
    #:
    #: Only consulted for ``auth_kind`` ``api_key`` and ``none``; the other two
    #: kinds are published anyway because they hold nothing (see
    #: :mod:`prompt_to_mcp.deployer.cloud_run`). Exists so that an operator who
    #: has genuinely decided the exposure is acceptable -- a free read-only key,
    #: a throwaway sandbox -- is not blocked, and so that the decision is
    #: recorded on the request rather than inferred from a default.
    allow_public_unauthenticated: bool = False

    #: Connect the finished MCP to this Gemini Enterprise engine (app) id.
    #: When omitted we still create the collection/datastore but bind nothing.
    gemini_enterprise_engine_id: str | None = None

    #: Stop after N stages; useful for dry runs. See pipeline.Stage.
    stop_after: str | None = None

    @model_validator(mode="after")
    def _mode_is_coherent(self) -> CreateMcpRequest:
        if not self.mcp_url and not self.docs:
            raise ValueError(
                "provide either `docs` (to generate an MCP server from API "
                "documentation) or `mcp_url` (to register an MCP server that "
                "already exists)"
            )
        if self.docs and len(self.docs) > MAX_DOC_SOURCES:
            raise ValueError(
                f"at most {MAX_DOC_SOURCES} doc sources may be merged, got {len(self.docs)}"
            )
        if self.mcp_url and not self.mcp_url.startswith("https://"):
            raise ValueError(f"mcp_url must be https, got {self.mcp_url!r}")
        if self.use_proxy is ProxyMode.NEVER and not (self.oauth and self.oauth.is_complete):
            if self.auth_kind is AuthKind.OAUTH_USER:
                raise ValueError(
                    "use_proxy='never' requires a complete `oauth` block "
                    "(authorization_endpoint, token_endpoint, client_id, client_secret)"
                )
        # Caught here rather than at `deploy`, four stages in. A run that
        # cannot possibly authenticate should never create a Cloud Run service.
        if self.auth_kind is AuthKind.API_KEY and not self.api_key:
            raise ValueError(
                "auth_kind='api_key' requires `api_key`. Supply the upstream key, "
                "or use auth_kind='oauth_user' for per-user credentials, or "
                "auth_kind='none' if the API needs no authentication."
            )
        if self.api_key and self.auth_kind is not AuthKind.API_KEY:
            raise ValueError(
                f"`api_key` was supplied but auth_kind is {self.auth_kind.value!r}; "
                "the key would be ignored. Set auth_kind='api_key' to use it."
            )
        return self

    @property
    def registers_existing(self) -> bool:
        return bool(self.mcp_url)


class ResumeMcpRequest(BaseModel):
    """Anything a resumed run needs that the persisted record cannot supply.

    Nearly always empty. Secrets are fingerprinted on the record and the doc
    source is truncated, so a resume that has to re-run one of the early stages
    may need those values again; the stages that already succeeded do not.
    """

    #: Partial :class:`CreateMcpRequest` fields, deep-merged over the original.
    overrides: dict[str, Any] = Field(default_factory=dict)


class StageResult(BaseModel):
    stage: str
    ok: bool
    detail: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class McpRecord(BaseModel):
    """Persisted result of one end-to-end provisioning run."""

    id: str
    display_name: str
    description: str = ""
    state: str = "PENDING"
    #: The :class:`CreateMcpRequest` exactly as submitted, secrets fingerprinted.
    #: Kept verbatim (including the doc source) so a run can be reproduced or
    #: diffed against another without reconstructing the inputs by hand.
    request: dict[str, Any] = Field(default_factory=dict)
    #: Effective configuration per stage, secrets fingerprinted. Values are the
    #: real request bodies handed to Google APIs, which is what makes an
    #: INVALID_ARGUMENT from Discovery Engine debuggable after the fact.
    #: Keyed by stage name; see :data:`prompt_to_mcp.pipeline.STAGES`.
    config: dict[str, Any] = Field(default_factory=dict)
    manifest: ToolManifest | None = None
    cloud_run_url: str | None = None
    image: str | None = None
    #: projects/*/locations/*/services/*
    registry_service: str | None = None
    #: projects/*/locations/*/mcpServers/*
    registry_resource: str | None = None
    #: projects/*/locations/*/authorizations/*
    authorization: str | None = None
    #: projects/*/locations/*/collections/*
    collection: str | None = None
    datastore: str | None = None
    #: Synthetic OAuth client the proxy issued to Gemini Enterprise.
    proxy_client_id: str | None = None
    #: Secret Manager version holding the upstream API key, for ``api_key``
    #: runs. A resource name, never the key. Recorded so teardown can remove it
    #: -- a key left behind in Secret Manager is a live credential nobody owns.
    api_key_secret: str | None = None
    stages: list[StageResult] = Field(default_factory=list)
    #: Preflight findings, so a failed run can render the fix in the UI.
    requirements: list[dict[str, Any]] = Field(default_factory=list)
    #: The stage that ended the run, when it ended badly. Set alongside
    #: ``error``; kept separate because the last entry in ``stages`` is not
    #: always the culprit once a run can be resumed and re-fail elsewhere.
    failed_stage: str | None = None
    error: str | None = None
    #: Explanation of ``error`` in terms of what to do about it. Populated by
    #: :mod:`prompt_to_mcp.diagnose` -- cheaply and deterministically when the
    #: run fails, and enriched by a model on request. Cached here because the
    #: model call costs money and the answer cannot change for a finished run.
    diagnosis: dict[str, Any] | None = None

    # -- derived --------------------------------------------------------
    @property
    def completed_stages(self) -> list[str]:
        """Stages that produced their output, in order, without duplicates.

        A resumed run appends to ``stages`` rather than replacing it, so the
        same stage can appear more than once.
        """
        seen: dict[str, None] = {}
        for entry in self.stages:
            if entry.ok:
                seen[entry.stage] = None
        return list(seen)

    @property
    def mcp_endpoint(self) -> str | None:
        """Where the MCP server actually answers.

        For a generated server that is the Cloud Run service root plus
        ``/mcp``. For a registered existing one there is no Cloud Run service
        at all, so fall back to the URL the `register` stage actually used --
        which is also the only correct answer when `preflight` auto-switched
        the run into register-existing mode, since the submitted request never
        named a URL.
        """
        if self.cloud_run_url:
            return f"{self.cloud_run_url.rstrip('/')}/mcp"
        registered = (self.config.get("register") or {}).get("mcp_url")
        return registered or (self.request.get("mcp_url") if self.request else None)

    @property
    def usable(self) -> bool:
        """Whether a working MCP server exists regardless of the run's state.

        The last two stages bind an already-deployed, already-registered server
        to Gemini Enterprise. Failing there leaves something the user can still
        use, and telling them the whole run FAILED would be untrue.
        """
        return bool(self.registry_service and self.mcp_endpoint)
