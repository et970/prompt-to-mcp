"""Turn one free-form input into a complete request, and ask only what's left.

The control plane already knows how to work almost everything out for itself:
whether a URL is an MCP server or a documentation page, which authorization
server a provider uses, what scopes it wants, which operations to expose. But
until now the *UI* asked first and inferred second -- eighteen form fields, most
of them re-stating something the pipeline would have derived anyway, and four of
them (the documentation-source tabs) existing purely to answer a question the
parser answers better.

This module inverts that. :func:`resolve` takes a single blob of text -- a URL,
a pasted spec, a pasted page -- plus a description of intent, and returns:

* a fully-populated :class:`~.models.CreateMcpRequest`,
* :class:`Finding` entries explaining every inference it made and why,
* :class:`Question` entries for the *residual* unknowns only.

The questions are the point. A static form must show every field that might
ever be needed; a resolved plan shows the two or three that actually are. Where
nothing is left to ask, ``ready`` is true and the user can just press Create.

Resolution is idempotent and re-entrant: answers come back in ``overrides`` and
the caller resolves again, which is how the UI converges. Nothing here creates
or mutates cloud resources, so it is safe to call on every edit.

Inference is never silent. Every derived value produces a Finding naming the
evidence, and everything remains overridable, because an inference the user can
neither see nor countermand is worse than the question it replaced.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel
from pydantic import Field as PydanticField

from .config import Settings
from .ingest import openapi_loader
from .ingest.detect import detect_mcp_server_url
from .ingest.fetcher import FetchError, fetch_document
from .ingest.mcp_probe import McpProbeResult
from .ingest.mcp_probe import probe as probe_mcp
from .models import AuthKind, CreateMcpRequest, DocSource, UpstreamOAuth
from .oauth import metadata as md_mod
from .redact import find_credentials, fingerprint
from .requirements import (
    Action,
    Preflight,
    ReqStatus,
    apply_provider_defaults,
    evaluate,
    provider_for,
)

log = logging.getLogger(__name__)

#: Mirrors the client-side guess that used to live in app.js. A raw spec is
#: almost always a .json/.yaml file or a path that says so; anything else is
#: probably a rendered page. Kept server-side now so there is one copy.
_SPEC_URL_HINTS = (".json", ".yaml", ".yml", "openapi", "swagger", "api-docs", "apidocs", "spec")

#: Path or host fragments that mark a URL as an MCP endpoint rather than docs.
_MCP_URL_HINTS = ("/mcp", "/mcp/", "mcp.", "-mcp", "mcp-")

#: Minimum length enforced by CreateMcpRequest.description.
_MIN_DESCRIPTION = 8

#: Resolution runs interactively while the user waits, so it uses tighter
#: deadlines than the pipeline does. The pipeline can afford mcp_probe's 30s
#: and a full discovery walk; a form that appears to hang for 45 seconds is
#: indistinguishable from one that is broken. A server too slow to answer in
#: this window simply stays un-inferred, and the user is asked instead.
_INTERACTIVE_TIMEOUT = httpx.Timeout(8.0, connect=4.0)


class InputKind(StrEnum):
    """What a single blob of user input turned out to be."""

    EMPTY = "empty"
    MCP_ENDPOINT = "mcp_endpoint"
    OPENAPI_URL = "openapi_url"
    DOCS_URL = "docs_url"
    OPENAPI_TEXT = "openapi_text"
    DOCS_TEXT = "docs_text"


@dataclass(slots=True)
class Classification:
    """The offline guess, before anything is fetched."""

    kind: InputKind
    #: For MCP_ENDPOINT found inside pasted text, the extracted endpoint.
    url: str | None = None
    #: Why we think so, in words fit for the UI.
    reason: str = ""


class FieldKind(StrEnum):
    TEXT = "text"
    PASSWORD = "password"
    SELECT = "select"


class Option(BaseModel):
    value: str
    label: str


class Field(BaseModel):
    """One input the user still has to supply."""

    #: Key to send back in ``overrides``.
    name: str
    label: str
    kind: FieldKind = FieldKind.TEXT
    options: list[Option] = PydanticField(default_factory=list)
    placeholder: str = ""
    value: str | None = None


class Question(BaseModel):
    """Something resolution could not settle on its own."""

    id: str
    title: str
    detail: str = ""
    #: False for advisory questions the user may ignore (e.g. no GE app).
    blocking: bool = True
    fields: list[Field] = PydanticField(default_factory=list)
    #: Console links, CLI commands and values to paste, from Requirement.
    actions: list[Action] = PydanticField(default_factory=list)


class Finding(BaseModel):
    """Something resolution worked out, and the evidence for it."""

    id: str
    title: str
    detail: str = ""
    #: "certain" when observed directly, "likely" when heuristic.
    confidence: str = "certain"


class ResolveRequest(BaseModel):
    """One free-form input plus whatever the user has answered so far."""

    #: A URL, an OpenAPI document, or documentation text. Anything.
    input: str = ""
    description: str = ""
    #: Answers to previously-returned questions, keyed by Field.name.
    overrides: dict[str, Any] = PydanticField(default_factory=dict)


class ResolvedPlan(BaseModel):
    ready: bool
    summary: str
    kind: InputKind
    request: CreateMcpRequest | None = None
    findings: list[Finding] = PydanticField(default_factory=list)
    questions: list[Question] = PydanticField(default_factory=list)
    #: Tools we already know about, for preview without a second round trip.
    tools: list[dict[str, Any]] = PydanticField(default_factory=list)
    #: Present when the input could not be turned into a request at all.
    error: str | None = None


# ---------------------------------------------------------------------------
# Offline classification
# ---------------------------------------------------------------------------


def _is_url(text: str) -> bool:
    """True for a bare URL, not prose that happens to contain one."""
    stripped = text.strip()
    if len(stripped.split()) != 1 or "\n" in stripped:
        return False
    return stripped.startswith("http://") or stripped.startswith("https://")


def _url_looks_like_mcp(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    if any(h in path for h in ("/mcp", "/mcp/")):
        return True
    return "mcp" in host.split(".")[0] or host.startswith("mcp") or "-mcp" in host


def _url_looks_like_spec(url: str) -> bool:
    lowered = url.lower()
    return any(hint in lowered for hint in _SPEC_URL_HINTS)


def classify_input(text: str) -> Classification:
    """Guess what the user pasted, without touching the network.

    Deliberately offline and pure so it can be unit-tested exhaustively and so
    the UI could run the same logic locally if it ever wanted to. :func:`resolve`
    confirms the guess by probing, and will overrule it.

    OpenAPI wins over MCP detection, matching the pipeline's existing rule that
    an explicit spec is never re-interpreted as MCP client configuration
    (see ``pipeline._detect_existing_mcp``).
    """
    stripped = (text or "").strip()
    if not stripped:
        return Classification(kind=InputKind.EMPTY, reason="nothing supplied")

    if _is_url(stripped):
        if _url_looks_like_mcp(stripped):
            return Classification(
                kind=InputKind.MCP_ENDPOINT,
                url=stripped,
                reason="the URL looks like an MCP endpoint",
            )
        if _url_looks_like_spec(stripped):
            return Classification(
                kind=InputKind.OPENAPI_URL,
                url=stripped,
                reason="the URL points at a specification file",
            )
        return Classification(
            kind=InputKind.DOCS_URL, url=stripped, reason="treated as a documentation page"
        )

    # Pasted content. A parseable spec is unambiguous, so check it first.
    try:
        parsed = openapi_loader.parse_document(stripped)
        if isinstance(parsed, dict) and ("openapi" in parsed or "swagger" in parsed):
            return Classification(
                kind=InputKind.OPENAPI_TEXT, reason="the text parses as an OpenAPI document"
            )
    except openapi_loader.OpenAPIError:
        pass

    detected = detect_mcp_server_url(stripped)
    if detected:
        return Classification(
            kind=InputKind.MCP_ENDPOINT, url=detected.url, reason=detected.reason
        )

    return Classification(kind=InputKind.DOCS_TEXT, reason="treated as freeform documentation")


# ---------------------------------------------------------------------------
# Description derivation
# ---------------------------------------------------------------------------


def _split_scopes(value: Any) -> list[str]:
    """Accept scopes as a list or as the space-separated string the UI sends."""
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    return [s for s in str(value).split() if s]


def _describe_from_spec(raw: str) -> str | None:
    """Build a description from an OpenAPI ``info`` block."""
    try:
        doc = openapi_loader.parse_document(raw)
    except openapi_loader.OpenAPIError:
        return None
    info = doc.get("info") if isinstance(doc, dict) else None
    if not isinstance(info, dict):
        return None
    title = (info.get("title") or "").strip()
    summary = (info.get("description") or info.get("summary") or "").strip()
    text = ". ".join(p for p in (title, summary) if p)
    return text[:8000] or None


def _describe_from_probe(result: McpProbeResult) -> str | None:
    name = (result.server_name or "").strip()
    names = result.tool_names[:8]
    if not name and not names:
        return None
    parts = [f"{name} MCP server" if name else "MCP server"]
    if names:
        parts.append("tools: " + ", ".join(names))
    return ". ".join(parts)[:8000]


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _auth_from_spec(raw: str) -> AuthKind | None:
    """Infer upstream auth from an OpenAPI ``securitySchemes`` block."""
    try:
        doc = openapi_loader.parse_document(raw)
    except openapi_loader.OpenAPIError:
        return None
    if not isinstance(doc, dict):
        return None
    schemes = (doc.get("components") or {}).get("securitySchemes") or {}
    if not isinstance(schemes, dict) or not schemes:
        # Swagger 2.0 spelling.
        schemes = doc.get("securityDefinitions") or {}
    if not isinstance(schemes, dict) or not schemes:
        return AuthKind.NONE
    kinds = {
        (s.get("type") or "").lower() for s in schemes.values() if isinstance(s, dict)
    }
    if "oauth2" in kinds or "openidconnect" in kinds:
        return AuthKind.OAUTH_USER
    return AuthKind.NONE


def _questions_from_preflight(pf: Preflight, *, overrides: dict[str, Any]) -> list[Question]:
    """Convert residual requirements into answerable questions.

    Only requirements the app genuinely cannot settle become questions. An
    ``AUTO`` requirement is something the run fixes itself, so surfacing it as a
    question would recreate exactly the noise this module exists to remove; it
    becomes a Finding instead.
    """
    questions: list[Question] = []
    for req in pf.requirements:
        if req.status is not ReqStatus.MANUAL:
            continue
        fields: list[Field] = []
        if req.id == "oauth_client":
            fields = [
                Field(
                    name="client_id",
                    label="Client ID",
                    placeholder="xxxx.apps.googleusercontent.com",
                    value=overrides.get("client_id"),
                ),
                Field(
                    name="client_secret",
                    label="Client secret",
                    kind=FieldKind.PASSWORD,
                    placeholder="GOCSPX-…",
                    value=overrides.get("client_secret"),
                ),
            ]
        questions.append(
            Question(
                id=req.id,
                title=req.title,
                detail=req.detail,
                blocking=req.blocking,
                fields=fields,
                actions=req.actions,
            )
        )
    return questions


async def _engine_question(
    engines: Any, *, overrides: dict[str, Any], findings: list[Finding]
) -> Question | None:
    """Offer the Gemini Enterprise apps that exist instead of asking for an ID.

    Previously the user had to open the console, find an app and copy its ID
    into a text box. The IDs are listable, so list them: with exactly one app
    there is nothing to ask at all.
    """
    if engines is None:
        return None
    try:
        found = await engines.list_engines()
    except Exception as exc:  # noqa: BLE001 - advisory only, never fatal
        log.debug("engine listing failed: %s", exc)
        return None
    if not found:
        return None

    options = [
        Option(value=e["id"], label=e.get("display_name") or e["id"]) for e in found
    ]
    if len(options) == 1 and not overrides.get("engine_id"):
        findings.append(
            Finding(
                id="engine",
                title="Gemini Enterprise app",
                detail=f"Only one app exists ({options[0].label}); it will be used.",
            )
        )
        overrides["engine_id"] = options[0].value
        return None

    return Question(
        id="engine",
        title="Gemini Enterprise app",
        detail="Which app should this MCP be attached to?",
        blocking=False,
        fields=[
            Field(
                name="engine_id",
                label="App",
                kind=FieldKind.SELECT,
                options=options,
                value=overrides.get("engine_id"),
            )
        ],
    )


#: A line this short, once the credential is removed, was only ever there to
#: introduce it ("here is the api key XXX"). Longer lines carry real intent and
#: are kept minus the value.
_CREDENTIAL_LINE_REMAINDER = 48

_CREDENTIAL_LABEL_RE = re.compile(
    r"(?i)\b(api[\s_\-]?key|apikey|access[\s_\-]?token|auth[\s_\-]?token|token|secret|password)\b"
)


def _strip_credential(text: str, key: str) -> str:
    """Remove ``key`` from ``text``, and the phrase that introduced it.

    Leaving "here us the api key" behind would be technically safe and read
    like a bug, so a line whose only purpose was to carry the credential goes
    with it.
    """
    if not text or key not in text:
        return text
    kept: list[str] = []
    for line in text.splitlines():
        if key not in line:
            kept.append(line)
            continue
        remainder = line.replace(key, "").strip(" \t,.;:=\"'`")
        if _CREDENTIAL_LABEL_RE.search(remainder) and len(remainder) <= _CREDENTIAL_LINE_REMAINDER:
            continue
        kept.append(remainder)
    return "\n".join(line for line in kept if line.strip()).strip()


def _lift_pasted_credential(
    payload: ResolveRequest, overrides: dict[str, Any], findings: list[Finding]
) -> tuple[ResolveRequest, str | None]:
    """Move a credential pasted into free text into the ``api_key`` override.

    Users paste keys into the description because it is the only box on the
    screen. Until now that was doubly wrong: no auth mode could consume one, so
    the run was doomed to fail at `oauth` however the key looked; and the value
    was persisted verbatim to Firestore, echoed back to the browser and shipped
    inside the downloadable package.

    Lifting it here fixes both. The key becomes ``api_key``, which
    :mod:`prompt_to_mcp.redact` fingerprints by name and the pipeline writes to
    Secret Manager, and the free text it came from no longer contains it -- which
    matters because that text is also sent to Gemini during ingest.

    Runs before classification on purpose: nothing should read the raw input
    while it still holds a credential.

    The resolved plan does still carry the key, in ``request.api_key`` and
    nowhere else, because the browser posts that request back verbatim -- that
    is what makes "Create runs the plan you were shown" true. It is the same
    value the same browser just sent over the same origin, so the round trip
    adds no exposure, whereas the *finding* describing it deliberately shows
    only a fingerprint, because findings are rendered and logged.
    """
    if overrides.get("api_key"):
        return payload, str(overrides["api_key"])

    found = find_credentials(f"{payload.input}\n{payload.description}")
    if not found:
        return payload, None

    key = found[0]
    overrides["api_key"] = key
    # Only default the auth mode; an explicit choice from the advanced panel
    # still wins, so a user who wants OAuth despite pasting a key gets it.
    overrides.setdefault("auth_kind", AuthKind.API_KEY.value)
    findings.append(
        Finding(
            id="api_key",
            title="API key detected in your input",
            detail=(
                f"{fingerprint(key)} was removed from the text and will be stored in "
                "Secret Manager, not in the record. The server will present it to the "
                "upstream API on every call. Change 'Authentication' under Advanced if "
                "you wanted per-user OAuth instead."
            ),
        )
    )
    return (
        payload.model_copy(
            update={
                "input": _strip_credential(payload.input, key),
                "description": _strip_credential(payload.description, key),
            }
        ),
        key,
    )


async def resolve(
    payload: ResolveRequest,
    settings: Settings,
    *,
    service_usage: Any | None = None,
    registry: Any | None = None,
    engines: Any | None = None,
    client: httpx.AsyncClient | None = None,
) -> ResolvedPlan:
    """Resolve one input into a request plus the questions that remain.

    Owns an HTTP client with interactive deadlines unless one is supplied, so
    every probe on this path shares the same short budget.
    """
    owns = client is None
    client = client or httpx.AsyncClient(timeout=_INTERACTIVE_TIMEOUT, follow_redirects=True)
    try:
        return await _resolve(
            payload,
            settings,
            service_usage=service_usage,
            registry=registry,
            engines=engines,
            client=client,
        )
    finally:
        if owns:
            await client.aclose()


async def _resolve(
    payload: ResolveRequest,
    settings: Settings,
    *,
    service_usage: Any | None,
    registry: Any | None,
    engines: Any | None,
    client: httpx.AsyncClient,
) -> ResolvedPlan:
    overrides = dict(payload.overrides or {})
    findings: list[Finding] = []
    questions: list[Question] = []
    allowed = settings.allowed_upstream_hosts or None

    # Before classification, fetching, or anything else that reads the input:
    # a pasted credential must not survive into a doc source or a record.
    payload, api_key = _lift_pasted_credential(payload, overrides, findings)

    classification = classify_input(payload.input)
    if classification.kind is InputKind.EMPTY:
        return ResolvedPlan(
            ready=False,
            summary="Paste a URL, an OpenAPI document, or API documentation to begin.",
            kind=InputKind.EMPTY,
        )

    kind = classification.kind
    url = classification.url
    raw_text = payload.input.strip()
    fetched: str | None = None
    probe_result: McpProbeResult | None = None
    tools: list[dict[str, Any]] = []

    # -- confirm the guess against reality -------------------------------
    if kind in (InputKind.MCP_ENDPOINT, InputKind.DOCS_URL) and url:
        # A docs URL that answers tools/list is an MCP server, whatever it is
        # called. Probing is cheap and settles the mode question outright.
        probe_result = await probe_mcp(url, allowed_hosts=allowed, client=client)
        is_mcp = probe_result.reachable and (
            bool(probe_result.tools) or probe_result.requires_auth
        )
        if is_mcp:
            if kind is not InputKind.MCP_ENDPOINT:
                findings.append(
                    Finding(
                        id="mode",
                        title="Existing MCP server detected",
                        detail=(
                            f"{url} answered an MCP tools/list request, so it will be "
                            "registered as-is rather than generating a wrapper."
                        ),
                    )
                )
            kind = InputKind.MCP_ENDPOINT
            tools = probe_result.tools
        elif kind is InputKind.MCP_ENDPOINT:
            # Looked like MCP, isn't. Fall back to reading it as documentation.
            findings.append(
                Finding(
                    id="mode",
                    title="Not an MCP endpoint",
                    detail=(
                        f"{url} did not answer tools/list "
                        f"({probe_result.error or 'no tools'}); reading it as documentation."
                    ),
                    confidence="likely",
                )
            )
            kind = InputKind.DOCS_URL
            probe_result = None

    if kind in (InputKind.DOCS_URL, InputKind.OPENAPI_URL) and url:
        try:
            doc = await fetch_document(url, allowed_hosts=allowed)
            fetched = doc.text
        except FetchError as exc:
            return ResolvedPlan(
                ready=False,
                summary="That URL could not be read.",
                kind=kind,
                error=str(exc),
                findings=findings,
            )
        # The parser is authoritative about what was actually returned, so a
        # page served from a /openapi.json path is still caught here.
        try:
            parsed = openapi_loader.parse_document(fetched)
            if isinstance(parsed, dict) and ("openapi" in parsed or "swagger" in parsed):
                if kind is not InputKind.OPENAPI_URL:
                    findings.append(
                        Finding(
                            id="source",
                            title="OpenAPI specification",
                            detail="The URL returned a spec, so it is parsed deterministically "
                            "with no model involved.",
                        )
                    )
                kind = InputKind.OPENAPI_URL
            elif kind is InputKind.OPENAPI_URL:
                findings.append(
                    Finding(
                        id="source",
                        title="Documentation page",
                        detail="The URL did not return a parseable spec; it will be read as "
                        "freeform documentation instead.",
                        confidence="likely",
                    )
                )
                kind = InputKind.DOCS_URL
        except openapi_loader.OpenAPIError:
            kind = InputKind.DOCS_URL

    # -- description ------------------------------------------------------
    description = (payload.description or overrides.get("description") or "").strip()
    if len(description) < _MIN_DESCRIPTION:
        derived = None
        if kind in (InputKind.OPENAPI_URL, InputKind.OPENAPI_TEXT):
            derived = _describe_from_spec(fetched or raw_text)
        elif probe_result is not None:
            derived = _describe_from_probe(probe_result)
        if derived and len(derived) >= _MIN_DESCRIPTION:
            description = derived
            findings.append(
                Finding(
                    id="description",
                    title="Description taken from the source",
                    detail=derived[:200],
                    confidence="likely",
                )
            )

    if len(description) < _MIN_DESCRIPTION:
        questions.append(
            Question(
                id="description",
                title="What should this MCP server do?",
                detail="Used to prioritise which documented operations become tools.",
                fields=[
                    Field(
                        name="description",
                        label="Description",
                        placeholder="Tools for querying and creating support tickets",
                        value=description or None,
                    )
                ],
            )
        )
        return ResolvedPlan(
            ready=False,
            summary="One thing left: describe what this server should do.",
            kind=kind,
            findings=findings,
            questions=questions,
            tools=tools,
        )

    # -- assemble the request ---------------------------------------------
    docs: DocSource | None = None
    mcp_url: str | None = None
    if kind is InputKind.MCP_ENDPOINT:
        mcp_url = url
    elif kind is InputKind.OPENAPI_URL:
        docs = DocSource(openapi_url=url)
    elif kind is InputKind.DOCS_URL:
        docs = DocSource(url=url)
    elif kind is InputKind.OPENAPI_TEXT:
        docs = DocSource(openapi_inline=raw_text)
    else:
        docs = DocSource(text=raw_text)

    # Auth: provider knowledge first, then the spec, then discovery.
    auth_kind: AuthKind | None = None
    _, provider_meta = provider_for(mcp_url)
    if provider_meta.get("oauth_preset"):
        auth_kind = AuthKind.OAUTH_USER
        findings.append(
            Finding(
                id="auth",
                title="Upstream authentication",
                detail=f"{provider_meta.get('label', 'This provider')} uses OAuth; its "
                "endpoints and scopes are known and will be filled in.",
            )
        )
    elif kind in (InputKind.OPENAPI_URL, InputKind.OPENAPI_TEXT):
        auth_kind = _auth_from_spec(fetched or raw_text)
        if auth_kind is AuthKind.NONE:
            findings.append(
                Finding(
                    id="auth",
                    title="No upstream authentication",
                    detail="The specification declares no OAuth security scheme.",
                    confidence="likely",
                )
            )
        elif auth_kind is AuthKind.OAUTH_USER:
            findings.append(
                Finding(
                    id="auth",
                    title="Upstream authentication",
                    detail="The specification declares an OAuth2 security scheme.",
                )
            )

    if auth_kind is None and mcp_url:
        discovered = await md_mod.discover_for_mcp(mcp_url, client=client)
        if discovered is not None:
            auth_kind = AuthKind.OAUTH_USER
            findings.append(
                Finding(
                    id="auth",
                    title="Authorization server discovered",
                    detail=f"{discovered.issuer} advertises OAuth metadata; "
                    + (
                        "it supports dynamic registration, so no credentials are needed."
                        if discovered.supports_dcr
                        else "static credentials may be required."
                    ),
                )
            )
        elif probe_result is not None and not probe_result.requires_auth:
            auth_kind = AuthKind.NONE
            findings.append(
                Finding(
                    id="auth",
                    title="No upstream authentication",
                    detail="The server answered unauthenticated and advertises no "
                    "authorization metadata.",
                    confidence="likely",
                )
            )

    if auth_kind is None:
        # Freeform documentation tells us nothing; keep the safe default rather
        # than guessing a server open that isn't.
        auth_kind = AuthKind.OAUTH_USER

    if override_auth := overrides.get("auth_kind"):
        auth_kind = AuthKind(override_auth)

    oauth_fields = {
        key: (overrides.get(key) or None)
        for key in ("client_id", "client_secret", "authorization_endpoint", "token_endpoint")
    }
    oauth = UpstreamOAuth(**oauth_fields) if any(oauth_fields.values()) else None

    try:
        request = CreateMcpRequest(
            description=description,
            docs=docs,
            mcp_url=mcp_url,
            oauth=oauth,
            auth_kind=auth_kind,
            # Only when the mode actually uses it: CreateMcpRequest rejects a
            # key supplied alongside any other auth kind, which is what stops a
            # detected key from being silently ignored.
            api_key=api_key if auth_kind is AuthKind.API_KEY else None,
            api_key_header=overrides.get("api_key_header") or None,
            api_key_query_param=overrides.get("api_key_query_param") or None,
            name=overrides.get("name") or None,
            scopes=_split_scopes(overrides.get("scopes")),
            base_url=overrides.get("base_url") or None,
            gemini_enterprise_engine_id=overrides.get("engine_id") or None,
            stop_after=overrides.get("stop_after") or None,
        )
    except ValueError as exc:
        return ResolvedPlan(
            ready=False,
            summary="That input could not be turned into a valid request.",
            kind=kind,
            error=str(exc),
            findings=findings,
        )

    # Fill in everything the provider tables know: endpoints, scopes, preset.
    request = apply_provider_defaults(request)
    if request.scopes:
        findings.append(
            Finding(
                id="scopes",
                title="Scopes",
                detail=" ".join(request.scopes),
            )
        )

    # -- what is genuinely left -------------------------------------------
    pf = await evaluate(
        request,
        project_id=settings.project_id,
        proxy_redirect_uri=f"{settings.oauth_public_base_url}/oauth/callback",
        service_usage=service_usage,
        registry=registry,
        invoker_principals=settings.default_mcp_invokers,
    )
    for req in pf.requirements:
        if req.status is ReqStatus.AUTO:
            findings.append(
                Finding(id=req.id, title=req.title, detail=req.detail)
            )
        elif req.status is ReqStatus.SATISFIED and req.id != "engine":
            findings.append(
                Finding(id=req.id, title=req.title, detail=req.detail)
            )

    questions.extend(
        q
        for q in _questions_from_preflight(pf, overrides=overrides)
        # The engine requirement is replaced by a real dropdown below.
        if q.id != "engine"
    )

    if not request.gemini_enterprise_engine_id:
        engine_q = await _engine_question(engines, overrides=overrides, findings=findings)
        if engine_q is not None:
            questions.append(engine_q)
        elif overrides.get("engine_id"):
            request = request.model_copy(
                update={"gemini_enterprise_engine_id": overrides["engine_id"]}
            )

    if tools:
        findings.append(
            Finding(
                id="tools",
                title=f"{len(tools)} tool{'s' if len(tools) != 1 else ''} available",
                detail=", ".join(t.get("name", "?") for t in tools[:12]),
            )
        )

    blocking = [q for q in questions if q.blocking]
    if blocking:
        summary = f"{len(blocking)} thing(s) still needed: " + "; ".join(
            q.title for q in blocking
        )
    else:
        summary = "Ready to create."

    return ResolvedPlan(
        ready=not blocking,
        summary=summary,
        kind=kind,
        request=request,
        findings=findings,
        questions=questions,
        tools=tools,
    )
