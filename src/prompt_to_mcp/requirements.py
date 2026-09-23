"""Preflight requirements: what the app fixes itself, and what only you can do.

Every prerequisite is modelled as a :class:`Requirement` with an explicit
status:

``SATISFIED``  nothing to do.
``AUTO``       the app can and will fix this itself (enabling APIs).
``MANUAL``     genuinely impossible to automate, so the app must instead say
               exactly what to click, exactly what to paste, and where.

The manual case matters most. Creating a generic web OAuth client is *not*
automatable: the only programmatic OAuth-client surface Google exposes is
``iap.projects.brands.identityAwareProxyClients``, whose
``IdentityAwareProxyClient`` resource has **no redirect-URI field** -- IAP
clients are pinned to IAP's own redirect handler and therefore cannot serve
Gemini Enterprise's callback. So instructions it is, but precise ones: deep
console links, the literal redirect URI to paste, and the exact scopes.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from .models import AuthKind, CreateMcpRequest, holds_static_credential


class ReqStatus(StrEnum):
    SATISFIED = "satisfied"
    AUTO = "auto"
    MANUAL = "manual"
    UNKNOWN = "unknown"


class Action(BaseModel):
    """One concrete thing to do, in whatever form is most useful."""

    text: str
    #: Deep link into the Cloud console, prefilled where possible.
    url: str | None = None
    #: Equivalent CLI command.
    cli: str | None = None
    #: A literal value the user must paste somewhere (redirect URI, scope...).
    #: Named `copy_value` because `copy` shadows a BaseModel method; the JSON
    #: field is still `copy`.
    copy_value: str | None = Field(default=None, alias="copy")

    model_config = {"populate_by_name": True}


class Requirement(BaseModel):
    id: str
    title: str
    status: ReqStatus
    detail: str = ""
    actions: list[Action] = Field(default_factory=list)
    #: True when the pipeline will fail without this.
    blocking: bool = True


class Preflight(BaseModel):
    ready: bool
    summary: str
    requirements: list[Requirement] = Field(default_factory=list)

    @property
    def blocking_manual(self) -> list[Requirement]:
        return [
            r for r in self.requirements if r.blocking and r.status is ReqStatus.MANUAL
        ]

    @property
    def auto_fixable(self) -> list[Requirement]:
        return [r for r in self.requirements if r.status is ReqStatus.AUTO]


# ---------------------------------------------------------------------------
# Provider knowledge
# ---------------------------------------------------------------------------

#: Providers whose setup requirements are documented out of band. Only entries
#: verified against the provider's own documentation belong here.
KNOWN_PROVIDERS: dict[str, dict[str, Any]] = {
    "drivemcp.googleapis.com": {
        "label": "Google Drive MCP",
        # Verified: developers.google.com/workspace/drive/api/guides/configure-mcp-server
        "apis": ["drive.googleapis.com", "drivemcp.googleapis.com"],
        "oauth_preset": "google",
        # Google supports neither RFC 7591 dynamic registration nor public
        # clients, so a static client ID and secret is unavoidable here. This
        # is what makes the requirement genuinely blocking rather than
        # something the proxy could solve on its own.
        "requires_static_credentials": True,
        "scopes": [
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/drive.file",
        ],
        "docs": "https://developers.google.com/workspace/drive/api/guides/configure-mcp-server",
    },
}

GEMINI_ENTERPRISE_REDIRECT = "https://vertexaisearch.cloud.google.com/oauth-redirect"


def provider_for(url: str | None) -> tuple[str | None, dict[str, Any]]:
    """Look up provider metadata for an MCP URL."""
    if not url:
        return None, {}
    host = (urlparse(url).hostname or "").lower()
    if host in KNOWN_PROVIDERS:
        return host, KNOWN_PROVIDERS[host]
    if host.endswith(".googleapis.com"):
        # Generic Google service: enabling the service itself is a safe guess.
        return host, {
            "label": host,
            "apis": [host],
            "oauth_preset": "google",
            "requires_static_credentials": True,
            "scopes": [],
            "docs": None,
        }
    return host or None, {}


def apply_provider_defaults(
    req: CreateMcpRequest, *, mcp_url: str | None = None
) -> CreateMcpRequest:
    """Fill in everything we can infer, so the user is never asked for it.

    If we recognise the provider we already know its authorization endpoints and
    its documented scopes. Making the operator restate them -- and failing the
    run when they don't -- is the app withholding information it has. Only the
    client ID and secret genuinely have to come from the user.

    Returns a copy; the original request is left untouched.
    """
    from .models import UpstreamOAuth

    url = mcp_url or req.mcp_url
    _, meta = provider_for(url)
    if not meta:
        return req

    preset = meta.get("oauth_preset")
    default_scopes = list(meta.get("scopes") or [])
    oauth = req.oauth

    if oauth is None:
        if not preset and not default_scopes:
            return req
        oauth = UpstreamOAuth(preset=preset, scopes=req.scopes or default_scopes)
    else:
        updates: dict[str, Any] = {}
        if preset and not oauth.preset and not oauth.has_endpoints:
            updates["preset"] = preset
        if not oauth.scopes:
            updates["scopes"] = req.scopes or default_scopes
        if not updates:
            return req.model_copy(update={"oauth": oauth})
        # Re-validate so the preset's endpoints are actually applied.
        oauth = UpstreamOAuth.model_validate({**oauth.model_dump(), **updates})

    scopes = req.scopes or oauth.scopes or default_scopes
    return req.model_copy(update={"oauth": oauth, "scopes": scopes})


def required_apis(req: CreateMcpRequest) -> list[str]:
    _, meta = provider_for(req.mcp_url)
    return list(meta.get("apis") or [])


# ---------------------------------------------------------------------------
# Requirement construction
# ---------------------------------------------------------------------------


def _oauth_client_requirement(
    req: CreateMcpRequest,
    *,
    project_id: str,
    proxy_redirect_uri: str,
    meta: dict[str, Any],
) -> Requirement:
    """The one genuinely manual step, spelled out end to end."""
    oauth = req.oauth
    if oauth and oauth.client_id and oauth.client_secret:
        return Requirement(
            id="oauth_client",
            title="OAuth client credentials",
            status=ReqStatus.SATISFIED,
            detail="Client ID and secret supplied.",
        )

    # Which redirect URI the operator must register depends on whether the
    # proxy is in the path, so compute it rather than listing both vaguely.
    from .models import ProxyMode

    uses_proxy = req.use_proxy is ProxyMode.ALWAYS or not (oauth and oauth.has_endpoints)
    redirect = proxy_redirect_uri if uses_proxy else GEMINI_ENTERPRISE_REDIRECT
    redirect_why = (
        "the OAuth proxy handles the callback"
        if uses_proxy
        else "Gemini Enterprise handles the callback directly"
    )

    scopes = (oauth.scopes if oauth else None) or req.scopes or list(meta.get("scopes") or [])

    # Only genuinely blocking when the upstream cannot mint credentials itself.
    # An unknown upstream may well support RFC 7591 dynamic registration, in
    # which case the proxy handles it and the operator needs to do nothing.
    must_be_static = bool(meta.get("requires_static_credentials"))
    if not must_be_static:
        return Requirement(
            id="oauth_client",
            title="OAuth client credentials",
            status=ReqStatus.AUTO,
            blocking=False,
            detail=(
                "None supplied. The proxy will try RFC 7591 dynamic registration "
                "against the upstream authorization server, and only needs your own "
                "client ID and secret if that is unavailable."
            ),
        )

    actions = [
        Action(
            text="Create an OAuth client: Google Auth Platform > Clients > Create client, "
            "type 'Web application'.",
            url=f"https://console.cloud.google.com/auth/clients/create?project={project_id}",
        ),
        Action(
            text=f"Add this Authorized redirect URI ({redirect_why}).",
            copy_value=redirect,
        ),
    ]
    if scopes:
        actions.append(
            Action(
                text="Add these scopes under Data Access > Add or remove scopes.",
                url=f"https://console.cloud.google.com/auth/scopes?project={project_id}",
                copy_value=" ".join(scopes),
            )
        )
    actions.append(
        Action(text="Copy the client ID and secret back into this form and run again.")
    )
    if meta.get("docs"):
        actions.append(Action(text="Provider setup guide.", url=meta["docs"]))

    return Requirement(
        id="oauth_client",
        title="OAuth client ID and secret",
        status=ReqStatus.MANUAL,
        detail=(
            f"{meta.get('label', 'This provider')} requires a static client ID and secret "
            "-- it supports neither dynamic registration nor public clients. Google exposes "
            "no API for creating a web OAuth client with a custom redirect URI, so this one "
            "step cannot be automated. It takes about a minute."
        ),
        actions=actions,
    )


def _exposure_requirement(
    req: CreateMcpRequest, *, invoker_principals: list[str]
) -> Requirement:
    """How the finished MCP will be reachable, stated before anything is built.

    This belongs in preflight specifically because the alternative is finding
    out at the deploy stage, four minutes in, that the run cannot proceed --
    or worse, not finding out at all and ending up with a public service
    spending an API key. Preflight's whole contract is "what this run needs,
    before it creates anything", and "who will be able to call the result" is
    the most consequential item on that list.
    """
    kind = req.auth_kind
    if not holds_static_credential(kind):
        return Requirement(
            id="mcp_exposure",
            title="MCP server exposure",
            status=ReqStatus.SATISFIED,
            blocking=False,
            detail=(
                f"Will be published publicly. Safe for auth_kind='{kind}': the server "
                "holds no credential of its own, so reaching it grants nothing. Every "
                "request must still carry a token the upstream validates."
            ),
        )

    what = (
        "holds your API key in Secret Manager and attaches it to every upstream request"
        if kind is AuthKind.API_KEY
        else "relays to the upstream base URL with no credential check"
    )

    if req.allow_public_unauthenticated:
        return Requirement(
            id="mcp_exposure",
            title="MCP server will be PUBLIC and holds a credential",
            status=ReqStatus.SATISFIED,
            blocking=False,
            detail=(
                f"allow_public_unauthenticated is set, so this server will be granted "
                f"allUsers even though it {what}. Anyone who finds its Cloud Run URL "
                "can use it as you, without authenticating. Reasonable for a free "
                "read-only key or a sandbox; not otherwise."
            ),
        )

    if invoker_principals:
        return Requirement(
            id="mcp_exposure",
            title="MCP server exposure",
            status=ReqStatus.SATISFIED,
            blocking=False,
            detail=(
                f"Will be deployed privately because auth_kind='{kind}' {what}. "
                f"roles/run.invoker will be granted to: {', '.join(invoker_principals)}. "
                "Note that this path is unverified against a live Gemini Enterprise "
                "app: if GE does not present a Google ID token, tool calls will return "
                "403 and you will need auth_kind='oauth_user' or "
                "allow_public_unauthenticated."
            ),
        )

    return Requirement(
        id="mcp_exposure",
        title="MCP server cannot be published and has no permitted caller",
        status=ReqStatus.MANUAL,
        detail=(
            f"auth_kind='{kind}' {what}, so it will not be granted allUsers. But no "
            "invoker principal is configured either, so nothing would be able to call "
            "it. The deploy stage will refuse rather than create an unreachable service."
        ),
        actions=[
            Action(
                text="Use per-user credentials instead -- the server then holds nothing "
                "and is published normally.",
                copy_value='"auth_kind": "oauth_user"',
            ),
            Action(
                text="Or let Gemini Enterprise in by name: set the project number so the "
                "Discovery Engine service agent can be granted roles/run.invoker.",
                cli="gcloud run services update prompt-to-mcp "
                "--update-env-vars P2M_PROJECT_NUMBER=$(gcloud projects describe "
                "$PROJECT_ID --format='value(projectNumber)')",
            ),
            Action(
                text="Or accept the exposure deliberately.",
                copy_value='"allow_public_unauthenticated": true',
            ),
        ],
    )


async def evaluate(
    req: CreateMcpRequest,
    *,
    project_id: str,
    proxy_redirect_uri: str,
    service_usage: Any | None = None,
    registry: Any | None = None,
    invoker_principals: list[str] | None = None,
) -> Preflight:
    """Assess everything a run needs before it starts."""
    requirements: list[Requirement] = []
    _, meta = provider_for(req.mcp_url)

    # Only meaningful when we are generating a server. Registering an existing
    # MCP deploys nothing, so there is no exposure decision to make.
    if not req.registers_existing:
        requirements.append(
            _exposure_requirement(req, invoker_principals=list(invoker_principals or []))
        )

    # -- Google APIs -----------------------------------------------------
    apis = list(meta.get("apis") or [])
    if apis:
        state: dict[str, bool] = {}
        if service_usage is not None:
            state = await service_usage.enabled_state(apis)
        missing = [a for a in apis if not state.get(a, False)]
        if not missing:
            requirements.append(
                Requirement(
                    id="apis",
                    title="Required Google APIs",
                    status=ReqStatus.SATISFIED,
                    detail=f"Enabled: {', '.join(apis)}",
                )
            )
        else:
            requirements.append(
                Requirement(
                    id="apis",
                    title="Required Google APIs",
                    status=ReqStatus.AUTO,
                    detail=(
                        f"{', '.join(missing)} will be enabled automatically when you run."
                    ),
                    actions=[
                        Action(
                            text="Enable manually instead (optional).",
                            cli=(
                                f"gcloud services enable {' '.join(missing)} "
                                f"--project {project_id}"
                            ),
                        )
                    ],
                )
            )

    # -- OAuth -----------------------------------------------------------
    if req.auth_kind is AuthKind.OAUTH_USER:
        requirements.append(
            _oauth_client_requirement(
                req,
                project_id=project_id,
                proxy_redirect_uri=proxy_redirect_uri,
                meta=meta,
            )
        )

        oauth = req.oauth
        _, pmeta = provider_for(req.mcp_url)
        if oauth and oauth.has_endpoints:
            how = (
                f"applied automatically from the '{oauth.preset}' preset"
                if oauth.preset
                else "supplied"
            )
            requirements.append(
                Requirement(
                    id="oauth_endpoints",
                    title="Authorization server endpoints",
                    status=ReqStatus.SATISFIED,
                    detail=f"{oauth.authorization_endpoint} ({how}).",
                )
            )
        elif pmeta.get("oauth_preset"):
            requirements.append(
                Requirement(
                    id="oauth_endpoints",
                    title="Authorization server endpoints",
                    status=ReqStatus.AUTO,
                    blocking=False,
                    detail=(
                        f"{pmeta['label']} publishes no OAuth discovery metadata, so the "
                        f"'{pmeta['oauth_preset']}' preset will be applied for you."
                    ),
                )
            )
        else:
            requirements.append(
                Requirement(
                    id="oauth_endpoints",
                    title="Authorization server endpoints",
                    status=ReqStatus.SATISFIED,
                    detail="Discoverable from the upstream server.",
                )
            )
    else:
        requirements.append(
            Requirement(
                id="oauth_client",
                title="OAuth client ID and secret",
                status=ReqStatus.SATISFIED,
                blocking=False,
                detail=f"Not required: auth_kind is '{req.auth_kind}'.",
            )
        )

    # -- Interface URL uniqueness ----------------------------------------
    if req.mcp_url and registry is not None:
        try:
            owner = await registry.service_using_url(req.mcp_url)
        except Exception:  # noqa: BLE001 - advisory only
            owner = None
        if owner is not None:
            name = owner.get("name", "").rsplit("/", 1)[-1]
            requirements.append(
                Requirement(
                    id="url_conflict",
                    title="MCP URL already registered",
                    status=ReqStatus.MANUAL,
                    detail=(
                        f"Agent Registry already has '{owner.get('displayName') or name}' "
                        f"bound to {req.mcp_url}. Interface URLs must be unique within a "
                        "location, so registering again will fail."
                    ),
                    actions=[
                        Action(
                            text=f"Delete the existing entry '{name}' from the list on the "
                            "right, then run again."
                        )
                    ],
                )
            )
        else:
            requirements.append(
                Requirement(
                    id="url_conflict",
                    title="MCP URL is free",
                    status=ReqStatus.SATISFIED,
                    detail=f"No other Agent Registry service is bound to {req.mcp_url}.",
                )
            )

    # -- Gemini Enterprise app -------------------------------------------
    if req.gemini_enterprise_engine_id:
        requirements.append(
            Requirement(
                id="engine",
                title="Gemini Enterprise app",
                status=ReqStatus.SATISFIED,
                detail=f"Will attach to '{req.gemini_enterprise_engine_id}'.",
            )
        )
    else:
        requirements.append(
            Requirement(
                id="engine",
                title="Gemini Enterprise app",
                status=ReqStatus.MANUAL,
                blocking=False,
                detail=(
                    "No app ID given. The data store will be created but not attached "
                    "to an app, so it will not appear to end users."
                ),
                actions=[
                    Action(
                        text="Find your app ID in the Gemini Enterprise console and set "
                        "'Gemini Enterprise app ID'.",
                        url="https://console.cloud.google.com/gen-app-builder/engines"
                        f"?project={project_id}",
                    )
                ],
            )
        )

    blocking = [r for r in requirements if r.blocking and r.status is ReqStatus.MANUAL]
    auto = [r for r in requirements if r.status is ReqStatus.AUTO]

    if blocking:
        summary = (
            f"{len(blocking)} step(s) need you: "
            + "; ".join(r.title for r in blocking)
        )
    elif auto:
        summary = (
            f"Ready. {len(auto)} prerequisite(s) will be set up automatically when you run."
        )
    else:
        summary = "Ready. Everything this run needs is already in place."

    return Preflight(ready=not blocking, summary=summary, requirements=requirements)
