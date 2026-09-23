"""Runtime configuration.

Location notes (verified against the live APIs, 2026-08):

* ``agentregistry.googleapis.com`` only accepts ``global`` and ``us-central1``.
  Any other location returns ``INVALID_ARGUMENT: location is not supported``.
* ``discoveryengine.googleapis.com`` collections/authorizations for Gemini
  Enterprise live under ``global`` and MUST be called on the global endpoint.
  Calling ``/locations/us/...`` on the global host returns
  ``Incorrect API endpoint used``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

AGENT_REGISTRY_LOCATIONS = {"global", "us-central1"}

#: A list setting that may be written as a comma-separated environment variable.
#:
#: pydantic-settings parses a ``list[str]`` field from the environment as JSON,
#: so ``P2M_ALLOWED_PRINCIPALS=a@x.com,b@x.com`` raises a ``SettingsError``
#: before any validator runs -- the service fails to start with a message that
#: names the field but not the format. ``NoDecode`` hands the raw string to the
#: validator below instead. That matters most for the allowlist: the failure
#: mode of a fiddly format on a security setting is an operator who gives up
#: and sets the escape hatch.
CommaSeparated = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="P2M_", env_file=".env", extra="ignore")

    # --- Google Cloud ---------------------------------------------------
    project_id: str = Field(..., description="GCP project that owns everything we create.")
    project_number: str | None = Field(
        default=None,
        description=(
            "Discovery Engine returns resource names by number, and the Gemini "
            "Enterprise service agent is keyed on it -- see mcp_invoker_principals. "
            "deploy.sh resolves it with `gcloud projects describe` and passes it in."
        ),
    )

    #: Where the generated MCP Cloud Run services are deployed.
    run_region: str = "us-central1"

    #: Agent Registry location. Must be one of AGENT_REGISTRY_LOCATIONS.
    agent_registry_location: str = "us-central1"

    #: Discovery Engine / Gemini Enterprise location.
    discovery_engine_location: str = "global"

    #: Artifact Registry repo for generated MCP images.
    artifact_repo: str = "prompt-to-mcp"

    #: Service account the generated MCP services run as. Falls back to the
    #: project's default compute SA when unset.
    mcp_service_account: str | None = None

    #: IAM members granted ``roles/run.invoker`` on a generated MCP service that
    #: is NOT published publicly -- i.e. the ``api_key`` and ``none`` auth kinds,
    #: which hold a credential and therefore must not accept anonymous callers.
    #:
    #: Full IAM member syntax (``serviceAccount:...``, ``user:...``,
    #: ``group:...``). When empty, :meth:`default_mcp_invokers` derives the
    #: Gemini Enterprise (Discovery Engine) service agent from
    #: ``project_number``.
    #:
    #: UNVERIFIED against a live Gemini Enterprise app. Cloud Run authorises a
    #: caller only if it presents a Google-signed ID token audienced to the
    #: service; whether the Discovery Engine connector does so when it calls an
    #: MCP endpoint has never been observed -- see the note in
    #: :mod:`prompt_to_mcp.deployer.cloud_run`. If it does not, tool calls fail
    #: with 403 and the operator's options are ``auth_kind="oauth_user"`` or the
    #: explicit ``allow_public_unauthenticated`` opt-in on the request.
    mcp_invoker_principals: CommaSeparated = Field(default_factory=list)

    # --- Control plane --------------------------------------------------
    #: Public base URL of THIS service -- the provisioning API and the UI.
    #: Used for self-referential links; it is NOT where the OAuth proxy lives
    #: (see ``oauth_base_url``).
    public_base_url: str = "http://localhost:8080"

    #: Base URL of the OAuth proxy, which runs as a **separate** Cloud Run
    #: service (see :mod:`prompt_to_mcp.oauth_app`).
    #:
    #: The split exists because the two halves have irreconcilable exposure
    #: requirements. The provisioning API acts as a service account holding
    #: broad project roles and must never accept an unauthenticated request.
    #: The OAuth proxy is the opposite by construction: the end user's browser
    #: is redirected to ``/oauth/authorize`` and the upstream provider redirects
    #: it back to ``/oauth/callback``, neither of which can carry a Google
    #: credential for this project. Hosting both in one service forced a choice
    #: between a public control plane and a broken consent flow.
    #:
    #: These URLs are baked into Discovery Engine ``Authorization`` resources at
    #: provisioning time and cannot be changed afterwards without rebuilding the
    #: connector, so this must be the externally reachable URL, not localhost.
    #: Falls back to ``public_base_url`` when unset, which is what makes a
    #: single-process local run (``make run``) still work.
    oauth_base_url: str | None = None

    #: Extra ``aud`` values accepted on an inbound ID token, on top of this
    #: service's own URL.
    #:
    #: Defaults to gcloud's OAuth client ID, which is the audience of every ID
    #: token minted for a *user* account -- gcloud refuses ``--audiences`` for
    #: user credentials, so without this no human can authenticate and every
    #: documented ``curl`` returns 401. Set it empty to accept service-account
    #: callers only. See :data:`prompt_to_mcp.auth.GCLOUD_CLI_AUDIENCE`.
    extra_allowed_audiences: CommaSeparated = Field(
        default_factory=lambda: ["32555940559.apps.googleusercontent.com"]
    )

    #: Principals allowed to call the control plane, as bare email addresses
    #: (``you@example.com``, ``deployer@project.iam.gserviceaccount.com``).
    #:
    #: Checked against the verified ``email``/``sub`` claim of a Google-signed
    #: ID token by :mod:`prompt_to_mcp.auth`. An **empty list denies everyone**
    #: -- it is not an "auth disabled" switch. Turning the check off is a
    #: separate, deliberate act (``P2M_ALLOW_UNAUTHENTICATED=1``), so a config
    #: that was forgotten cannot silently publish the API.
    allowed_principals: CommaSeparated = Field(default_factory=list)

    #: Firestore database id holding MCP records and OAuth client state.
    firestore_database: str = "(default)"

    #: Gemini model used to turn freeform API docs into a tool manifest, to
    #: explain failures, and to drive the contract discovery agent.
    #:
    #: Gemini 3 has no GA pro-tier text model; the only one is
    #: ``gemini-3.1-pro-preview``. This is deliberately pinned to the newest GA
    #: model instead, trading some reasoning headroom for a supported model.
    #: The contract agent is the workload most sensitive to that trade -- its
    #: evidence gate downgrades unverified proposals, so a weaker model yields
    #: thinner findings rather than wrong ones.
    gemini_model: str = "gemini-3.7-flash"
    gemini_location: str = "global"

    #: Fail closed if the caller asks for an upstream host not on this list.
    #: Empty list disables the check (not recommended in production).
    allowed_upstream_hosts: CommaSeparated = Field(default_factory=list)

    #: Max tools we will synthesise from one document.
    max_tools: int = 60

    #: Agent Registry caps mcpServerSpec.content at 10KB.
    tool_spec_max_bytes: int = 10_000

    @field_validator(
        "allowed_principals",
        "mcp_invoker_principals",
        "allowed_upstream_hosts",
        "extra_allowed_audiences",
        mode="before",
    )
    @classmethod
    def _split_list(cls, v: Any) -> Any:
        """Accept ``a,b,c`` as well as a real list or a JSON array.

        Blank entries are dropped rather than kept: `P2M_ALLOWED_PRINCIPALS=","`
        must mean "nobody", and an allowlist containing an empty string that
        happened to match an empty claim would be a genuinely bad surprise.
        """
        if isinstance(v, str):
            text = v.strip()
            if text.startswith("["):
                import json

                return json.loads(text)
            return [part.strip() for part in text.split(",") if part.strip()]
        if isinstance(v, list):
            return [str(part).strip() for part in v if str(part).strip()]
        return v

    @field_validator("agent_registry_location")
    @classmethod
    def _check_ar_location(cls, v: str) -> str:
        if v not in AGENT_REGISTRY_LOCATIONS:
            raise ValueError(
                "agent_registry_location must be one of "
                f"{sorted(AGENT_REGISTRY_LOCATIONS)}, got {v!r}"
            )
        return v

    @field_validator("public_base_url")
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @property
    def oauth_public_base_url(self) -> str:
        """Where the OAuth proxy actually answers.

        Falls back to ``public_base_url`` so a single-process local run, where
        both halves are served by one app, keeps working.
        """
        return (self.oauth_base_url or self.public_base_url).rstrip("/")

    @property
    def default_mcp_invokers(self) -> list[str]:
        """Who may invoke a private generated MCP service.

        The Discovery Engine service agent is the identity Gemini Enterprise
        uses for project-scoped work, and it is addressable only by project
        *number*, not project id -- hence the ``project_number`` requirement.
        Returns empty when the number is unknown, which leaves the service
        reachable by nobody rather than by everybody.
        """
        if self.mcp_invoker_principals:
            return list(self.mcp_invoker_principals)
        if not self.project_number:
            return []
        return [
            "serviceAccount:service-"
            f"{self.project_number}@gcp-sa-discoveryengine.iam.gserviceaccount.com"
        ]

    @property
    def agent_registry_parent(self) -> str:
        return f"projects/{self.project_id}/locations/{self.agent_registry_location}"

    @property
    def discovery_engine_parent(self) -> str:
        return f"projects/{self.project_id}/locations/{self.discovery_engine_location}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
