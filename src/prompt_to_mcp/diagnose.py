"""Explain a failed run in terms of what to do about it.

A stage failure currently surfaces as the upstream error verbatim:

    400 from ...:setUpDataConnector: For auth_type: OAUTH, Connector params
    must contain client_id.

That is precise, and useless to almost everyone. It names a field in a request
body the user never wrote, in an API they may not know exists, at a stage they
cannot see into. Knowing the message is not the same as knowing what to do.

This module turns a failed :class:`~.models.McpRecord` into a
:class:`Diagnosis`: what broke, why, whether it is even the operator's problem,
and the concrete next step. Two sources, in order of trust:

**Known failures** (:data:`KNOWN_FAILURES`) are hand-written rules matched
against the error text. They are exact, free, instant, and testable, and they
can say things a model cannot know -- such as which line of this codebase is
wrong. Every failure worth seeing twice belongs here.

**The model** handles everything else. Novel failures are exactly where a user
is most stranded and where canned text helps least, so an unmatched error is
sent to Gemini for a structured explanation rather than shrugged at.

A diagnosis never blames the user by default. Some failures are genuinely bugs
in this app, and saying so -- rather than inventing a plausible setup step for
the operator to waste an afternoon on -- is the whole point. ``likely_app_bug``
is part of the contract.

Nothing here is sent to the model unredacted: the record is persisted with
secrets already fingerprinted by :mod:`.redact`, and that persisted form is
what gets used.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

from .config import Settings
from .requirements import Action

log = logging.getLogger(__name__)

#: Cap on the record JSON handed to the model. Records embed tool specs and doc
#: previews and can be large; the stages and the error are what matter.
MAX_CONTEXT_CHARS = 24_000


class Diagnosis(BaseModel):
    """A failure, explained."""

    #: One line, plain language, no jargon: what went wrong.
    summary: str
    #: Why it happened, in as much depth as is actually known.
    cause: str = ""
    #: Ordered, concrete things to do. May be empty when it is our bug.
    steps: list[Action] = Field(default_factory=list)
    #: True when the fault is in this application, not the user's setup.
    #: Deliberately explicit: the alternative is inventing a setup step for a
    #: problem the operator cannot fix, which wastes their time and hides ours.
    likely_app_bug: bool = False
    #: Which stage failed, when it can be determined.
    stage: str | None = None
    #: "known" (hand-written rule), "model" (Gemini), or "none".
    source: str = "none"
    #: False when the model was unavailable and we fell back to the raw error.
    confident: bool = True


# ---------------------------------------------------------------------------
# Known failures
# ---------------------------------------------------------------------------

#: A rule: (id, compiled pattern, builder). The builder receives the regex
#: match and the failed record, and returns a Diagnosis.
Rule = tuple[str, re.Pattern[str], Callable[[re.Match[str], dict[str, Any]], Diagnosis]]


def _connector_missing_client_id(_m: re.Match[str], record: dict[str, Any]) -> Diagnosis:
    """`setUpDataConnector` demanded a connector param the run could not supply.

    The connector body is negotiated: ``set_up_mcp_connector`` reads the API's
    own rejection, amends the request from values the run already holds, and
    resends. Reaching this diagnosis therefore means the negotiation ran out of
    road -- the demanded key was not in the pool. For ``client_id`` that should
    only be possible when no Authorization resource was created, because
    otherwise the id exists and is sent up front.
    """
    client_id = record.get("proxy_client_id")
    negotiation = ((record.get("config") or {}).get("connect") or {}).get("negotiation") or []
    tried = f" after {len(negotiation)} request shape(s)" if len(negotiation) > 1 else ""
    return Diagnosis(
        summary=(
            "Gemini Enterprise rejected the data-connector request: it requires an "
            "OAuth client ID in the connector parameters" + tried + "."
        ),
        cause=(
            "Everything up to this point succeeded -- the MCP server was deployed and "
            "registered, and the Discovery Engine authorization was created. The "
            "connector request is negotiated against the API's own error messages, so "
            "a demanded field is normally filled in automatically and retried. This one "
            "was not, which means the run did not hold a value for it"
            + (
                f". An OAuth client ({client_id}) does exist, so this is a defect in "
                "prompt-to-mcp: the value is not being offered to the negotiation pool."
                if client_id
                else ", most likely because no OAuth authorization was configured for "
                "this MCP. Re-run with `auth_kind: oauth_user` and OAuth endpoints so a "
                "client is created."
            )
        ),
        likely_app_bug=bool(client_id),
        steps=[
            Action(
                text="Your MCP server is deployed and registered, and stays usable. Only "
                "the Gemini Enterprise connection is missing."
            ),
            Action(
                text="Retry just the failed step once the cause is addressed -- this "
                "keeps the existing registration instead of colliding with it.",
                cli=f"curl -X POST $P2M_URL/v1/mcps/{record.get('id', '<id>')}/resume",
            ),
            Action(
                text="Or attach the MCP server to a Gemini Enterprise app by hand.",
                url="https://console.cloud.google.com/gen-app-builder/engines",
            ),
        ],
    )


def _connector_param_shape(m: re.Match[str], _record: dict[str, Any]) -> Diagnosis:
    allowed = m.group("allowed") if "allowed" in (m.groupdict() or {}) else ""
    return Diagnosis(
        summary="Gemini Enterprise rejected the shape of the connector parameters.",
        cause=(
            "setUpDataConnector accepts a different set of 'params' on create than it "
            "returns on read, and the accepted set has changed"
            + (f"; it currently wants: {allowed}" if allowed else "")
            + ". This is a mismatch between this app and the API, not your setup."
        ),
        likely_app_bug=True,
        steps=[
            Action(text="Update the params block in build_mcp_connector to match the "
                        "keys named in the error above.")
        ],
    )


def _action_params_rejected(_m: re.Match[str], _record: dict[str, Any]) -> Diagnosis:
    return Diagnosis(
        summary="Gemini Enterprise rejected one of the connector action parameters.",
        cause=(
            "actionParams is an untyped map in the v1alpha API, so the accepted keys "
            "can only be learned from the server's own rejection message. The set this "
            "app knows about is out of date."
        ),
        likely_app_bug=True,
        steps=[
            Action(text="Update SUPPORTED_ACTION_PARAMS in discovery_engine.py to the "
                        "list of keys named in the error.")
        ],
    )


def _url_already_registered(_m: re.Match[str], record: dict[str, Any]) -> Diagnosis:
    url = (record.get("config", {}).get("register", {}) or {}).get("mcp_url")
    return Diagnosis(
        summary="Another Agent Registry entry already points at this MCP endpoint.",
        cause=(
            "Agent Registry requires interface URLs to be unique within a location"
            + (f", and {url} is already claimed" if url else "")
            + ". This usually means an earlier run for the same server was not deleted."
        ),
        steps=[
            Action(
                text="Delete the earlier entry from the 'Provisioned servers' list, then "
                "run again."
            ),
            Action(
                text="List what is registered, to find the owner.",
                cli="gcloud alpha agent-registry services list --location us-central1",
            ),
        ],
    )


def _permission_denied(_m: re.Match[str], record: dict[str, Any]) -> Diagnosis:
    project = (record.get("config", {}).get("preflight", {}) or {}).get("project_id", "")
    return Diagnosis(
        summary="The control plane's service account is missing a permission.",
        cause=(
            "A Google API refused the call with 403. The service account running "
            "prompt-to-mcp needs roles for Cloud Run, Agent Registry, Discovery Engine, "
            "Secret Manager and Service Usage; deploy/bootstrap.sh grants the full set."
        ),
        steps=[
            Action(
                text="Re-run the bootstrap script, which is idempotent and grants every "
                "role the pipeline needs.",
                cli="make bootstrap",
            ),
            Action(
                text="Or inspect the current bindings and grant the missing role.",
                cli=f"gcloud projects get-iam-policy {project}" if project else None,
            ),
            Action(
                text="Check the IAM page for the service account.",
                url=f"https://console.cloud.google.com/iam-admin/iam?project={project}"
                if project
                else None,
            ),
        ],
    )


def _api_not_enabled(m: re.Match[str], record: dict[str, Any]) -> Diagnosis:
    service = m.groupdict().get("service") or ""
    project = (record.get("config", {}).get("preflight", {}) or {}).get("project_id", "")
    return Diagnosis(
        summary=f"A required Google API is not enabled{f' ({service})' if service else ''}.",
        cause=(
            "The pipeline enables provider APIs it knows about, but this one was not in "
            "its list, so it has to be turned on manually."
        ),
        steps=[
            Action(
                text="Enable it, then run again.",
                cli=f"gcloud services enable {service} --project {project}".strip()
                if service
                else "gcloud services enable SERVICE --project PROJECT",
            )
        ],
    )


def _org_policy_public_invoker(_m: re.Match[str], _record: dict[str, Any]) -> Diagnosis:
    return Diagnosis(
        summary="An organization policy blocked making the Cloud Run service public.",
        cause=(
            "constraints/iap.allowedPolicyMemberDomains prevents granting 'allUsers' the "
            "invoker role, so the generated MCP server was deployed but cannot be reached "
            "anonymously. Gemini Enterprise calls it over the public internet."
        ),
        steps=[
            Action(
                text="Ask an organization administrator to allow public members for this "
                "project, or to exempt it from the domain-restricted-sharing constraint.",
                url="https://console.cloud.google.com/iam-admin/orgpolicies",
            ),
            Action(
                text="The service exists and is otherwise healthy; only the public IAM "
                "binding failed."
            ),
        ],
    )


def _docs_page_not_a_spec(_m: re.Match[str], record: dict[str, Any]) -> Diagnosis:
    """The commonest ingest failure: a rendered page fed to the spec parser.

    The giveaway in the error is inlined CSS -- the YAML parser choking on a
    `@media` block. The user did nothing unreasonable; the page they linked is
    documentation, it just is not a machine-readable specification.
    """
    ingest = record.get("config", {}).get("ingest", {}) or {}
    # `doc_sources` is the full list; `doc_source` is the pre-merge single-value
    # field, still present on older records.
    sources = ingest.get("doc_sources") or [ingest.get("doc_source") or {}]
    # The error does not say which document failed, so name every link that
    # could plausibly be the culprit rather than guessing at the first.
    urls = [
        s.get("value")
        for s in sources
        if isinstance(s, dict) and str(s.get("kind", "")).endswith("url") and s.get("value")
    ]
    url = ", ".join(urls) if urls else None
    return Diagnosis(
        summary="That link is a documentation web page, not a machine-readable API spec.",
        cause=(
            "The parser was handed HTML and CSS where it expected JSON or YAML"
            + (f" ({url})" if url else "")
            + ". A rendered documentation page cannot be parsed deterministically; only "
            "an OpenAPI/Swagger file can. This is a limitation of the input, not a bug."
        ),
        steps=[
            Action(
                text="Find the raw specification file. It usually ends in .json or .yaml "
                "and is linked from the docs as 'OpenAPI', 'Swagger' or 'API reference'. "
                "Paste that URL instead."
            ),
            Action(
                text="If the provider publishes no spec, paste the documentation text "
                "itself rather than its URL. Freeform prose is sent to Gemini for "
                "synthesis, which tolerates pages that the strict parser cannot."
            ),
            Action(
                text="If the service already runs an MCP server, paste that endpoint "
                "instead -- its tool catalog is read directly and nothing is generated."
            ),
        ],
    )


def _mcp_requires_auth(_m: re.Match[str], _record: dict[str, Any]) -> Diagnosis:
    return Diagnosis(
        summary="The MCP server would not list its tools without credentials.",
        cause=(
            "The server was registered with NO_SPEC, meaning Gemini Enterprise knows the "
            "endpoint but not the tool catalog until a user authorizes. This is normal "
            "for servers that require OAuth and is not by itself a failure."
        ),
        steps=[
            Action(text="Complete the OAuth consent flow once from Gemini Enterprise; "
                        "the catalog is read with the user's token.")
        ],
    )


KNOWN_FAILURES: list[Rule] = [
    (
        "connector_missing_client_id",
        re.compile(r"params must contain client_id", re.IGNORECASE),
        _connector_missing_client_id,
    ),
    (
        "connector_param_shape",
        re.compile(
            r"[Dd]ata [Cc]onnector parameters must be one of:\s*(?P<allowed>[^b]+?)\s*but got",
        ),
        _connector_param_shape,
    ),
    (
        "connector_param_missing_token",
        re.compile(r"Missing Parameter Private App Access Token", re.IGNORECASE),
        _connector_param_shape,
    ),
    (
        "action_params_rejected",
        re.compile(r"actionParams must be one of|unsupported .*actionParams", re.IGNORECASE),
        _action_params_rejected,
    ),
    (
        "url_conflict",
        re.compile(r"already (exists|registered)|must be unique", re.IGNORECASE),
        _url_already_registered,
    ),
    (
        "api_not_enabled",
        re.compile(
            r"(?P<service>[a-z0-9.-]+\.googleapis\.com)[^.]{0,80}?"
            r"(has not been used|is disabled|not enabled)",
            re.IGNORECASE,
        ),
        _api_not_enabled,
    ),
    (
        "org_policy",
        re.compile(r"allowedPolicyMemberDomains|domain restricted sharing", re.IGNORECASE),
        _org_policy_public_invoker,
    ),
    (
        "permission_denied",
        re.compile(r"\b403\b|PERMISSION_DENIED|does not have permission", re.IGNORECASE),
        _permission_denied,
    ),
    (
        "docs_page_not_a_spec",
        re.compile(
            r"could not parse document as JSON or YAML"
            r"|rendered documentation page, not a spec"
            r"|document is HTML, not an OpenAPI document",
            re.IGNORECASE,
        ),
        _docs_page_not_a_spec,
    ),
    (
        "mcp_requires_auth",
        re.compile(r"requires authentication for tools/list", re.IGNORECASE),
        _mcp_requires_auth,
    ),
]


def failed_stage(record: dict[str, Any]) -> str | None:
    for stage in record.get("stages") or []:
        if not stage.get("ok"):
            return stage.get("stage")
    return None


def match_known(record: dict[str, Any]) -> Diagnosis | None:
    """First hand-written rule matching the error, if any."""
    error = record.get("error") or ""
    if not error:
        return None
    for rule_id, pattern, build in KNOWN_FAILURES:
        match = pattern.search(error)
        if match:
            diagnosis = build(match, record)
            diagnosis.source = "known"
            diagnosis.stage = failed_stage(record)
            log.info("diagnosis for %s matched rule %s", record.get("id"), rule_id)
            return diagnosis
    return None


# ---------------------------------------------------------------------------
# Model fallback
# ---------------------------------------------------------------------------

_SYSTEM = """\
You explain failures in a tool that provisions MCP servers on Google Cloud and \
connects them to Gemini Enterprise. Your audience is a competent engineer who \
does not know this tool's internals.

Rules:
- Say what to DO, not just what happened. Be specific: name consoles, commands,
  fields.
- If the failure is a defect in the tool rather than the user's configuration,
  say so plainly and set likely_app_bug true. Never invent a setup step for a
  problem the user cannot fix.
- Do not restate the raw error. Explain it.
- Prefer three precise steps to ten vague ones. Zero steps is correct when the
  user genuinely cannot act.
- Do not speculate beyond the evidence. If the cause is unclear, say which
  additional information would settle it.

Return ONLY a JSON object:
{"summary": str,           // one line, plain language
 "cause": str,             // why, in 1-4 sentences
 "likely_app_bug": bool,
 "steps": [{"text": str, "url": str|null, "cli": str|null}]}
"""

_USER_TEMPLATE = """\
The run failed at stage: {stage}

Error:
{error}

Stage history and effective configuration (secrets are already redacted as
`***`; treat them as present, not missing):
{context}
"""


class FailureExplainer:
    """Wraps the Gemini call. Injected so tests can substitute a fake."""

    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        self.settings = settings
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            from google import genai  # imported lazily; heavy dependency

            self._client = genai.Client(
                vertexai=True,
                project=self.settings.project_id,
                location=self.settings.gemini_location,
            )
        return self._client

    def _generate(self, prompt: str) -> str:
        from google.genai import types

        resp = self._get_client().models.generate_content(
            model=self.settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM,
                response_mime_type="application/json",
                temperature=0.1,
                # Generous on purpose. Gemini 2.5 spends output tokens on
                # reasoning before it emits anything, so a budget sized to the
                # visible answer gets consumed by thinking and the JSON is
                # truncated mid-string -- observed as "Unterminated string" on
                # a real failure, which silently degraded every model-backed
                # diagnosis to the raw-error fallback.
                max_output_tokens=8192,
            ),
        )
        return resp.text or ""

    def explain(self, record: dict[str, Any]) -> Diagnosis | None:
        context = {
            "stages": record.get("stages"),
            "config": record.get("config"),
            "requirements": record.get("requirements"),
        }
        blob = json.dumps(context, indent=2, default=str)[:MAX_CONTEXT_CHARS]
        prompt = _USER_TEMPLATE.format(
            stage=failed_stage(record) or "unknown",
            error=record.get("error") or "(none recorded)",
            context=blob,
        )
        payload = None
        for attempt in (1, 2):
            try:
                payload = json.loads(_strip_fences(self._generate(prompt)))
                break
            except json.JSONDecodeError as exc:
                # Usually a truncated reply. Retrying with an explicit brevity
                # instruction is cheaper than raising the budget again.
                log.warning(
                    "model diagnosis attempt %d for %s: %s", attempt, record.get("id"), exc
                )
                prompt += (
                    "\n\nYour previous reply was truncated or not valid JSON. "
                    "Reply again, more briefly, with only the JSON object."
                )
            except Exception as exc:  # noqa: BLE001 - never fail the caller
                log.warning("model diagnosis failed for %s: %s", record.get("id"), exc)
                return None
        if payload is None:
            return None

        steps = []
        for step in payload.get("steps") or []:
            if isinstance(step, dict) and step.get("text"):
                steps.append(
                    Action(
                        text=str(step["text"]),
                        url=step.get("url") or None,
                        cli=step.get("cli") or None,
                    )
                )
        return Diagnosis(
            summary=str(payload.get("summary") or "").strip() or "The run failed.",
            cause=str(payload.get("cause") or "").strip(),
            likely_app_bug=bool(payload.get("likely_app_bug")),
            steps=steps,
            stage=failed_stage(record),
            source="model",
        )


def _strip_fences(text: str) -> str:
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        return fence.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return text[start : end + 1]
    return text


def diagnose(
    record: dict[str, Any],
    settings: Settings,
    *,
    explainer: FailureExplainer | None = None,
    use_model: bool = True,
) -> Diagnosis:
    """Explain a failed run. Never raises: a bad explanation beats none.

    Hand-written rules win over the model: they are exact where the model would
    guess, and they can name a defect in this codebase, which the model cannot
    know about.
    """
    known = match_known(record)
    if known is not None:
        return known

    if use_model:
        explainer = explainer or FailureExplainer(settings)
        explained = explainer.explain(record)
        if explained is not None:
            return explained

    return Diagnosis(
        summary="The run failed and no explanation could be generated.",
        cause=record.get("error") or "",
        stage=failed_stage(record),
        source="none",
        confident=False,
        steps=[
            Action(
                text="Open the Configuration section below; the failing stage is expanded "
                "and shows the exact request that was rejected."
            )
        ],
    )
