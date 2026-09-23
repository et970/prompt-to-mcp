"""An agent that works out what the connector API currently wants.

Motivation
----------
The `connect` stage broke because this codebase held a wrong belief about an
undocumented v1alpha contract, and the API's own error messages actively
supported the wrong belief: a partial OAuth group is rejected with a generic
allow-list that names one arbitrary key and never mentions completeness, and a
missing group is reported as ``params must contain client_id`` -- naming a
field that ``params`` refuses.

Neither the test suite nor the runtime negotiation loop could recover from
that. Tests pin what we send. The loop hill-climbs one key at a time, so it can
never discover that four keys are required *together*.

What did work, when a human did it, was: read a working connector in the
project, diff it against what we send, form a hypothesis about the rule, and
test the hypothesis with a handful of probes. That is a search problem with
cheap feedback, which is what this module automates.

Why this is safe to run against a production project
----------------------------------------------------
``setUpDataConnector`` validates parameters *before* it checks for the
"Private App Access Token". A request that omits ``oauth_access_token`` is
therefore rejected no matter how correct everything else is -- verified: a
complete, valid OAuth group still returns *"Missing Parameter Private App
Access Token"*.

:class:`ProbeHarness` strips that token from every request. The agent's action
space is consequently unbounded and free: it cannot create a resource, cannot
incur cost, and cannot leave anything to clean up, however wrong it is.

That property is also the evidence gate. A probe whose only remaining complaint
is the missing token has, by definition, passed every parameter check -- so it
is a *proof* that the shape is accepted. The agent may only propose a shape it
has proven this way; a finding is never merely the model's opinion.

Authority
---------
Propose only. This module emits a :class:`ContractFinding` with its reasoning,
its probe transcript and a concrete suggested change. It does not modify the
connector builder, and nothing it produces reaches a provisioning run.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field

from .config import Settings
from .contract_knowledge import DISCOVERY_DOC_URL, render_briefing
from .gcp.base import GoogleApiError
from .gcp.discovery_engine import (
    BASE,
    BASE_ACTION_PARAMS,
    OAUTH_ACTION_PARAMS,
    REQUIRED_OAUTH_ACTION_PARAMS,
    DiscoveryEngineClient,
    error_message,
)

log = logging.getLogger(__name__)

#: Substring of the complaint that means the parameter checks passed and only
#: the deliberately-omitted setup token is missing.
_TOKEN_COMPLAINT = "private app access token"

#: Validation order, measured:
#:   1. actionParams allow-list / OAuth-group completeness
#:   2. params must contain oauth_access_token
#:   3. auth_type defaulting, and the credential demand that follows
#:
#: Step 3 is BEHIND the token check, so a token-less probe cannot reach it.
#: That matters: a shape with no `auth_type` at all passes 1 and stops at 2,
#: looking accepted -- and then fails in production with "For auth_type: OAUTH,
#: Connector params must contain client_id", which is precisely the bug that
#: caused the outage. Such a probe is therefore reported as inconclusive rather
#: than accepted, so the evidence gate cannot certify it.
_UNREACHABLE_WITHOUT_TOKEN = "auth_type"

#: Hard ceilings. The agent is bounded by probes rather than by tokens because
#: probes are the expensive-in-wall-clock part and the only part that touches
#: Google.
MAX_PROBES = 30
MAX_STEPS = 20


class ProbeOutcome(BaseModel):
    """One experiment against the live API."""

    params: list[str]
    action_params: dict[str, Any]
    #: ``shape_accepted`` means every parameter check passed.
    outcome: str
    message: str


class ContractFinding(BaseModel):
    """What the agent concluded, and the evidence for it."""

    #: One line an operator can act on.
    summary: str
    #: The rule the agent believes governs the contract.
    rule: str = ""
    #: An ``actionParams`` shape proven accepted by a probe. Empty if none was.
    verified_action_params: dict[str, Any] = Field(default_factory=dict)
    #: Concrete suggested change to the codebase.
    proposed_change: str = ""
    #: Every probe, in order. The transcript is the argument.
    probes: list[ProbeOutcome] = Field(default_factory=list)
    #: True only when a probe proved the proposed shape is accepted.
    verified: bool = False
    #: Differences found against connectors already working in the project.
    working_examples: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    #: ``agent`` or, when the model is unavailable, ``probes-only``.
    source: str = "agent"


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@dataclass
class ProbeHarness:
    """The agent's whole action surface. Every method is non-creating."""

    discovery: DiscoveryEngineClient
    max_probes: int = MAX_PROBES
    #: Cheap model for the grounded-search side call; the main loop stays on
    #: the configured reasoning model.
    search_model: str = "gemini-3.7-flash"
    probes: list[ProbeOutcome] = field(default_factory=list)
    #: Fetched once per investigation; it is ~2MB of JSON.
    _discovery_cache: dict[str, Any] | None = None
    #: Signature -> outcome. A repeated probe is answered from here rather than
    #: re-sent: an early version of this agent spent half its budget asking the
    #: same question three times, which is a failure mode worth designing out
    #: rather than hoping the model avoids.
    _seen: dict[str, ProbeOutcome] = field(default_factory=dict)

    @property
    def exhausted(self) -> bool:
        return len(self._seen) >= self.max_probes

    async def probe(
        self, params: dict[str, Any] | None, action_params: dict[str, Any]
    ) -> ProbeOutcome:
        """Send one ``setUpDataConnector`` variant and report the complaint.

        ``oauth_access_token`` is removed unconditionally. This is the safety
        interlock, not a convenience: with it absent the request cannot
        succeed, so no collection is ever created regardless of what the agent
        asks for.
        """
        safe_params = {
            k: v for k, v in (params or {}).items() if k.lower() != "oauth_access_token"
        }
        signature = json.dumps(
            {"p": safe_params, "a": action_params}, sort_keys=True, default=str
        )
        cached = self._seen.get(signature)
        if cached is not None:
            return cached.model_copy(
                update={"message": f"(already probed) {cached.message}"}
            )
        if self.exhausted:
            raise RuntimeError(f"probe budget of {self.max_probes} exhausted")
        body = {
            "collectionId": f"p2m-agent-{secrets.token_hex(4)}",
            "collectionDisplayName": "prompt-to-mcp contract agent probe (not created)",
            "dataConnector": {
                "dataSource": "custom_mcp",
                "connectorModes": ["FEDERATED"],
                "params": safe_params,
                "actionConfig": {
                    "actionParams": action_params,
                    "createBapConnection": True,
                },
                "entities": [{"entityName": "mcp_data"}],
            },
        }
        url = f"{BASE}/{self.discovery.parent}:setUpDataConnector"
        try:
            await self.discovery.api.post(url, json=body)
        except GoogleApiError as exc:
            message = error_message(exc)
            if _TOKEN_COMPLAINT not in message.lower():
                verdict, note = "rejected", message
            elif _UNREACHABLE_WITHOUT_TOKEN not in action_params:
                # Passed everything a token-less probe can exercise, but the
                # auth_type check sits behind the token check and would reject
                # this. Not provable safely, so not proved.
                verdict = "inconclusive"
                note = (
                    f"{message} -- NOTE: actionParams has no 'auth_type'. The server "
                    "defaults it to OAUTH and then demands credentials, but that check "
                    "runs after the setup-token check and a safe probe cannot reach it. "
                    "Set auth_type explicitly (NO_AUTH or a complete OAUTH group) and "
                    "probe again."
                )
            else:
                verdict, note = "shape_accepted", message
            outcome = ProbeOutcome(
                params=sorted(safe_params),
                action_params=action_params,
                outcome=verdict,
                message=note,
            )
        else:
            # Should be unreachable: the token is always absent. Treated as an
            # anomaly and cleaned up rather than trusted.
            log.error("agent probe was accepted despite having no setup token")
            await self._cleanup(body["collectionId"])
            outcome = ProbeOutcome(
                params=sorted(safe_params),
                action_params=action_params,
                outcome="created",
                message="unexpectedly accepted; the created collection was deleted",
            )
        self._seen[signature] = outcome
        self.probes.append(outcome)
        return outcome

    async def _cleanup(self, collection_id: str) -> None:
        try:
            await self.discovery.api.delete(
                f"{BASE}/{self.discovery.parent}/collections/{collection_id}"
            )
        except Exception:  # noqa: BLE001 - already anomalous; do not mask
            log.exception("could not delete agent probe collection %s", collection_id)

    async def search_docs(self, query: str, model: Any = None) -> dict[str, Any]:
        """Grounded web search, for generating hypotheses only.

        Deliberately a *separate* model call rather than a grounding tool on the
        main loop, for two reasons: mixing search grounding with function
        declarations is not reliably supported, and keeping it separate makes
        the epistemic boundary explicit. What comes back is labelled unverified
        and cannot, on its own, justify a conclusion.

        Google's documentation is measurably wrong about this data source -- see
        :mod:`prompt_to_mcp.contract_knowledge` -- so the result is returned
        with that warning attached rather than as a fact.
        """
        if model is None:
            return {"error": "no model available for search"}
        try:
            from google.genai import types

            resp = await asyncio.to_thread(
                model.generate_content,
                model=self.search_model,
                contents=(
                    "Answer only from search results, and quote the exact field "
                    f"names and JSON you find. If you find nothing specific, say so.\n\n{query}"
                ),
                config=types.GenerateContentConfig(
                    tools=[types.Tool(google_search=types.GoogleSearch())],
                    temperature=0.0,
                    max_output_tokens=2048,
                ),
            )
        except Exception as exc:  # noqa: BLE001 - advisory tool, never fatal
            log.warning("doc search failed: %s", exc)
            return {"error": str(exc)}

        citations: list[str] = []
        try:
            for candidate in resp.candidates or []:
                meta = getattr(candidate, "grounding_metadata", None)
                for chunk in getattr(meta, "grounding_chunks", None) or []:
                    web = getattr(chunk, "web", None)
                    if web is not None and getattr(web, "uri", None):
                        citations.append(web.uri)
        except Exception:  # noqa: BLE001 - citations are a nicety
            pass

        return {
            "answer": (resp.text or "")[:4000],
            "citations": citations[:10],
            "reliability": (
                "UNVERIFIED. Google's published docs are known to be wrong about "
                "custom_mcp -- in particular every worked example places client_id "
                "in dataConnector.params, which is rejected. Use this to form a "
                "hypothesis, then prove or disprove it with probe()."
            ),
        }

    async def resource_schema(self, resource: str) -> dict[str, Any]:
        """Field list for a Discovery Engine resource, from the discovery doc.

        Authoritative for *which fields exist*, which is a real question the
        error messages cannot answer -- it is how `federatedConfig` and
        `endUserConfig` were found and then ruled out by probing. Not
        authoritative for the untyped map fields, whose contents it reduces to
        "structured json format".
        """
        doc = await self._discovery_doc()
        if not doc:
            return {"error": "discovery document unavailable"}
        schemas = doc.get("schemas", {})
        wanted = resource.lower().replace("_", "").replace(".", "")
        for name, schema in schemas.items():
            short = name.replace("GoogleCloudDiscoveryengineV1alpha", "").lower()
            if short == wanted or name.lower() == resource.lower():
                return {
                    "resource": name,
                    "properties": {
                        k: {
                            "type": v.get("type") or v.get("$ref", ""),
                            "description": (v.get("description") or "")[:200],
                        }
                        for k, v in sorted(schema.get("properties", {}).items())
                    },
                }
        candidates = [
            n.replace("GoogleCloudDiscoveryengineV1alpha", "")
            for n in schemas
            if wanted in n.lower()
        ]
        return {"error": f"no schema named {resource!r}", "did_you_mean": candidates[:15]}

    async def _discovery_doc(self) -> dict[str, Any]:
        if self._discovery_cache is None:
            try:
                async with httpx.AsyncClient(timeout=30.0) as http:
                    resp = await http.get(DISCOVERY_DOC_URL)
                    resp.raise_for_status()
                    self._discovery_cache = resp.json()
            except Exception as exc:  # noqa: BLE001 - advisory tool
                log.warning("could not fetch discovery document: %s", exc)
                self._discovery_cache = {}
        return self._discovery_cache

    async def working_connectors(self) -> list[dict[str, Any]]:
        """Shapes of ``custom_mcp`` connectors that are already ACTIVE here.

        The highest-signal call available, and the one that solved this by
        hand: a working connector is a worked example of the current contract,
        which no error message and no documentation provides.
        """
        try:
            collections = await self.discovery.list_collections()
        except GoogleApiError as exc:
            log.warning("could not list collections: %s", exc)
            return []
        examples: list[dict[str, Any]] = []
        for collection in collections:
            dc = collection.get("dataConnector") or {}
            if dc.get("dataSource") != "custom_mcp":
                continue
            action_params = dict((dc.get("actionConfig") or {}).get("actionParams") or {})
            for key in ("client_secret", "oauth_access_token"):
                if key in action_params:
                    action_params[key] = "<redacted>"
            examples.append(
                {
                    "collection": collection.get("name", "").rsplit("/", 1)[-1],
                    "state": dc.get("state"),
                    "connector_type": dc.get("connectorType"),
                    # Read shape differs from write shape; say so rather than
                    # letting it be mistaken for something replayable.
                    "params_on_read": dc.get("params"),
                    "action_params": action_params,
                }
            )
        return examples


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------

_SYSTEM = """\
You are diagnosing the request contract of Google Discovery Engine's
`setUpDataConnector` for `dataSource: custom_mcp`. It is an undocumented
v1alpha surface with two untyped map fields, `dataConnector.params` and
`dataConnector.actionConfig.actionParams`.

Its error messages are unreliable and have caused a production outage:
- A rejection listing "parameters must be one of: ..." is a FALLBACK. It is
  emitted when a recognised parameter *group* is present but incomplete. Keys
  absent from that list may still be accepted as part of a complete group.
- "Connector params must contain client_id" names the wrong field. `params`
  rejects client_id outright.
So do not take a single message literally. Form a hypothesis about the rule and
test it.

EVIDENCE HIERARCHY. Sources are not equal, and this ordering is not negotiable:
  1. probe()                  -- the only thing that can VERIFY. Decisive.
  2. read_working_connectors  -- worked examples from this project. Very strong.
  3. read_schema              -- authoritative for which fields EXIST; silent on
                                 what the untyped maps accept.
  4. search_docs              -- hypothesis generation ONLY. Google's docs are
                                 measurably wrong about custom_mcp: every
                                 published worked example puts client_id in
                                 `params`, which is rejected. A document
                                 agreeing with you is not evidence. Anything it
                                 suggests must be probed before you believe it.
Never propose a shape on documentary grounds. If probe() did not accept it you
did not verify it, and claiming otherwise is worse than reporting that you could
not determine the answer.

Method, in this order:
0. Read the briefing below. It contains facts already proven, shapes already
   known good, and specific documented claims that are FALSE. Do not re-derive
   what is already proven; build on it.
1. Call read_working_connectors first. An ACTIVE connector is a worked example
   of the contract that no error message provides. Diff it against the shape
   the app currently sends.
2. Probe to test hypotheses. Probes are free and cannot create anything -- the
   setup token is always stripped, so the request always fails validation.
3. A probe with outcome "shape_accepted" means every reachable parameter check
   passed and only the omitted token remains. That is proof the shape is valid.
   Outcome "inconclusive" means it got that far but omits `auth_type`, whose
   check sits behind the token check where a safe probe cannot reach it -- such
   a shape fails in production. Always set auth_type explicitly.
4. Call propose exactly once when you have such a proof, or when the probe
   budget is nearly gone. Set verified_action_params to a shape you actually
   proved. Never claim a shape you did not probe.

Be concise. Prefer few, well-chosen probes over many random ones.
"""


def _tool_declarations() -> list[dict[str, Any]]:
    obj = {"type": "object"}
    return [
        {
            "name": "read_working_connectors",
            "description": (
                "List custom_mcp connectors already ACTIVE in this project, with their "
                "actionParams. Worked examples of the current contract. Call this first."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
        {
            "name": "probe",
            "description": (
                "Send one setUpDataConnector variant and return the API's complaint. "
                "Cannot create anything: the setup token is always stripped. Outcome "
                "'shape_accepted' proves every parameter check passed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action_params": {
                        **obj,
                        "description": "actionConfig.actionParams to send.",
                    },
                    "params": {**obj, "description": "dataConnector.params to send."},
                },
                "required": ["action_params"],
            },
        },
        {
            "name": "read_schema",
            "description": (
                "Field list for a Discovery Engine resource from the official discovery "
                "document, e.g. 'DataConnector' or 'ActionConfig'. Authoritative for "
                "which fields EXIST; says nothing about what untyped maps accept."
            ),
            "parameters": {
                "type": "object",
                "properties": {"resource": {"type": "string"}},
                "required": ["resource"],
            },
        },
        {
            "name": "search_docs",
            "description": (
                "Search Google's public documentation. HYPOTHESIS GENERATION ONLY -- "
                "the docs are known to be wrong about custom_mcp and their worked "
                "examples produce a rejected payload. Never conclude from this; probe it."
            ),
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
        {
            "name": "propose",
            "description": "Report the finding. Call exactly once, at the end.",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                    "rule": {
                        "type": "string",
                        "description": "The contract rule you inferred.",
                    },
                    "verified_action_params": {
                        **obj,
                        "description": "A shape a probe proved accepted. Omit if none.",
                    },
                    "proposed_change": {
                        "type": "string",
                        "description": "Concrete change to build_mcp_connector or the constants.",
                    },
                },
                "required": ["summary", "rule"],
            },
        },
    ]


class ContractAgent:
    """Bounded tool-using loop over :class:`ProbeHarness`.

    The model is injected the same way :class:`~prompt_to_mcp.diagnose.
    FailureExplainer` does it, so tests drive the loop with a scripted model and
    never touch Vertex.
    """

    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        self.settings = settings
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            from google import genai  # heavy; imported lazily

            self._client = genai.Client(
                vertexai=True,
                project=self.settings.project_id,
                location=self.settings.gemini_location,
            )
        return self._client

    def _turn(self, contents: list[Any]) -> Any:
        from google.genai import types

        return self._get_client().models.generate_content(
            model=self.settings.gemini_model,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM,
                tools=[types.Tool(function_declarations=_tool_declarations())],
                temperature=0.0,
                max_output_tokens=8192,
            ),
        )

    async def investigate(
        self, harness: ProbeHarness, *, context: str = ""
    ) -> ContractFinding:
        """Run the loop. Always returns a finding, even on model failure."""
        from google.genai import types

        # Ground the model in evidence before it forms any hypothesis.
        #
        # The first version of this agent was told to read working connectors
        # first and simply did not; it guessed instead, and proposed moving the
        # OAuth fields into `params` -- the exact opposite of the truth. The
        # human investigation only worked because it began from a connector
        # that was already ACTIVE. Making that a precondition rather than an
        # instruction removes the whole failure mode.
        seed = await self._seed(harness)

        opening = (
            "Work out what setUpDataConnector currently accepts for custom_mcp.\n\n"
            f"The app currently believes:\n"
            f"  base actionParams : {sorted(BASE_ACTION_PARAMS)}\n"
            f"  oauth group       : {sorted(OAUTH_ACTION_PARAMS)}\n"
            f"  required of group : {sorted(REQUIRED_OAUTH_ACTION_PARAMS)}\n\n"
            f"{render_briefing()}\n{seed}"
        )
        if context:
            opening += f"\nWhat just failed:\n{context}\n"

        contents: list[Any] = [
            types.Content(role="user", parts=[types.Part(text=opening)])
        ]

        for _step in range(MAX_STEPS):
            try:
                response = self._turn(contents)
            except Exception as exc:  # noqa: BLE001 - degrade, never raise
                log.warning("contract agent model call failed: %s", exc)
                return self._fallback(harness, f"the model was unavailable ({exc})")

            calls = list(getattr(response, "function_calls", None) or [])
            if not calls:
                return self._fallback(
                    harness, "the model stopped without proposing a finding"
                )

            contents.append(response.candidates[0].content)
            replies = []
            for call in calls:
                args = dict(call.args or {})
                if call.name == "propose":
                    return self._finalise(harness, args)
                result = await self._invoke(harness, call.name, args)
                replies.append(
                    types.Part.from_function_response(name=call.name, response=result)
                )
            contents.append(types.Content(role="user", parts=replies))

            if harness.exhausted:
                contents.append(
                    types.Content(
                        role="user",
                        parts=[
                            types.Part(
                                text="Probe budget exhausted. Call propose now with "
                                "what you have."
                            )
                        ],
                    )
                )
        return self._fallback(harness, f"no finding after {MAX_STEPS} steps")

    @staticmethod
    async def _seed(harness: ProbeHarness) -> str:
        """Facts gathered before the model speaks: worked examples, and the
        shapes the app itself sends, already probed.

        Two probes' worth of budget buys a baseline the model would otherwise
        have to find by luck -- and, crucially, one known-accepted shape, so it
        knows what success looks like before it starts varying things.
        """
        blocks: list[str] = []

        examples = await harness.working_connectors()
        if examples:
            blocks.append(
                "Connectors already ACTIVE in this project. These are worked "
                "examples of the current contract -- note that `params` is shown "
                "as READ BACK, which differs from what create accepts:\n"
                + json.dumps(examples, indent=2, default=str)[:4000]
            )
        else:
            blocks.append("No existing custom_mcp connectors to learn from.")

        # The two shapes the app builds today, already tested.
        baseline = {
            "mcp_server_source": "BYO_MCP",
            "instance_uri": "https://probe.invalid/mcp",
        }
        trials = {
            "what the app sends with no OAuth": {**baseline, "auth_type": "NO_AUTH"},
            "what the app sends with OAuth": {
                **baseline,
                "auth_type": "OAUTH",
                "client_id": "probe-client",
                "client_secret": "probe-secret",
                "auth_uri": "https://probe.invalid/authorize",
                "token_uri": "https://probe.invalid/token",
            },
        }
        results = []
        for label, shape in trials.items():
            try:
                outcome = await harness.probe({}, shape)
            except Exception as exc:  # noqa: BLE001 - seeding must not abort the run
                results.append(f"- {label}: probe failed ({exc})")
                continue
            results.append(
                f"- {label}: {outcome.outcome}\n"
                f"  actionParams: {json.dumps(shape, sort_keys=True)}\n"
                f"  response: {outcome.message[:200]}"
            )
        blocks.append("Baseline probes already run for you:\n" + "\n".join(results))
        return "\n\n".join(blocks) + "\n"

    async def _invoke(
        self, harness: ProbeHarness, name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            if name == "read_working_connectors":
                return {"connectors": await harness.working_connectors()}
            if name == "probe":
                outcome = await harness.probe(
                    args.get("params"), args.get("action_params") or {}
                )
                return outcome.model_dump()
            if name == "read_schema":
                return await harness.resource_schema(str(args.get("resource") or ""))
            if name == "search_docs":
                model = None
                try:
                    model = self._get_client().models
                except Exception as exc:  # noqa: BLE001 - search is optional
                    log.warning("no model for search_docs: %s", exc)
                return await harness.search_docs(str(args.get("query") or ""), model)
            return {"error": f"unknown tool {name!r}"}
        except Exception as exc:  # noqa: BLE001 - surfaced to the model, not fatal
            return {"error": str(exc)}

    def _finalise(self, harness: ProbeHarness, args: dict[str, Any]) -> ContractFinding:
        """Build the finding, and check the model's claim against the evidence."""
        claimed = dict(args.get("verified_action_params") or {})
        # The evidence gate. A shape counts as verified only if a probe actually
        # proved it -- the model asserting so is not sufficient, and a claim
        # that fails this check is downgraded rather than trusted.
        verified = any(
            p.outcome == "shape_accepted" and p.action_params == claimed
            for p in harness.probes
        )
        if claimed and not verified:
            log.warning("contract agent proposed an unproven shape; downgrading")
        return ContractFinding(
            summary=str(args.get("summary") or "no summary"),
            rule=str(args.get("rule") or ""),
            verified_action_params=claimed if verified else {},
            proposed_change=str(args.get("proposed_change") or ""),
            probes=harness.probes,
            verified=verified,
            source="agent",
        )

    @staticmethod
    def _fallback(harness: ProbeHarness, why: str) -> ContractFinding:
        """A finding assembled from probes alone.

        The transcript is worth keeping even when the model contributes
        nothing: an accepted shape is an accepted shape regardless of who
        described it.
        """
        proven = [p for p in harness.probes if p.outcome == "shape_accepted"]
        return ContractFinding(
            summary=f"No model-authored conclusion: {why}.",
            rule=(
                f"{len(proven)} probed shape(s) were accepted; see the transcript."
                if proven
                else "No accepted shape was found."
            ),
            verified_action_params=proven[-1].action_params if proven else {},
            probes=harness.probes,
            verified=bool(proven),
            source="probes-only",
        )


def summarise_for_operator(finding: ContractFinding) -> str:
    """Plain-text rendering, for a log line or a CLI."""
    lines = [finding.summary]
    if finding.rule:
        lines += ["", f"Rule: {finding.rule}"]
    if finding.verified_action_params:
        lines += [
            "",
            "Proven accepted actionParams:",
            json.dumps(finding.verified_action_params, indent=2, sort_keys=True),
        ]
    if finding.proposed_change:
        lines += ["", f"Proposed change: {finding.proposed_change}"]
    lines += ["", f"{len(finding.probes)} probe(s), none of which created anything."]
    return "\n".join(lines)
