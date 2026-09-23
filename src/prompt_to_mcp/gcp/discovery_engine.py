"""Discovery Engine / Gemini Enterprise (``discoveryengine.googleapis.com`` v1alpha).

Verified against the live discovery document and against two working
``custom_mcp`` connectors in a real project.

Key facts encoded here
----------------------
* ``Authorization.serverSideOauth2`` requires ``clientId``, ``clientSecret``,
  ``authorizationUri`` and ``tokenUri``. There is no DCR/public-client option --
  this is precisely why :mod:`prompt_to_mcp.oauth.proxy` exists.
* A remote MCP server is attached as a **collection with a data connector**,
  not as a plain data store:
  ``dataSource="custom_mcp"``, ``connectorType="THIRD_PARTY_FEDERATED"``,
  ``connectorModes=["FEDERATED"]``, ``params.oauth_access_token=<setup token>``,
  and ``actionConfig.actionParams`` holding ``mcp_server_source="BYO_MCP"`` plus
  ``instance_uri=<mcp url>``. Setup creates a data store named
  ``<collection_id>_mcp_data``.
* ``actionParams`` takes **no** OAuth configuration -- see
  :data:`SUPPORTED_ACTION_PARAMS`. Credential propagation is driven entirely by
  the ``Authorization`` resource bound to the agent.
* ``setUpDataConnector`` lives at the **location** level
  (``/locations/{loc}:setUpDataConnector``), not under ``collections``.
* Everything must go through the ``global`` endpoint and ``locations/global``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Callable
from typing import Any

from .base import GoogleApiClient, GoogleApiError

log = logging.getLogger(__name__)

BASE = "https://discoveryengine.googleapis.com/v1alpha"

#: Hard cap on the request-negotiation loop in
#: :meth:`DiscoveryEngineClient.set_up_mcp_connector`.
#:
#: ``custom_mcp`` is a v1alpha surface whose required request shape has changed
#: under us more than once, and its ``params`` map is untyped, so no discovery
#: document can tell us what it wants. What it *does* do is name the offending
#: field in the 400. That makes the shape negotiable: send a body, read the
#: complaint, amend, resend. Each iteration is one real API call and the loop
#: only continues while the server keeps naming a field it wants changed, so it
#: converges in one or two rounds. The cap bounds a server that contradicts
#: itself rather than the normal path.
MAX_PARAM_NEGOTIATION_ATTEMPTS = 4

#: ``actionConfig.actionParams`` keys accepted outside of an OAuth group.
#:
#: This is the list the server names when it rejects something::
#:
#:     Data Connector parameters must be one of: instance_uri,
#:     use_agent_gateway_egress, agent_gateway_engine, tool_list,
#:     mcp_server_source, registry_mcp_server_name but got: auth_uri_params
#:
#: That message is misleading, and believing it literally is what broke this
#: code. It is a *fallback*: it is emitted when the OAuth configuration group
#: (:data:`OAUTH_ACTION_PARAMS`) is present but incomplete. A complete group is
#: accepted even though none of its keys appear in the list above. Verified
#: against the live API -- see :data:`OAUTH_ACTION_PARAMS`.
BASE_ACTION_PARAMS: frozenset[str] = frozenset(
    {
        "agent_gateway_engine",
        "instance_uri",
        "mcp_server_source",
        "registry_mcp_server_name",
        "tool_list",
        "use_agent_gateway_egress",
    }
)

#: The OAuth configuration group, which the connector accepts **all or
#: nothing**. Verified key by key against the live API:
#:
#: ===================================================== ========
#: ``actionParams``                                      result
#: ===================================================== ========
#: ``auth_type,client_id,auth_uri,token_uri``            accepted
#: ``… minus client_secret``                             accepted
#: ``… minus client_id``                                 rejected
#: ``auth_type,client_id,client_secret`` (no URIs)       rejected
#: ``auth_type,client_id,client_secret,auth_uri``        rejected
#: ``auth_type,client_id,client_secret,token_uri``       rejected
#: ``auth_type:NO_AUTH`` alone                           accepted
#: ===================================================== ========
#:
#: A partial group falls through to the generic allow-list error above, which
#: names one arbitrary key and gives no hint that the problem is incompleteness
#: rather than the key itself. That is precisely the trap this codebase fell
#: into: it saw ``but got: auth_uri_params``, concluded OAuth keys were banned
#: outright, and stopped sending all of them -- which made every OAuth
#: connector fail, because omitting ``auth_type`` makes the server default it
#: to ``OAUTH`` and then demand the credentials it was just told not to send.
OAUTH_ACTION_PARAMS: frozenset[str] = frozenset(
    {
        "auth_type",
        "auth_uri",
        "auth_uri_params",
        "client_id",
        "client_secret",
        "scopes",
        "token_uri",
    }
)

#: Without these the server rejects an ``auth_type=OAUTH`` connector.
REQUIRED_OAUTH_ACTION_PARAMS: frozenset[str] = frozenset(
    {"auth_type", "auth_uri", "client_id", "token_uri"}
)

#: Everything :meth:`DiscoveryEngineClient.build_mcp_connector` may send.
SUPPORTED_ACTION_PARAMS: frozenset[str] = BASE_ACTION_PARAMS | OAUTH_ACTION_PARAMS

#: ``dataConnector.params`` takes exactly this on create, in every auth mode.
#: ``client_id`` is **not** accepted here despite the error message that says
#: ``Connector params must contain client_id`` -- that complaint is about the
#: connector's OAuth configuration, which lives in ``actionParams``.
SUPPORTED_PARAMS: frozenset[str] = frozenset({"oauth_access_token"})

_PARAM_REJECTION_RE = re.compile(
    r"parameters must be one of:\s*(?P<allowed>.*?)\s*but got:\s*(?P<got>.*?)\s*\.?$",
    re.IGNORECASE | re.DOTALL,
)

#: The "you left something out" half of the vocabulary, as in
#: ``For auth_type: OAUTH, Connector params must contain client_id.``
_MISSING_PARAMS_RE = re.compile(
    r"params must contain\s+(?P<keys>[A-Za-z0-9_,\s]+?)\s*\.?\s*$",
    re.IGNORECASE,
)

#: The same complaint phrased as prose, as in ``Missing Parameter Private App
#: Access Token for Custom MCP Server data source.`` The API is inconsistent
#: about whether it names the wire key or the human label.
_MISSING_NAMED_PARAM_RE = re.compile(r"missing parameter\s+(?P<label>.+?)\s+for\b", re.IGNORECASE)

#: Prose labels the API uses for connector params, mapped back to wire keys.
_PARAM_LABELS: dict[str, str] = {
    "private app access token": "oauth_access_token",
}


def _split_keys(text: str) -> list[str]:
    return [p for p in re.split(r"[,\s]+", text.strip()) if p and p.lower() != "and"]


def parse_param_rejection(message: str) -> tuple[list[str], list[str]] | None:
    """Pull the allowed/rejected key lists out of a Data Connector 400.

    Returns ``(allowed, rejected)`` or ``None`` if the message is not one of
    these. The allowed list is authoritative and current, which makes it worth
    surfacing verbatim: it is the only published description of this field.
    """
    match = _PARAM_REJECTION_RE.search(message or "")
    if match is None:
        return None
    return _split_keys(match.group("allowed")), _split_keys(match.group("got"))


def parse_missing_params(message: str) -> list[str]:
    """Names of connector params the API says are absent.

    The counterpart to :func:`parse_param_rejection`: that one reports keys to
    drop, this one reports keys to add. Together they are enough to converge on
    the shape the server currently wants without anyone editing this file.
    """
    text = (message or "").strip()
    match = _MISSING_PARAMS_RE.search(text)
    if match is not None:
        return _split_keys(match.group("keys"))
    named = _MISSING_NAMED_PARAM_RE.search(text)
    if named is not None:
        key = _PARAM_LABELS.get(named.group("label").strip().lower())
        if key:
            return [key]
    return []


def error_message(exc: GoogleApiError) -> str:
    """The server's own prose out of a :class:`GoogleApiError`."""
    payload = exc.payload if isinstance(exc.payload, dict) else {}
    return str(payload.get("error", {}).get("message") or exc)


class DiscoveryEngineClient:
    def __init__(self, api: GoogleApiClient, project_id: str, location: str = "global") -> None:
        self.api = api
        self.project_id = project_id
        self.location = location

    @property
    def parent(self) -> str:
        return f"projects/{self.project_id}/locations/{self.location}"

    # ------------------------------------------------------------------
    # Authorizations -- credential propagation
    # ------------------------------------------------------------------
    async def create_authorization(
        self,
        authorization_id: str,
        *,
        display_name: str,
        client_id: str,
        client_secret: str,
        authorization_uri: str,
        token_uri: str,
        scopes: list[str] | None = None,
        pkce: bool = True,
    ) -> dict[str, Any]:
        """Create (or replace) an Authorization resource.

        ``authorization_uri`` must be a complete authorization request URL --
        the API's own documentation states it "should include everything
        required for a successful authorization: OAuth ID, extra flags, etc."
        The ``redirect_uri`` query parameter is overwritten by the Gemini
        Enterprise frontend, so we deliberately do not set one.
        """
        body = {
            "displayName": display_name[:128],
            "serverSideOauth2": {
                "clientId": client_id,
                "clientSecret": client_secret,
                "authorizationUri": authorization_uri,
                "tokenUri": token_uri,
                "pkceVerificationEnabled": pkce,
                **({"scopes": scopes} if scopes else {}),
            },
        }
        url = f"{BASE}/{self.parent}/authorizations"
        try:
            return await self.api.post(url, json=body, params={"authorizationId": authorization_id})
        except GoogleApiError as exc:
            if exc.status != 409:
                raise
            log.info("authorization %s exists; patching", authorization_id)
            return await self.api.patch(
                f"{BASE}/{self.parent}/authorizations/{authorization_id}",
                json=body,
                params={"updateMask": "displayName,serverSideOauth2"},
            )

    async def get_authorization(self, authorization_id: str) -> dict[str, Any]:
        return await self.api.get(f"{BASE}/{self.parent}/authorizations/{authorization_id}")

    async def delete_authorization(self, authorization_id: str) -> None:
        await self.api.delete(f"{BASE}/{self.parent}/authorizations/{authorization_id}")

    # ------------------------------------------------------------------
    # Remote MCP as a federated data connector
    # ------------------------------------------------------------------
    @staticmethod
    def split_action_params(
        params: dict[str, Any],
        *,
        supported: frozenset[str] = SUPPORTED_ACTION_PARAMS,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Partition ``actionParams`` into ``(accepted, rejected)``.

        Sending a rejected key is a hard 400 that fails the whole
        ``setUpDataConnector`` call, so they are dropped rather than sent. The
        rejected half is returned instead of discarded so the caller can record
        it -- silently swallowing configuration the operator supplied would be
        worse than the 400 it avoids.
        """
        accepted = {k: v for k, v in params.items() if k in supported}
        rejected = {k: v for k, v in params.items() if k not in supported}
        return accepted, rejected

    @staticmethod
    def build_oauth_action_params(
        *,
        client_id: str,
        authorization_endpoint: str,
        token_endpoint: str,
        client_secret: str = "",
        scopes: list[str] | None = None,
        authorization_uri_params: str = "",
    ) -> dict[str, Any]:
        """The connector's OAuth group, or ``{"auth_type": "NO_AUTH"}``.

        ``auth_type`` is always set. Omitting it is not neutral: the server
        defaults it to ``OAUTH`` and then rejects the connector for lacking
        credentials, which is the failure this function exists to prevent.

        ``authorization_endpoint`` must be the bare endpoint. The full
        authorization *request* URL -- with ``client_id`` and ``scope`` in the
        query string -- is what the ``Authorization`` resource wants; the
        connector takes the pieces separately and assembles its own.
        """
        if not (client_id and authorization_endpoint and token_endpoint):
            # A partial group is worse than none: the server rejects it with a
            # message naming one arbitrary key, which reads like that key is
            # forbidden rather than like something is missing.
            return {"auth_type": "NO_AUTH"}
        params: dict[str, Any] = {
            "auth_type": "OAUTH",
            "client_id": client_id,
            "auth_uri": authorization_endpoint,
            "token_uri": token_endpoint,
        }
        if client_secret:
            params["client_secret"] = client_secret
        if scopes:
            params["scopes"] = " ".join(scopes)
        if authorization_uri_params:
            params["auth_uri_params"] = authorization_uri_params
        return params

    @staticmethod
    def build_mcp_connector(
        *,
        mcp_url: str,
        setup_access_token: str = "",
        oauth_action_params: dict[str, Any] | None = None,
        extra_action_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Assemble the ``custom_mcp`` DataConnector body.

        ``actionConfig.actionParams`` is an untyped ``map<string, any>`` in the
        v1alpha schema, so it cannot be validated against a discovery document;
        :data:`SUPPORTED_ACTION_PARAMS` transcribes the server's own rejection
        message instead. Only two keys are needed for a bring-your-own MCP:

        ``mcp_server_source="BYO_MCP"``
            Selects the BYO path over a Google-hosted or registry-sourced one.
        ``instance_uri``
            The MCP endpoint Gemini Enterprise will call.
        ``auth_type`` and, for OAuth, its whole group
            Built by :meth:`build_oauth_action_params`. Always present: an
            absent ``auth_type`` is treated as ``OAUTH`` by the server.

        ``setup_access_token`` is the "Private App Access Token" Gemini
        Enterprise uses for its initial handshake with the MCP server. It is
        required at create time even when the connector needs no credentials.

        ``extra_action_params`` is an escape hatch for keys this codebase does
        not model yet (``registry_mcp_server_name``, ``agent_gateway_engine``,
        ``tool_list``, ``use_agent_gateway_egress``). Unsupported keys are
        dropped with a warning rather than sent.
        """
        desired: dict[str, Any] = {
            "mcp_server_source": "BYO_MCP",
            "instance_uri": mcp_url,
            **(oauth_action_params or {"auth_type": "NO_AUTH"}),
            **(extra_action_params or {}),
        }
        action_params, rejected = DiscoveryEngineClient.split_action_params(desired)
        if rejected:
            log.warning(
                "dropping unsupported custom_mcp actionParams %s; supported keys are %s",
                sorted(rejected),
                sorted(SUPPORTED_ACTION_PARAMS),
            )

        # Catch an incomplete OAuth group here, where the cause is obvious,
        # rather than letting the server reject it with a message that names an
        # arbitrary key and reads like that key is forbidden.
        if action_params.get("auth_type") == "OAUTH":
            missing = sorted(REQUIRED_OAUTH_ACTION_PARAMS - set(action_params))
            if missing:
                raise ValueError(
                    f"incomplete OAuth connector configuration: missing {missing}. "
                    "The API accepts this group all-or-nothing and reports a partial "
                    "one as an unrelated 'parameters must be one of' error."
                )
        # `params` is WRITE-DIFFERENT FROM READ, which is a genuine trap.
        #
        # On create it accepts a narrow set of keys. Anything outside it is
        # rejected with:
        #   "Data Connector parameters must be one of: oauth_access_token
        #    but got: instance_uri"
        # omitting a required one gives either:
        #   "Missing Parameter Private App Access Token for Custom MCP
        #    Server data source."
        # or:
        #   "For auth_type: OAUTH, Connector params must contain client_id."
        #
        # After creation the backend DISCARDS the token from `params` and
        # substitutes `{"instance_uri": ...}`, which is what you see when
        # reading an existing connector. Copying the read shape back into a
        # create call therefore fails -- verified against the live API.
        #
        # `client_id` does NOT belong here, despite the API saying "Connector
        # params must contain client_id" when it is missing: that complaint is
        # about `actionParams.auth_type=OAUTH` lacking its group. Putting it in
        # `params` is rejected with "must be one of: oauth_access_token but
        # got: client_id" -- the two messages together make the field look
        # simultaneously required and forbidden. Verified both ways.
        params: dict[str, Any] = {"oauth_access_token": setup_access_token}

        return {
            # `connectorType` is deliberately NOT set: the schema marks it
            # output-only ("Each source can only map to one type"), so the
            # server derives THIRD_PARTY_FEDERATED from dataSource=custom_mcp.
            # Sending it risks an INVALID_ARGUMENT on create.
            "dataSource": "custom_mcp",
            "connectorModes": ["FEDERATED"],
            "params": params,
            "actionConfig": {
                "actionParams": action_params,
                "createBapConnection": True,
            },
            "entities": [{"entityName": "mcp_data"}],
        }

    # ------------------------------------------------------------------
    # Request negotiation
    # ------------------------------------------------------------------
    @staticmethod
    def amend_connector_body(
        message: str, body: dict[str, Any], pool: dict[str, Any]
    ) -> tuple[dict[str, Any], str] | None:
        """Rewrite a rejected ``setUpDataConnector`` body per the server's complaint.

        Returns the amended body and a human description of the change, or
        ``None`` when the message names nothing actionable -- either it is not
        a shape complaint at all, or it demands a value we do not hold.

        ``pool`` is the set of values this run is allowed to supply if asked.
        Nothing is invented: a key the server demands but the pool cannot
        satisfy is a real failure and is reported as one.
        """
        connector = dict(body.get("dataConnector") or {})
        params = dict(connector.get("params") or {})
        action_config = dict(connector.get("actionConfig") or {})
        action_params = dict(action_config.get("actionParams") or {})

        def rebuild() -> dict[str, Any]:
            amended = dict(body)
            new_connector = dict(connector)
            new_connector["params"] = params
            if action_config or action_params:
                new_action = dict(action_config)
                new_action["actionParams"] = action_params
                new_connector["actionConfig"] = new_action
            amended["dataConnector"] = new_connector
            return amended

        missing = parse_missing_params(message)
        if missing:
            # Only keys we can actually fill, and only ones not already sent --
            # re-sending a value the server just called absent would spin.
            fillable = [k for k in missing if k in pool and k not in params]
            if len(fillable) != len(missing):
                return None
            for key in fillable:
                params[key] = pool[key]
            return rebuild(), f"added {sorted(fillable)} to params"

        rejection = parse_param_rejection(message)
        if rejection is None:
            return None
        _allowed, rejected = rejection
        # The same sentence is used for both maps, so let the body disambiguate:
        # whichever one actually holds the offending keys is the one at fault.
        in_params = [k for k in rejected if k in params]
        in_action = [k for k in rejected if k in action_params]
        if in_params:
            for key in in_params:
                params.pop(key, None)
            return rebuild(), f"removed {sorted(in_params)} from params"
        if in_action:
            for key in in_action:
                action_params.pop(key, None)
            return rebuild(), f"removed {sorted(in_action)} from actionConfig.actionParams"
        return None

    async def set_up_mcp_connector(
        self,
        *,
        collection_id: str,
        display_name: str,
        connector: dict[str, Any],
        param_pool: dict[str, Any] | None = None,
        wait: bool = True,
        on_attempt: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Create the collection + connector. Returns the LRO or its result.

        A 400 that names a connector param is not treated as terminal. The
        server's complaint is a description of the shape it wants, so the body
        is amended from ``param_pool`` and resent, up to
        :data:`MAX_PARAM_NEGOTIATION_ATTEMPTS` times. This is what keeps an
        undocumented v1alpha surface changing under us from becoming a user's
        problem -- the values it asks for are ones this run already minted.

        ``on_attempt`` receives a JSON-safe summary of every round so the
        caller can persist the negotiation alongside the run. Values are never
        passed to it, only key names.
        """
        pool = dict(param_pool or {})
        body: dict[str, Any] = {
            "collectionId": collection_id,
            "collectionDisplayName": display_name[:1024],
            "dataConnector": connector,
        }
        url = f"{BASE}/{self.parent}:setUpDataConnector"
        operation = await self._post_negotiated(url, body, pool, on_attempt)
        name = operation.get("name", "")
        if wait and "/operations/" in name:
            try:
                return await self.api.poll_operation(
                    f"{BASE}/{name}", interval=5.0, timeout=1800.0
                )
            except GoogleApiError as exc:
                if exc.status != 404:
                    raise
                # Verified against the live API: setUpDataConnector returns an
                # LRO named `.../operations/create-data-connector-sync-lro-*`
                # that is NOT retrievable by GET -- polling it 404s even though
                # the connector goes on to reach ACTIVE with its data store
                # created. Resource-level polling via wait_for_mcp_datastore is
                # the authoritative signal, so a missing LRO is not an error.
                log.info(
                    "setUpDataConnector LRO %s is not retrievable (expected); "
                    "falling back to polling the connector resource",
                    name,
                )
        return operation

    async def _post_negotiated(
        self,
        url: str,
        body: dict[str, Any],
        pool: dict[str, Any],
        on_attempt: Callable[[dict[str, Any]], None] | None,
    ) -> dict[str, Any]:
        """POST ``body``, amending it from ``pool`` for as long as the server
        keeps naming a param it wants changed."""
        attempts: list[dict[str, Any]] = []
        seen: set[str] = set()
        last_exc: GoogleApiError | None = None

        def signature(candidate: dict[str, Any]) -> str:
            return json.dumps(candidate, sort_keys=True, default=str)

        def report(entry: dict[str, Any]) -> None:
            attempts.append(entry)
            if on_attempt is not None:
                try:
                    on_attempt(entry)
                except Exception:  # noqa: BLE001 - reporting must not fail the call
                    log.warning("connector attempt callback failed", exc_info=True)

        for attempt in range(1, MAX_PARAM_NEGOTIATION_ATTEMPTS + 1):
            seen.add(signature(body))
            sent_params = sorted((body.get("dataConnector", {}) or {}).get("params", {}))
            try:
                operation = await self.api.post(url, json=body)
            except GoogleApiError as exc:
                last_exc = exc
                message = error_message(exc)
                entry = {
                    "attempt": attempt,
                    "params": sent_params,
                    "status": exc.status,
                    "error": message,
                }
                amended = self.amend_connector_body(message, body, pool)
                if amended is None:
                    entry["outcome"] = "not a param-shape complaint; giving up"
                    report(entry)
                    break
                candidate, action = amended
                if signature(candidate) in seen:
                    # The server rejected a body, we changed it as instructed,
                    # and arrived back at something already refused. Continuing
                    # would just alternate between two rejected shapes.
                    entry["outcome"] = f"{action}, but that body was already refused; giving up"
                    report(entry)
                    break
                entry["outcome"] = action
                report(entry)
                log.warning(
                    "setUpDataConnector attempt %d rejected (%s); %s and retrying",
                    attempt,
                    message,
                    action,
                )
                body = candidate
                continue

            report(
                {"attempt": attempt, "params": sent_params, "status": 200, "outcome": "accepted"}
            )
            if attempt > 1:
                log.info("setUpDataConnector converged after %d attempts", attempt)
            return operation

        if last_exc is None:  # pragma: no cover - loop always sets it before breaking
            raise RuntimeError("connector negotiation ended without a result")
        raise self._explain(last_exc, body, attempts) from last_exc

    @staticmethod
    def _explain(
        exc: GoogleApiError,
        body: dict[str, Any],
        attempts: list[dict[str, Any]] | None = None,
    ) -> Exception:
        """Turn a Data Connector 400 into something actionable.

        The raw error names one offending key and one moment in time. What the
        operator needs is the delta between what we sent and what the API now
        accepts -- including the possibility that
        :data:`SUPPORTED_ACTION_PARAMS` is simply out of date, which this
        message says outright rather than leaving them to infer it.

        When negotiation ran, the transcript is appended: a 400 that survived
        three amended bodies means something different from one that failed
        outright, and the difference is not recoverable from the last message.
        """
        original = error_message(exc)
        lines: list[str] = []

        missing = parse_missing_params(original)
        rejection = parse_param_rejection(original)

        action_params = (body.get("dataConnector", {}).get("actionConfig", {}) or {}).get(
            "actionParams", {}
        ) or {}

        if missing and set(missing) & OAUTH_ACTION_PARAMS:
            # The single most misleading error this API produces. It says
            # `params` is missing an OAuth field; `params` rejects that field.
            # What it actually means is that `actionParams` declared (or
            # defaulted to) auth_type=OAUTH without a complete OAuth group.
            absent = sorted(REQUIRED_OAUTH_ACTION_PARAMS - set(action_params))
            lines = [
                original,
                "",
                "This message names the wrong field. `dataConnector.params` does not "
                f"accept {missing} -- it takes only {sorted(SUPPORTED_PARAMS)}. The "
                "connector's OAuth configuration lives in "
                "`actionConfig.actionParams`, which the API accepts all-or-nothing.",
                "",
                f"Sent actionParams: {sorted(action_params) or '(none)'}",
                f"auth_type: {action_params.get('auth_type') or '(unset -> defaults to OAUTH)'}",
                f"Missing from the OAuth group: {absent or '(none)'}",
                "",
                "Either supply the full group (auth_type, client_id, auth_uri, token_uri) "
                "or set auth_type=NO_AUTH.",
            ]
        elif missing:
            sent = sorted((body.get("dataConnector", {}) or {}).get("params", {}))
            lines = [
                original,
                "",
                f"Sent params: {sent or '(none)'}",
                f"Demanded but not available to this run: {missing}",
                "",
                "The connector body is negotiated from the API's own error messages, so "
                "this is not a stale constant -- it is a value the run never had. It has "
                "to be threaded into `param_pool` at the pipeline's connect stage.",
            ]
        elif rejection is not None:
            allowed, rejected = rejection
            sent = sorted(
                (body.get("dataConnector", {}).get("actionConfig", {}) or {}).get(
                    "actionParams", {}
                )
            )
            # Compared against the base list, not the full supported set: the
            # message's allow-list is the fallback used when no complete OAuth
            # group is present, so it legitimately omits every OAuth key.
            stale = sorted(set(allowed) - BASE_ACTION_PARAMS)
            gone = sorted(BASE_ACTION_PARAMS - set(allowed))
            lines = [
                original,
                "",
                f"Sent actionParams: {sent or '(none)'}",
                f"Rejected: {rejected}",
                f"Accepted by the API right now: {allowed}",
            ]
            if stale or gone:
                lines += [
                    "",
                    "The API's accepted set no longer matches BASE_ACTION_PARAMS in "
                    "prompt_to_mcp/gcp/discovery_engine.py -- update it.",
                    f"  newly accepted: {stale or '(none)'}",
                    f"  no longer accepted: {gone or '(none)'}",
                ]

        if attempts and len(attempts) > 1:
            lines = lines or [original]
            lines += ["", f"Negotiated {len(attempts)} request shape(s) before giving up:"]
            lines += [
                f"  {a['attempt']}. params={a['params'] or '(none)'} -> "
                f"{a.get('status')} {a.get('outcome', '')}".rstrip()
                for a in attempts
            ]

        if not lines:
            return exc
        return GoogleApiError(exc.status, {"error": {"message": "\n".join(lines)}}, exc.url)

    async def get_data_connector(self, collection_id: str) -> dict[str, Any]:
        return await self.api.get(f"{BASE}/{self.parent}/collections/{collection_id}/dataConnector")

    async def list_collections(self) -> list[dict[str, Any]]:
        payload = await self.api.get(f"{BASE}/{self.parent}/collections")
        return payload.get("collections", [])

    async def wait_for_mcp_datastore(
        self, collection_id: str, *, timeout: float = 900.0, interval: float = 10.0
    ) -> str:
        """Block until the connector materialises its ``mcp_data`` data store."""
        deadline = time.monotonic() + timeout
        last_state = "?"
        while time.monotonic() < deadline:
            try:
                connector = await self.get_data_connector(collection_id)
            except GoogleApiError as exc:
                if exc.status != 404:
                    raise
                connector = {}
            last_state = connector.get("state", "?")
            for entity in connector.get("entities", []):
                if entity.get("entityName") == "mcp_data" and entity.get("dataStore"):
                    return entity["dataStore"]
            if last_state in ("ERROR", "FAILED"):
                raise RuntimeError(
                    f"connector {collection_id} entered state {last_state}: "
                    f"{connector.get('errors')}"
                )
            await asyncio.sleep(interval)
        raise TimeoutError(
            f"data store for collection {collection_id} not ready within {timeout}s "
            f"(last state {last_state})"
        )

    # ------------------------------------------------------------------
    # Attaching to a Gemini Enterprise app (Engine)
    # ------------------------------------------------------------------
    async def get_engine(
        self, engine_id: str, collection: str = "default_collection"
    ) -> dict[str, Any]:
        return await self.api.get(
            f"{BASE}/{self.parent}/collections/{collection}/engines/{engine_id}"
        )

    async def list_engines(
        self, collection: str = "default_collection"
    ) -> list[dict[str, Any]]:
        """The Gemini Enterprise apps in this project, as ``{id, display_name}``.

        Exists so the UI can offer a list instead of asking the operator to open
        the console, find an app and copy its ID into a text box. The bare id is
        what ``CreateMcpRequest.gemini_enterprise_engine_id`` wants, so the
        trailing path segment is extracted here rather than at each call site.
        """
        payload = await self.api.get(
            f"{BASE}/{self.parent}/collections/{collection}/engines"
        )
        engines = []
        for engine in payload.get("engines", []):
            name = engine.get("name", "")
            engine_id = name.rsplit("/", 1)[-1]
            if not engine_id:
                continue
            engines.append(
                {
                    "id": engine_id,
                    "display_name": engine.get("displayName") or engine_id,
                    "name": name,
                }
            )
        return engines

    async def attach_datastore_to_engine(
        self,
        engine_id: str,
        datastore: str,
        *,
        collection: str = "default_collection",
    ) -> dict[str, Any]:
        """Add a data store to a Gemini Enterprise app.

        ``dataStoreIds`` holds bare IDs, not full resource names, so the
        trailing path segment is extracted. Search/recommendation engines only
        accept a single data store; chat/assistant engines accept many.
        """
        engine = await self.get_engine(engine_id, collection)
        existing: list[str] = list(engine.get("dataStoreIds") or [])
        datastore_id = datastore.rstrip("/").split("/")[-1]

        if datastore_id in existing:
            log.info("data store %s already attached to engine %s", datastore_id, engine_id)
            return engine

        existing.append(datastore_id)
        return await self.api.patch(
            f"{BASE}/{self.parent}/collections/{collection}/engines/{engine_id}",
            json={"dataStoreIds": existing},
            params={"updateMask": "dataStoreIds"},
        )

    async def detach_datastore_from_engine(
        self,
        engine_id: str,
        datastore: str,
        *,
        collection: str = "default_collection",
    ) -> dict[str, Any]:
        """Remove a data store from a Gemini Enterprise app.

        Required before the data store's collection can be deleted. Without it
        the collection is permanently undeletable::

            DataStore <id> currently exists in list at index 12 of Engine <name>

        which leaves the operator with an orphaned entry in their app and a
        collection they cannot remove -- found by running a teardown for real.
        """
        engine = await self.get_engine(engine_id, collection)
        existing: list[str] = list(engine.get("dataStoreIds") or [])
        datastore_id = datastore.rstrip("/").split("/")[-1]

        if datastore_id not in existing:
            return engine
        return await self.api.patch(
            f"{BASE}/{self.parent}/collections/{collection}/engines/{engine_id}",
            json={"dataStoreIds": [d for d in existing if d != datastore_id]},
            params={"updateMask": "dataStoreIds"},
        )

    async def delete_collection(self, collection_id: str) -> dict[str, Any]:
        """Delete a collection and the data connector inside it."""
        return await self.api.delete(f"{BASE}/{self.parent}/collections/{collection_id}")

    async def attach_authorization_to_agent(
        self,
        *,
        engine_id: str,
        assistant_id: str,
        agent_id: str,
        authorization: str,
        collection: str = "default_collection",
        agent_authorization: bool = False,
    ) -> dict[str, Any]:
        """Wire an authorization resource onto an agent for credential propagation.

        ``toolAuthorizations`` tokens are delivered in the request *body*;
        ``agentAuthorization`` is delivered in the request *auth header*. For an
        MCP tool we want the former unless the agent itself is the protected
        resource.
        """
        path = (
            f"{BASE}/{self.parent}/collections/{collection}/engines/{engine_id}"
            f"/assistants/{assistant_id}/agents/{agent_id}"
        )
        agent = await self.api.get(path)
        config = dict(agent.get("authorizationConfig") or {})

        if agent_authorization:
            config["agentAuthorization"] = authorization
        else:
            tools = list(config.get("toolAuthorizations") or [])
            if authorization not in tools:
                tools.append(authorization)
            config["toolAuthorizations"] = tools

        return await self.api.patch(
            path,
            json={"authorizationConfig": config},
            params={"updateMask": "authorizationConfig"},
        )
