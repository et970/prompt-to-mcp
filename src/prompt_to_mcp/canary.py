"""Drift detection for the Discovery Engine data-connector contract.

The `connect` stage talks to a v1alpha surface with an untyped ``params`` map.
No discovery document describes it, so nothing in a unit test can tell us when
it changes -- and it does change: a run that had worked for weeks began failing
because ``setUpDataConnector`` started requiring ``client_id``. The test suite
could not have caught that, because it pins what *we* send, not what the server
accepts.

What the server will do is describe its own contract, if asked wrongly. Send a
parameter it does not recognise and it answers with the exhaustive list of the
ones it does::

    Data Connector parameters must be one of: oauth_access_token, client_id
    but got: __p2m_contract_probe__

That is a complete, current, authoritative description of the field, and
obtaining it costs one rejected request. Crucially the request is rejected
*during validation*, so nothing is created, nothing is billed, and there is
nothing to clean up -- which is what makes this safe to run on a schedule
against a production project.

Drift found here is a warning, not an outage: :func:`set_up_mcp_connector`
negotiates its way through most changes at runtime. The point of the canary is
that the warning arrives before a user does.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass, field
from typing import Any

from .gcp.base import GoogleApiError
from .gcp.discovery_engine import (
    BASE,
    BASE_ACTION_PARAMS,
    REQUIRED_OAUTH_ACTION_PARAMS,
    SUPPORTED_PARAMS,
    DiscoveryEngineClient,
    error_message,
    parse_missing_params,
    parse_param_rejection,
)

log = logging.getLogger(__name__)

#: A key no revision of the API will ever accept, which is the point: its
#: rejection carries the list of keys that *are* accepted.
PROBE_SENTINEL = "__p2m_contract_probe__"

#: `auth_type` must be explicit in every probe. Omitting it makes the server
#: default to OAUTH and answer with a credentials complaint instead of the
#: allow-list the probe is trying to read.
_NO_AUTH_ACTION_PARAMS: dict[str, Any] = {
    "mcp_server_source": "BYO_MCP",
    "instance_uri": "https://probe.invalid/mcp",
    "auth_type": "NO_AUTH",
}

#: What `build_mcp_connector` puts in `params`, in every auth mode.
EXPECTED_PARAMS: frozenset[str] = SUPPORTED_PARAMS


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class CanaryResult:
    ok: bool
    checks: list[Check]

    @property
    def drift(self) -> list[str]:
        return [c.detail for c in self.checks if not c.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "drift": self.drift,
            "checks": [
                {"name": c.name, "ok": c.ok, "detail": c.detail, **c.data} for c in self.checks
            ],
        }


def _probe_body(
    *, params: dict[str, Any], action_params: dict[str, Any]
) -> dict[str, Any]:
    return {
        # Randomised so two canaries running at once cannot interfere, though
        # neither should get far enough for it to matter.
        "collectionId": f"p2m-probe-{secrets.token_hex(4)}",
        "collectionDisplayName": "prompt-to-mcp contract probe (not created)",
        "dataConnector": {
            "dataSource": "custom_mcp",
            "connectorModes": ["FEDERATED"],
            "params": params,
            "actionConfig": {"actionParams": action_params, "createBapConnection": True},
            "entities": [{"entityName": "mcp_data"}],
        },
    }


async def _ask(discovery: DiscoveryEngineClient, body: dict[str, Any]) -> tuple[str | None, bool]:
    """Send a probe. Returns ``(complaint, created)``.

    ``created`` is the case this must never hit: a probe that is accepted has
    made a real collection. It is reported loudly rather than swallowed,
    because a silent leak on a schedule is worse than the drift being watched
    for.
    """
    url = f"{BASE}/{discovery.parent}:setUpDataConnector"
    try:
        await discovery.api.post(url, json=body)
    except GoogleApiError as exc:
        return error_message(exc), False
    return None, True


async def _cleanup(discovery: DiscoveryEngineClient, collection_id: str) -> None:
    try:
        await discovery.api.delete(f"{BASE}/{discovery.parent}/collections/{collection_id}")
        log.warning("canary probe was accepted; deleted the collection it created")
    except Exception:  # noqa: BLE001 - already an anomaly; do not mask it
        log.exception("canary probe created collection %s and could not remove it", collection_id)


async def check_params_contract(discovery: DiscoveryEngineClient) -> Check:
    """Which keys ``dataConnector.params`` accepts right now."""
    body = _probe_body(
        params={PROBE_SENTINEL: "x"},
        action_params=_NO_AUTH_ACTION_PARAMS,
    )
    complaint, created = await _ask(discovery, body)
    if created:
        await _cleanup(discovery, body["collectionId"])
        return Check(
            "params_contract",
            False,
            "the API accepted an unknown connector param, so it no longer validates "
            "this field and the probe created a collection (now deleted)",
        )
    rejection = parse_param_rejection(complaint or "")
    if rejection is None:
        return Check(
            "params_contract",
            False,
            "could not read the accepted params from the API's response; the error "
            f"format has changed: {complaint}",
        )
    allowed = set(rejection[0])
    unknown = sorted(EXPECTED_PARAMS - allowed)
    added = sorted(allowed - EXPECTED_PARAMS)
    data = {"accepted": sorted(allowed), "we_send": sorted(EXPECTED_PARAMS)}
    if unknown:
        return Check(
            "params_contract",
            False,
            f"the API no longer accepts {unknown} in dataConnector.params, which "
            "build_mcp_connector still sends",
            data,
        )
    if added:
        # Not a failure: the connector may not need them. Worth surfacing,
        # because this is exactly how the client_id requirement first appeared.
        return Check(
            "params_contract",
            True,
            f"the API accepts params this app does not send: {added}",
            data,
        )
    return Check("params_contract", True, "unchanged", data)


async def check_required_params(discovery: DiscoveryEngineClient) -> Check:
    """What the API demands when ``params`` is empty."""
    body = _probe_body(
        params={},
        action_params=_NO_AUTH_ACTION_PARAMS,
    )
    complaint, created = await _ask(discovery, body)
    if created:
        await _cleanup(discovery, body["collectionId"])
        return Check(
            "required_params",
            False,
            "the API accepted a connector with no params at all (probe collection deleted)",
        )
    demanded = parse_missing_params(complaint or "")
    data = {"demands": demanded, "raw": complaint}
    if not demanded:
        # A connector with no params at all must draw a complaint about params.
        # Anything else -- a 403, a changed message format -- means the probe
        # did not measure what it was pointed at, and reporting that as a pass
        # would make the canary worse than useless.
        return Check(
            "required_params",
            False,
            "sending no params drew a response that names no missing param, so the "
            f"contract could not be read: {complaint}",
            data,
        )
    unavailable = [k for k in demanded if k not in EXPECTED_PARAMS]
    if unavailable:
        return Check(
            "required_params",
            False,
            f"the API demands {unavailable}, which build_mcp_connector does not send",
            data,
        )
    return Check("required_params", True, f"demands {demanded}, all of which are sent", data)


async def check_oauth_group_contract(discovery: DiscoveryEngineClient) -> Check:
    """Whether a complete OAuth ``actionParams`` group is still accepted.

    This is the check that would have caught the outage. The connector takes
    its OAuth configuration all-or-nothing, and rejects a partial group with a
    generic "parameters must be one of" error that names one arbitrary key and
    never mentions completeness. Reading that message literally is what led to
    the OAuth keys being dropped entirely, which made every OAuth connector
    fail -- because an absent ``auth_type`` defaults to ``OAUTH``.

    So the probe sends a complete group with junk values. Junk is fine: the
    credentials are not verified at create time, only their presence. It is
    still rejected -- ``params`` carries no ``oauth_access_token`` -- so
    nothing is created.
    """
    complete = {
        "mcp_server_source": "BYO_MCP",
        "instance_uri": "https://probe.invalid/mcp",
        "auth_type": "OAUTH",
        "client_id": "probe",
        "client_secret": "probe",
        "auth_uri": "https://probe.invalid/authorize",
        "token_uri": "https://probe.invalid/token",
    }
    body = _probe_body(params={}, action_params=complete)
    complaint, created = await _ask(discovery, body)
    if created:
        await _cleanup(discovery, body["collectionId"])
        return Check(
            "oauth_group_contract",
            False,
            "a connector with no oauth_access_token was accepted (probe collection deleted)",
        )
    data = {"sent": sorted(complete), "raw": complaint}
    rejection = parse_param_rejection(complaint or "")
    if rejection is not None:
        offending = sorted(set(rejection[1]) & REQUIRED_OAUTH_ACTION_PARAMS)
        return Check(
            "oauth_group_contract",
            False,
            "the API rejected a complete OAuth actionParams group"
            + (f", objecting to {offending}" if offending else "")
            + ". build_oauth_action_params no longer matches the accepted shape, and "
            "every OAuth connector will fail until it does",
            data,
        )
    # Getting the Private-App-Access-Token complaint means the OAuth group got
    # all the way through validation, which is exactly what we want to know.
    if parse_missing_params(complaint or ""):
        return Check("oauth_group_contract", True, "complete OAuth group accepted", data)
    return Check(
        "oauth_group_contract",
        False,
        f"unexpected response to a complete OAuth group: {complaint}",
        data,
    )


async def check_action_params_contract(discovery: DiscoveryEngineClient) -> Check:
    """Whether :data:`BASE_ACTION_PARAMS` still matches the server."""
    body = _probe_body(
        params={"oauth_access_token": "probe"},
        action_params={**_NO_AUTH_ACTION_PARAMS, PROBE_SENTINEL: "x"},
    )
    complaint, created = await _ask(discovery, body)
    if created:
        await _cleanup(discovery, body["collectionId"])
        return Check(
            "action_params_contract",
            False,
            "the API accepted an unknown actionParam (probe collection deleted)",
        )
    rejection = parse_param_rejection(complaint or "")
    if rejection is None:
        return Check(
            "action_params_contract",
            False,
            f"could not read the accepted actionParams from: {complaint}",
        )
    allowed = set(rejection[0])
    data = {"accepted": sorted(allowed), "we_know_about": sorted(BASE_ACTION_PARAMS)}
    if allowed != set(BASE_ACTION_PARAMS):
        return Check(
            "action_params_contract",
            False,
            "BASE_ACTION_PARAMS is stale: newly accepted "
            f"{sorted(allowed - BASE_ACTION_PARAMS) or '(none)'}, no longer accepted "
            f"{sorted(BASE_ACTION_PARAMS - allowed) or '(none)'}",
            data,
        )
    return Check("action_params_contract", True, "unchanged", data)


CHECKS = (
    check_params_contract,
    check_required_params,
    check_oauth_group_contract,
    check_action_params_contract,
)


async def run_canary(discovery: DiscoveryEngineClient) -> CanaryResult:
    """Probe the connector contract. Creates nothing on the happy path."""
    results = await asyncio.gather(
        *(check(discovery) for check in CHECKS), return_exceptions=True
    )
    checks: list[Check] = []
    for check, result in zip(CHECKS, results, strict=True):
        if isinstance(result, BaseException):
            checks.append(
                Check(check.__name__.removeprefix("check_"), False, f"probe failed: {result}")
            )
        else:
            checks.append(result)
    return CanaryResult(ok=all(c.ok for c in checks), checks=checks)
