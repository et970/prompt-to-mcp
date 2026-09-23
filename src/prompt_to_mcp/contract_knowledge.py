"""What we know about the connector contract, and how we came to know it.

This module is the agent's corpus. It exists because the obvious corpus --
Google's own documentation -- was measured and found to be actively harmful for
this task.

Why the official docs are not the source of truth
-------------------------------------------------
A crawl of the Gemini Enterprise documentation tree (1,939 pages) and all five
``discoveryengine`` Discovery documents found:

* ``oauth_access_token`` appears in **zero** Google-published artifacts.
* ``mcp_server_source`` appears in **zero**.
* The custom-MCP setup guide is entirely console clickthrough: no JSON, no
  ``curl``, no field names.

Absence would be survivable. The real problem is that the docs teach the
failing payload. Every worked ``setUpDataConnector`` example with OAuth --
SharePoint, Jira -- puts ``client_id`` and ``client_secret`` in
``dataConnector.params``, and the ``DataConnector`` reference states in prose
that OAuth sources require ``client_id`` there. For ``custom_mcp`` that is
rejected outright.

A retrieval agent grounded on that corpus therefore: finds SharePoint as the
nearest worked example, emits ``client_id`` in ``params``, receives *"For
auth_type: OAUTH, Connector params must contain client_id"*, and reads it as
confirmation -- the docs said ``params``, the error says ``params``. It is a
self-reinforcing wrong answer, which is worse than no retrieval at all.

So the hierarchy here is deliberate and inverted:

1. :data:`GOLDEN_PAYLOADS` -- shapes proven accepted by a live probe.
2. :data:`VERIFIED_FACTS` -- claims with the experiment that established them.
3. :data:`DOC_TRAPS` -- documented claims known to be false, named so the model
   recognises them when retrieval surfaces them.
4. Documentation -- hypothesis generation only. Never sufficient to conclude.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

#: Machine-readable schema. Authoritative for *which fields exist* on a
#: resource, which is genuinely useful -- it is how ``federatedConfig`` and
#: ``endUserConfig`` were found and ruled out. Not authoritative for the untyped
#: map fields, whose contents it reduces to "structured json format".
DISCOVERY_DOC_URL = "https://discoveryengine.googleapis.com/$discovery/rest?version=v1alpha"

Confidence = Literal["proven", "observed", "unverified"]


@dataclass(frozen=True)
class ContractFact:
    """A claim about the API, inseparable from its evidence.

    The evidence field is not decoration. Every wrong belief this codebase has
    held came from a claim that outlived the observation behind it -- most
    expensively "actionParams takes no OAuth keys", which was true of one
    partial group and false in general.
    """

    statement: str
    evidence: str
    confidence: Confidence = "proven"

    def render(self) -> str:
        return f"[{self.confidence}] {self.statement}\n    evidence: {self.evidence}"


@dataclass(frozen=True)
class DocTrap:
    """A documented claim that is false for ``custom_mcp``.

    Named explicitly so that when retrieval surfaces the page, the model
    recognises it as a known trap rather than as corroboration.
    """

    claim: str
    reality: str
    source: str

    def render(self) -> str:
        return f"DOC SAYS: {self.claim}\n    REALITY: {self.reality}\n    source: {self.source}"


# ---------------------------------------------------------------------------
# Proven shapes
# ---------------------------------------------------------------------------

#: ``actionParams`` shapes a live probe has accepted. A worked example is the
#: single highest-signal artifact available for this API: it is what solved the
#: outage by hand, and what the agent now gets before it forms a hypothesis.
GOLDEN_PAYLOADS: dict[str, dict[str, Any]] = {
    "no_auth": {
        "mcp_server_source": "BYO_MCP",
        "instance_uri": "https://example.invalid/mcp",
        "auth_type": "NO_AUTH",
    },
    "oauth": {
        "mcp_server_source": "BYO_MCP",
        "instance_uri": "https://example.invalid/mcp",
        "auth_type": "OAUTH",
        "client_id": "<client id>",
        "client_secret": "<client secret>",
        "auth_uri": "https://example.invalid/oauth/authorize",
        "token_uri": "https://example.invalid/oauth/token",
        "scopes": "read write",
        "auth_uri_params": "&access_type=offline&prompt=consent",
    },
}

#: ``dataConnector.params`` on create, in every auth mode.
GOLDEN_PARAMS: dict[str, Any] = {"oauth_access_token": "<setup token>"}


VERIFIED_FACTS: tuple[ContractFact, ...] = (
    ContractFact(
        "dataConnector.params accepts exactly one key on create: oauth_access_token.",
        "Probed directly: any other key returns 'must be one of: oauth_access_token "
        "but got: <key>'. Confirmed for client_id specifically.",
    ),
    ContractFact(
        "The OAuth actionParams group is all-or-nothing. auth_type, client_id, "
        "auth_uri and token_uri must be sent together; client_secret, scopes and "
        "auth_uri_params are optional additions.",
        "Probed key by key. auth_type+client_id+auth_uri+token_uri accepted; "
        "dropping client_secret still accepted; dropping client_id rejected; "
        "any two of the four alone rejected.",
    ),
    ContractFact(
        "A partial OAuth group is reported as a generic allow-list error naming "
        "one arbitrary key, which looks like a ban on that key rather than a "
        "missing group. That list is a FALLBACK, not the set of accepted keys.",
        "The allow-list omits every OAuth key, yet a complete OAuth group is "
        "accepted. Misreading this caused a production outage.",
    ),
    ContractFact(
        "Omitting auth_type is not neutral: the server defaults it to OAUTH and "
        "then rejects the connector for lacking credentials. Always send it.",
        "A connector with no auth_type and no OAuth group returns 'For auth_type: "
        "OAUTH, Connector params must contain client_id'.",
    ),
    ContractFact(
        "'Connector params must contain client_id' names the wrong field. It is "
        "raised by an incomplete OAuth group in actionConfig.actionParams; "
        "params itself rejects client_id.",
        "Both directions probed: sending client_id in params is rejected, "
        "omitting the actionParams group produces this message.",
    ),
    ContractFact(
        "Parameter validation runs BEFORE the setup-token check. A request "
        "omitting oauth_access_token therefore cannot be created, whatever else "
        "it contains -- which is what makes probing free and safe.",
        "A complete, valid OAuth group with empty params still returns 'Missing "
        "Parameter Private App Access Token'.",
    ),
    ContractFact(
        "Validation order is: (1) actionParams allow-list and OAuth-group "
        "completeness, (2) params must contain oauth_access_token, (3) auth_type "
        "defaulting and its credential demand. Step 3 is BEHIND the token check, "
        "so a token-less probe cannot reach it -- a shape omitting auth_type looks "
        "accepted and then fails in production.",
        "Probed all four combinations. Incomplete group + empty params is rejected "
        "by the allow-list (so step 1 precedes step 2), while no auth_type + empty "
        "params returns only the token complaint, yet the same shape WITH a token "
        "returns 'must contain client_id'.",
    ),
    ContractFact(
        "params is write-different-from-read. After creation the backend discards "
        "the token and substitutes instance_uri, and client_id/client_secret are "
        "not present on read. The read shape cannot be replayed into a create.",
        "Read back an ACTIVE connector created by this app and compared.",
    ),
    ContractFact(
        "setUpDataConnector's LRO is not retrievable; GET on it 404s while the "
        "connector still reaches ACTIVE. Poll the connector resource instead.",
        "Observed on every successful run.",
    ),
)


DOC_TRAPS: tuple[DocTrap, ...] = (
    DocTrap(
        "Worked setUpDataConnector examples put client_id and client_secret in "
        "dataConnector.params.",
        "Rejected for custom_mcp. Those examples are for sharepoint_federated_search "
        "and jira, which are different data sources with a different contract. "
        "Pattern-matching them onto custom_mcp produces exactly the payload that "
        "caused the outage.",
        "docs.cloud.google.com/gemini/enterprise/docs/connectors/ms-sharepoint/set-up-data-store",
    ),
    DocTrap(
        "The DataConnector reference states: 'Required parameters for sources that "
        "support OAUTH... Key: client_id' under params.",
        "Not true of custom_mcp. OAuth configuration goes in "
        "actionConfig.actionParams for this data source.",
        "cloud.google.com/generative-ai-app-builder/docs/reference/rest/v1alpha/"
        "projects.locations.collections",
    ),
    DocTrap(
        "The actionParams reference lists the OAuth-capable sources as 'gmail, "
        "google_calendar, jira, workday, salesforce, confluence' -- custom_mcp is "
        "absent, implying it does not apply.",
        "custom_mcp does take OAuth actionParams. The list is stale, not exhaustive.",
        "cloud.google.com/generative-ai-app-builder/docs/reference/rest/v1alpha/"
        "projects.locations.collections",
    ),
    DocTrap(
        "The only working OAuth REST example in the guides uses "
        "serverSideOauth2.{clientId, clientSecret, authorizationUri, tokenUri}.",
        "That is the Authorization resource -- a separate resource, camelCase, and "
        "a different mechanism. The connector needs snake_case auth_uri/token_uri "
        "in actionParams. Conflating the two is the highest-risk confusion in the "
        "corpus.",
        "docs.cloud.google.com/gemini/enterprise/docs/register-and-manage-an-adk-agent",
    ),
    DocTrap(
        "actionParams is marked 'Optional' with no required-group semantics.",
        "For auth_type=OAUTH it is required, and required as a complete group.",
        "cloud.google.com/generative-ai-app-builder/docs/reference/rest/v1alpha/"
        "projects.locations.collections",
    ),
    DocTrap(
        "The custom MCP server setup guide documents Client ID, Authorization URL "
        "and Token URL as console fields.",
        "It never names the API fields behind them, and contains no JSON at all. "
        "It cannot tell you where they belong in a request.",
        "docs.cloud.google.com/gemini/enterprise/docs/connectors/custom-mcp-server/"
        "set-up-custom-mcp-server",
    ),
)

#: Pages worth retrieving despite the above, each with the caveat that keeps
#: them from being read as gospel.
USEFUL_DOC_PAGES: tuple[tuple[str, str], ...] = (
    (
        "cloud.google.com/generative-ai-app-builder/docs/reference/rest/v1alpha/"
        "projects.locations.collections",
        "The only page listing the auth_type enum (BASIC_AUTH, OAUTH, "
        "OAUTH_ACCESS_TOKEN, NO_AUTH, ...). Read the rendered page, not the "
        "Discovery JSON, which drops the oneof comments. Its params/client_id "
        "prose is wrong for custom_mcp.",
    ),
    (
        "docs.cloud.google.com/gemini/enterprise/docs/connectors/custom-mcp-server/"
        "override-constraint-for-custom-mcp-data-stores",
        "Real prerequisites: the custom_mcp dataSource value, allowedDataSources "
        "and allowedEgressFqdns org policy constraints.",
    ),
)


def render_briefing() -> str:
    """The corpus, as the agent sees it before it reasons."""
    facts = "\n".join(f.render() for f in VERIFIED_FACTS)
    traps = "\n".join(t.render() for t in DOC_TRAPS)
    pages = "\n".join(f"- {url}\n    {why}" for url, why in USEFUL_DOC_PAGES)
    return f"""\
ESTABLISHED FACTS (each proven by a probe against the live API):
{facts}

KNOWN-GOOD actionParams SHAPES:
  no auth: {GOLDEN_PAYLOADS["no_auth"]}
  oauth  : {GOLDEN_PAYLOADS["oauth"]}
KNOWN-GOOD params on create: {GOLDEN_PARAMS}

DOCUMENTATION TRAPS -- Google's docs are wrong about this specific data source.
If retrieval surfaces any of the following, treat it as a known error, NOT as
corroboration:
{traps}

Pages that are still worth reading, with their caveats:
{pages}
"""
