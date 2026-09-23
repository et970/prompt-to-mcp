# prompt-to-mcp

Takes a prompt (a description plus API documentation), and produces a working
MCP server on Cloud Run that is registered in Agent Registry, connected to a
Gemini Enterprise app as a data store, and wired for end-user credential
propagation — including an OAuth 2.1 proxy for MCP servers that have no static
client ID and secret.

Licensed under [Apache 2.0](LICENSE). Not an official Google product — see
[Disclaimer](#disclaimer).

```
prompt + docs
     │
     ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│  ingest  │─▶│  deploy  │─▶│  oauth   │─▶│ register │─▶│authorize │─▶│ connect  │─▶│  attach  │
└──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘
 ToolManifest  Cloud Run     DCR + static  Agent         Discovery     custom_mcp    Engine
               MCP service   client pair   Registry      Engine        connector +   dataStoreIds
                                           Service       Authorization data store
```

## Security posture (read before deploying)

Two deployment defaults through 1.0.1 were unsafe, and both are fixed as
**breaking changes** in 1.0.2. If you are running 1.0.1 or earlier, see
[CHANGELOG.md](CHANGELOG.md) and treat the deployment as compromised until the
logs say otherwise.

**The control plane must not be exposed unauthenticated.** It runs as a service
account that can create Cloud Run services, act as other service accounts, read
every secret in the project and administer Discovery Engine. One unauthenticated
call to `POST /v1/mcps` is arbitrary workload execution in your project.
`deploy.sh` now deploys it **private**, and the application independently
verifies a Google-signed ID token against `P2M_ALLOWED_PRINCIPALS`, so it fails
closed even if ingress is later misconfigured. `/docs` and `/openapi.json` are
disabled outside local development. Reach the UI with
`gcloud run services proxy`, never by re-adding `--allow-unauthenticated`.

**The OAuth proxy is a separate, deliberately public service.** It has to be:
the end user's browser is redirected to `/oauth/authorize` and the upstream
provider redirects it back to `/oauth/callback`, and neither hop can carry a
Google credential for your project. Running it in the same process as the
provisioning API is what forced the API to be public in the first place. It now
has its own service account with two roles and holds nothing worth stealing.

**`api_key` MCP servers are not published publicly.** A generated server in
`api_key` mode holds your upstream key in Secret Manager and attaches it to
every outbound request without checking who called it; granting `allUsers`
made it an open credential proxy. Those servers are now deployed private, with
`run.invoker` granted to the Gemini Enterprise service agent. `auth_kind:
"none"` is treated the same way. `oauth_user` and `google_id_token` servers
hold nothing and are still published exactly as before. See
[INSTALL.md](INSTALL.md#who-can-call-a-generated-server).

## The problem this solves

Gemini Enterprise's `Authorization` resource
(`discoveryengine.googleapis.com/v1alpha`) declares these fields **required**:

```jsonc
// GoogleCloudDiscoveryengineV1alphaAuthorizationServerSideOAuth2
{
  "clientId":         "Required. The OAuth2 client ID.",
  "clientSecret":     "Required. The OAuth2 client secret. Encrypted at rest.",
  "authorizationUri": "Required. ...",
  "tokenUri":         "Required. ..."
}
```

There is no dynamic-client-registration option and no public-client option. But
a managed MCP server built to the OAuth 2.1 / MCP authorization spec commonly
supports *only* RFC 7591 dynamic registration or public PKCE clients — it has no
static client ID and secret to give you. Such a server **cannot be described to
Gemini Enterprise at all**.

`prompt-to-mcp` closes that gap with an OAuth proxy that is a real authorization
server on the downstream side and a real OAuth client on the upstream side:

```
Gemini Enterprise                  OAuth proxy                    Upstream MCP AS
─────────────────                  ───────────                    ───────────────
static client_id     ──────────▶   validates synthetic
static client_secret               credentials, runs its
PKCE (challenge A)                 own PKCE (challenge B)  ──────▶  DCR-registered
                                                                    confidential client
                                                                    or public PKCE client
        ◀────────── access token passed through unmodified ───────────
```

Two independent PKCE exchanges. The downstream verifier is never forwarded
upstream. Upstream tokens pass through unmodified, which is exactly what makes
end-to-end credential propagation work: the token Gemini Enterprise stores is
the token the MCP server forwards to the upstream API.

## Working against the v1alpha APIs

Agent Registry and the Discovery Engine connector surface are v1alpha, and the
parts that matter most here are undocumented: `params` and `actionParams` are
untyped `map<string, any>` fields that no discovery document describes. The
contract below was established by introspecting the live discovery documents
and by reading working resources out of a real project. It is recorded here
because it is not available anywhere else, and because it will change.

**Established from the discovery documents and live resources**

| Fact | Source |
|---|---|
| Register an MCP by creating a **Service** with `mcpServerSpec`; `mcpServers` is read-only and derived | `agentregistry` discovery doc |
| `mcpServerSpec.type` ∈ `NO_SPEC` \| `TOOL_SPEC`; `content` mirrors a `tools/list` response, capped at 10 KB | discovery doc + live services |
| `interfaces[].protocolBinding` ∈ `JSONRPC` \| `GRPC` \| `HTTP_JSON` | discovery doc |
| Agent Registry `Service` has **no** auth fields at all | discovery doc |
| Agent Registry supports only `global` and `us-central1` | live 400 on other regions |
| A remote MCP attaches as `dataSource: "custom_mcp"`, `connectorType: "THIRD_PARTY_FEDERATED"`, `connectorModes: ["FEDERATED"]` | two live ACTIVE connectors |
| `actionParams` accepts **only** `instance_uri`, `mcp_server_source`, `registry_mcp_server_name`, `tool_list`, `agent_gateway_engine`, `use_agent_gateway_egress` | live 400 |
| Setup creates a data store named `<collection_id>_mcp_data` | same |
| `setUpDataConnector` is at the **location** level, not under `collections` | discovery doc |
| Discovery Engine requires the `global` endpoint and `locations/global` | live 400 on `locations/us` |
| `Agent.authorizationConfig` = `{agentAuthorization, toolAuthorizations[]}` | discovery doc |
| `services.create` takes `?serviceId=`, returns an **LRO**, and the derived `mcpServers/*` echoes tools and annotations back | **live round-trip** |

The Agent Registry body this project generates was validated by creating a
service in a live project, reading back the derived read-only `mcpServers/*`
projection (tools and annotations echoed correctly, URN minted), and deleting
it again.

**Behaviour the discovery documents do not describe**

The pipeline has been run end to end in a live project, reaching `state: READY`
with a working MCP server, an Agent Registry entry and a Gemini Enterprise data
store. These are the behaviours that only that run could establish, and the
ones most likely to cost you an afternoon:

| Behaviour | Detail |
|---|---|
| `DataConnector.connectorType` is **output-only** | Derived from `dataSource`. Sending it is an invalid write. |
| `params` is **write-different-from-read** | Create takes exactly `{"oauth_access_token": "..."}` in every auth mode. Anything else fails with *"Data Connector parameters must be one of: oauth_access_token"*; omitting it fails with *"Missing Parameter Private App Access Token"*. After creation the backend **discards the token and substitutes `instance_uri`** — so the shape you read back cannot be replayed into a create. |
| `setUpDataConnector`'s LRO is **not retrievable** | It returns `.../operations/create-data-connector-sync-lro-*`, which `GET`s as 404 while the connector still reaches `ACTIVE`. Poll the connector resource, not the operation. |
| `actionParams` takes OAuth config **all-or-nothing** | A *partial* OAuth group is rejected with *"Data Connector parameters must be one of: instance_uri, use_agent_gateway_egress, agent_gateway_engine, tool_list, mcp_server_source, registry_mcp_server_name but got: auth_uri_params"* — which names one arbitrary key and looks like a blanket ban on OAuth keys. It is not: that list is a **fallback**, used only when no complete group is present. A complete group (`auth_type`, `client_id`, `auth_uri`, `token_uri`; `client_secret`, `scopes`, `auth_uri_params` optional) is accepted even though none of those keys appear in it. Verified key by key against the live API — see the table in `OAUTH_ACTION_PARAMS`. |
| `auth_type` must be **explicit** | Omitting it is not neutral: the server defaults it to `OAUTH` and then rejects the connector for lacking credentials. Every connector sets `auth_type`, `NO_AUTH` included. |
| `params must contain client_id` **names the wrong field** | Sending `client_id` in `params` fails with *"must be one of: oauth_access_token but got: client_id"*; omitting it fails with *"For auth_type: OAUTH, Connector params must contain client_id"*. The field looks simultaneously required and forbidden. It is neither — the complaint is about an incomplete OAuth group in `actionParams`. `_explain` rewrites this message so it never reaches a user as-is. |

**The connector request is negotiated, not hardcoded**

Validation of those untyped fields is order-dependent, and the error messages
routinely name the wrong field — so a hardcoded request body transcribed from
them is wrong in ways no test can catch, because a test suite pins what the
client sends, not what the server accepts.

The shape is therefore treated as negotiable. `set_up_mcp_connector` sends its
best current guess, and when the API names a field it wants changed, amends the
request and resends — up to `MAX_PARAM_NEGOTIATION_ATTEMPTS` times. Both
directions are handled: `parse_missing_params` reads keys to add,
`parse_param_rejection` reads keys to drop. Values come from a `param_pool` of
things the run already minted, so nothing is invented; a key the pool cannot
satisfy is a real failure and is reported as one, with the full transcript of
attempted shapes. Every round is persisted to the record, so a run that only
succeeded on its second shape is visible without waiting for one to fail.

**Drift detection**

`GET /v1/canary` asks the live API what it currently accepts, by sending a
parameter no revision will ever take and reading the exhaustive list back out
of the rejection. It compares that against what `build_mcp_connector` sends and
against `SUPPORTED_ACTION_PARAMS`, and returns **503** on drift. The probe is
rejected during request validation, so it creates nothing and is safe to run on
a schedule — `deploy.sh` installs an hourly Cloud Scheduler job. The same
probes run as tests via `make test-live`.

**Contract discovery agent**

`POST /v1/contract/investigate` runs a bounded tool-using loop (Gemini 3.7
Flash on Vertex, via `P2M_GEMINI_MODEL`) that works out what the connector API
currently accepts. It is
**propose-only**: it returns a finding with its evidence and a suggested
change, and never touches how connectors are built.

It is safe to point at a production project because of one measured property:
`setUpDataConnector` validates parameters *before* it checks for the setup
token. `ProbeHarness` strips `oauth_access_token` from every request, so a
probe cannot succeed however correct the rest of it is — no resource created,
no cost, nothing to clean up. The same property is the evidence gate: a probe
whose only remaining complaint is the missing token has passed every parameter
check, so it *proves* the shape is valid. A shape the agent did not prove this
way is downgraded, not reported.

The agent is seeded before it reasons, with connectors already `ACTIVE` in the
project plus baseline probes of the shapes the app itself sends. Grounding it
in a worked example rather than instructing it to go and find one is load
bearing: without the seed it guesses, and the evidence gate then correctly
marks the result `verified: false` — sound, but useless. Seeded, it reaches the
right rule in about three probes.

What it deliberately does not do is provision. The eight pipeline stages are
deterministic, idempotent and resumable, and nondeterminism there would cost
the progress timeline and the resume semantics while buying nothing. The agent
sits underneath a pipeline that stays boring.

**Inspecting what a run actually sent**

Every record carries the inputs and the derived configuration that produced it,
per stage, under *Provisioned servers → (click a server) → Configuration*:
the request as submitted, the request after presets and provider defaults, the
doc source, the deployed manifest, and the verbatim `setUpDataConnector` request
body. The body is recorded *before* the call, so a stage that 400s leaves behind
exactly what it sent. Secrets appear as a `***<sha256 prefix> (n chars)`
fingerprint — comparable between runs, not recoverable.

**IAM roles that are not obvious**

- Agent Registry has its **own** IAM surface. `roles/aiplatform.user` does *not*
  grant `agentregistry.services.create`, despite the shared Vertex branding.
  `roles/agentregistry.editor` is also insufficient — it omits `bindings.*`.
  Use `roles/agentregistry.admin`.
- The control-plane service account is also the **runtime identity of every
  generated MCP service**, so it needs `roles/artifactregistry.reader` to pull
  the shared runtime image. Without it Cloud Run rejects the create with
  `artifactregistry.repositories.downloadArtifacts denied`.

**Known gaps in the platform**

- `agentregistry` `Binding.authProviderBinding` references
  `projects/*/locations/*/authProviders/*`, but that resource **404s** — it is
  not live yet. Auth therefore goes through Discovery Engine `authorizations`,
  not Agent Registry bindings.
- One live connector routes via
  `aiplatform.googleapis.com/v1/.../agentRegistry/services/{svc}:proxy`. That
  endpoint appears in **no** public discovery document (checked aiplatform v1
  and v1beta1). It works, but depending on it is a risk. This project points
  Gemini Enterprise at the Cloud Run URL directly instead.

## SDK and packaging traps

Three failures that only a real deployment surfaces, all now covered by tests:

- **`mcp` 2.x changes the meaning of `transport_security=None`.** It is not
  "disabled": `streamable_http_app` defaults `host="127.0.0.1"` and
  auto-enables DNS-rebinding protection with a localhost-only allowlist. Every
  Cloud Run request then fails `421 Misdirected Request`. Pass
  `TransportSecuritySettings(enable_dns_rebinding_protection=False)` explicitly.
- **`python-multipart` is required** for FastAPI to parse the form-encoded
  OAuth `/token` body. It is easy to miss because dev environments usually have
  it transitively; the container dies at import time without it.
- **Cloud Run `ResourceRequirements`** has `cpuIdle` as a sibling boolean, not a
  key inside `limits` — and `limits` values must be strings.

## Design decisions worth knowing

**Tools are declarative, never generated code.** The model emits a JSON
`ToolManifest` describing HTTP operations; Pydantic validates it; a single
prebuilt runtime image interprets it. No model-authored code is ever compiled or
executed. A malformed or malicious manifest fails validation instead of becoming
a running server.

**One runtime image for every MCP.** Provisioning is a Cloud Run *create*
(seconds), not a container build (minutes). The manifest is injected as
configuration, spilling to Cloud Storage past Cloud Run's 32 KiB env-var cap.

**OpenAPI beats the model.** When a machine-readable spec is available the
deterministic parser is used — exact, stable across runs, and it yields real
JSON Schemas. Freeform text that happens to parse as OpenAPI is opportunistically
upgraded to that path. Gemini is the fallback, not the default.

**The generated MCP is a pass-through — for two of the four auth kinds.** In
`oauth_user` and `google_id_token` mode it stores no credentials and grants no
access of its own: every request must carry a bearer token the upstream API
independently validates. Those are published to `allUsers`, and that is
defensible, because reaching them yields nothing.

It is **not** true for the other two. An `api_key` server holds your key in
Secret Manager and attaches it to every outbound request with no inbound check
at all; an `auth_kind: "none"` server relays anywhere with no check. Publishing
either to `allUsers` makes it an open proxy onto your credential, which is what
1.0.1 did. Both are now deployed private, with `run.invoker` granted to a named
caller — by default the Gemini Enterprise service agent.
`deployer/cloud_run.py` records which kind is which and why the distinction
matters.

## Web UI

The control plane serves a dependency-free single-page UI at **`/ui/`**, and the
root path redirects browsers to it. It provides:

- a provisioning form covering every request field, with four documentation
  input modes (OpenAPI URL, pasted spec, docs URL, pasted docs);
- **Preview tools** — runs ingestion only and lists the tools that would be
  generated, without deploying anything;
- **Check OAuth support** — probes an upstream and reports whether dynamic
  registration, public clients or the proxy are needed;
- a live list of provisioned servers with per-stage progress dots, and a detail
  drawer showing the eight-stage timeline, every created resource, the tool
  list, and a delete action.

No bundler, framework or CDN: the UI is plain HTML/CSS/JS shipped inside the
Python package, so the image stays a single Python artifact with no Node build
step and nothing that can break because a third-party script moved.

Two tests keep it honest: one asserts the UI is actually present in the built
wheel (static assets are easy to lose in packaging), and one parses `app.js` and
fails if it calls any endpoint the API does not expose.

## Quickstart

```bash
PROJECT_ID=my-project ./deploy/bootstrap.sh   # APIs, Artifact Registry, Firestore, SAs, IAM
PROJECT_ID=my-project ./deploy/deploy.sh      # build + deploy two services
```

`deploy.sh` deploys the **public OAuth proxy** and the **private control
plane**, each twice on first run by design: Cloud Run only reveals a service
URL after creation, and both must advertise their own — the proxy in its RFC
8414 metadata, the control plane in the links it renders. The proxy's URL gets
baked into Discovery Engine `Authorization` resources, so it cannot change
later without rebuilding the connector.

Every `curl` below needs an identity token, because the control plane is
private:

```bash
URL=$(gcloud run services describe prompt-to-mcp --region us-central1 \
        --format='value(status.url)')
TOKEN=$(gcloud auth print-identity-token)
# Twice on purpose: X-Serverless-Authorization for Cloud Run's IAM check,
# X-P2M-Authorization for the application. Cloud Run replaces a Google
# credential found in either standard header with an assertion of its own,
# so the app can only see a token that travels in a header it ignores.
AUTH=(-H "X-Serverless-Authorization: Bearer $TOKEN" -H "X-P2M-Authorization: Bearer $TOKEN")
# ...then add:  "${AUTH[@]}" to each curl
```

### Two modes

**Generate** an MCP server by wrapping a documented HTTP API (`docs`), or
**register** an MCP server that already exists (`mcp_url`) — a vendor's hosted
server, an internal deployment, or Google's own. In register mode nothing is
generated or deployed; the tool catalog is read from the server via `tools/list`.

```bash
# Register Google's hosted Drive MCP and connect it to Gemini Enterprise
curl -X POST "${AUTH[@]}" "$URL/v1/mcps" -H 'content-type: application/json' -d '{
  "description": "Google Drive MCP server",
  "mcp_url": "https://drivemcp.googleapis.com/mcp/v1",
  "auth_kind": "oauth_user",
  "oauth": {"preset": "google", "client_id": "...", "client_secret": "...",
            "scopes": ["https://www.googleapis.com/auth/drive.readonly"]}
}'
```

Some providers — Google among them — serve no RFC 9728 / RFC 8414 metadata and
document their OAuth configuration out of band, so discovery cannot find it. The
`oauth` block supplies it explicitly, and `preset: "google"` fills the endpoints.

When static `client_id` and `client_secret` are supplied the proxy is
**skipped**: it exists to manufacture static credentials, so interposing it when
they already exist adds a hop and solves nothing. Override with
`use_proxy: auto | always | never`.

### Provision an MCP

```bash
curl -X POST "${AUTH[@]}" "$URL/v1/mcps" -H 'content-type: application/json' -d '{
  "description": "Tools for querying and creating support tickets",
  "docs": {"openapi_url": "https://api.example.com/openapi.json"},
  "auth_kind": "oauth_user",
  "scopes": ["tickets.read", "tickets.write"],
  "gemini_enterprise_engine_id": "my-ge-app"
}'
```

Asynchronous by default — a full run takes minutes. Add `?wait=true` to block.

### Merging several documents

`docs` also accepts a list, for APIs whose documentation is split across more
than one document — a spec plus an addendum covering endpoints it omits, or one
spec per service area:

```bash
curl -X POST "${AUTH[@]}" "$URL/v1/mcps" -H 'content-type: application/json' -d '{
  "description": "Tools for orders, invoices and the undocumented legacy API",
  "docs": [
    {"openapi_url": "https://api.example.com/orders.json"},
    {"openapi_url": "https://api.example.com/invoices.json"},
    {"text": "GET /v0/legacy/ping returns {\"ok\": true} ..."}
  ],
  "auth_kind": "oauth_user"
}'
```

Each source is parsed by the rule that suits it — OpenAPI deterministically,
freeform text through the model, an SDK reference through the ingest agent
(below) — and the results are concatenated. The single
object form (`"docs": {...}`) is unchanged and still works.

Every spec is parsed *before* any text is synthesised, and the origin the specs
resolve is then handed to the model as its `base_url`. That ordering matters:
left to itself the model invents an origin, and an invented origin that happens
to disagree with the spec is indistinguishable from two genuinely different
APIs — so mixing a spec with an addendum would fail for no real reason. The
model is given the answer instead of being asked to guess it, and writes its
paths relative to the origin they will actually be called on.

Sources must still describe **one** API. Every tool's `path` is relative to a
single manifest-level `base_url`, so if two *specs* resolve different origins
the request is rejected rather than reconciled: adopting one would silently
point the other's tools at the wrong host, and you would find out at tool-call
time as a 404. Set `base_url` explicitly to override all of them.

### Building from an SDK

`docs.sdk` takes a client library instead of a document — a docs URL, a git
repository, or an `ecosystem:name` package reference:

```bash
curl -X POST "${AUTH[@]}" "$URL/v1/mcps" -H 'content-type: application/json' -d '{
  "description": "Tools for the widgets API",
  "docs": [{"sdk": "pypi:widgets-client"}],
  "auth_kind": "oauth_user"
}'
```

This is a different kind of problem from the others. An SDK documents *method
calls*; a tool needs an HTTP method and a path. `client.widgets.create(...)`
states neither, and the mapping is usually not written down anywhere, so it has
to be looked for. `sdk_agent.py` does that with a bounded tool-using loop —
`fetch`, `find_openapi`, `search`, `set_base_url`, `probe` — of the same shape
as the contract agent, and for the same reason: the answer is not in any one
place, so something has to go and look.

**The best outcome uses no model at all.** Most SDKs for large APIs are
generated *from* an OpenAPI document, and it is often published — next to the
docs, or in the repository. That hunt is deterministic and runs *before* the
agent starts; when it succeeds the spec is parsed by the ordinary parser and the
model is never consulted. Same "OpenAPI beats the model" rule, applied to a case
where the spec has to be found rather than handed over.

**Probes cannot change anything.** Only GET, HEAD and OPTIONS are ever sent, the
SSRF policy applies to every one, and the budget is capped. The useful answers
are the rejections: 401 and 403 prove a path exists as well as 200 does, and 404
disproves it — so an endpoint can be confirmed with no credentials at all. That
is what makes it defensible to point this at a production API you do not own.
Setting `probe_token` sends a bearer token as well, which buys real response
bodies; it is fingerprinted in the record and never persisted in usable form.

**Tools say how much is actually known about them.** Each carries an `evidence`
field — `spec`, `probed`, or `inferred` — and unproven tools still ship, marked
`inferred` and badged in the UI. Dropping them would publish a smaller API than
the SDK documents, and presenting them as facts would be a lie; labelling them
is the only option that is neither. The default is `inferred`, so a producer
that forgets to set it under-claims.

A spec that is found but unusable — most often one over the fetcher's 8 MB cap,
which GitHub's ~90 MB description comfortably exceeds — is reported back to the
agent rather than ending the run, and it carries on with `probe` and `propose`.
Measured against `https://api.github.com`, that path returns 9–10 tools with
every one confirmed by a probe, in roughly 90 seconds.

There is a limit worth knowing before you try it. This only works for SDKs that
are thin clients over an HTTP API. If the library speaks gRPC, holds a
websocket, or does real work locally, there is no HTTP operation to describe and
the runtime cannot serve it — that is a property of the pass-through design, not
a gap in the agent.

### Rejections when merging

Two rejections, both preferring a clear error to a quiet wrong answer:

- **Duplicate tool names.** The error names both positions. Keeping one would
  drop a capability the other document promised. Use `include_operations` to
  take the operation from a single source.
- **Exceeding `P2M_MAX_TOOLS` in total.** The cap applies to the merged result,
  not per document. Publishing the first 60 of 90 tools would read as "this API
  has 60 operations", which is worse than refusing.

### Preflight: what the app does for you, and what it can't

`POST /v1/preflight` (UI: **What do I need?**) reports every prerequisite,
classified by who has to act:

| Status | Meaning |
|---|---|
| `satisfied` | Nothing to do. |
| `auto` | The app does it during the run. Currently: enabling provider APIs via `serviceusage.services.batchEnable`. |
| `manual` | Genuinely not automatable, so the response carries a console deep link, the literal value to paste, and the CLI equivalent. |

The one unavoidable manual step is creating an OAuth client. Google's only
programmatic OAuth-client surface is
`iap.projects.brands.identityAwareProxyClients`, and its resource has **no
redirect-URI field** — IAP clients are pinned to IAP's own redirect handler and
cannot serve Gemini Enterprise's callback. So the app instead tells you exactly
which redirect URI to register, *and that URI depends on whether the proxy is in
the path*, which it computes for you.

Provisioning runs preflight first and warns before creating anything.

### Before you commit: dry runs

```bash
# Will this MCP need the proxy at all?
curl -X POST "${AUTH[@]}" "$URL/v1/inspect/oauth" -H 'content-type: application/json' \
  -d '{"url": "https://api.example.com/mcp"}'

# What tools would be generated, and what goes to Agent Registry?
curl -X POST "${AUTH[@]}" "$URL/v1/inspect/manifest" -H 'content-type: application/json' \
  -d '{"description": "...", "docs": {"openapi_url": "..."}}'
```

`stop_after` (`ingest`|`deploy`|`oauth`|`register`|`authorize`|`connect`) halts
the pipeline partway for staged rollouts.

### Following a run

`POST /v1/mcps` allocates the identifier up front and returns it immediately:

```json
{"id": "support-tickets-a1b2c3", "state": "RUNNING", "poll": "/v1/mcps/support-tickets-a1b2c3"}
```

The pipeline persists the record after **every** stage, so polling that URL
shows stages appearing one by one rather than a single opaque wait. This is what
the UI renders as a progress timeline.

### Is my fix actually live?

```
make check-deployed P2M_URL=https://...      # exit 1 if the deployment is stale
```

`/v1/buildinfo` reports a content fingerprint of the source tree the image was
built from, stamped in by `deploy.sh`, so "is the running service this code?"
is answerable in one call rather than inferred from whether the bug reproduced.
It lived on `/readyz` until 1.0.2, which also disclosed the project id and
region configuration to unauthenticated callers. The check runs as a `live`
test when `P2M_URL` is set.

### When a run stops part-way

The eight stages are not equally consequential. By the end of `register` there
is a deployed, registered, working MCP server; `connect` and `attach` only bind
it to Gemini Enterprise. A failure after `register` therefore lands in
**`PARTIAL`**, not `FAILED` — the record carries `failed_stage`, and the server
it already built stays usable.

Starting over is not an equivalent recovery, because Agent Registry interface
URLs are unique per location: a second run against the same endpoint fails at
`register` no matter what went wrong the first time. So partial runs are
**resumed** instead:

```
POST /v1/mcps/{id}/resume
```

Stages whose output is on the record are reused rather than repeated — reported
as `reused:` in the timeline, since "reused" and "created" are different facts
about what exists in the project. The synthetic OAuth client is read back rather
than re-minted, because the `Authorization` resource already holds its secret.
The collection a failed `connect` named is reused rather than stranded.

Two things cannot be reconstructed from a record: secrets (fingerprinted) and
oversized doc sources (truncated). Both are only needed by stages that already
succeeded, so this is normally invisible; when it is not, resume says exactly
what to resupply and takes it in the request body:

```json
{"overrides": {"oauth": {"client_secret": "..."}}}
```

## Configuration

All settings are `P2M_`-prefixed environment variables (see `config.py`).

| Variable | Default | Notes |
|---|---|---|
| `P2M_PROJECT_ID` | — | Required |
| `P2M_ALLOWED_PRINCIPALS` | empty | Who may call the control plane. **Empty denies everyone**; it is not an "off" switch |
| `P2M_ALLOW_UNAUTHENTICATED` | unset | Local development only. Disables auth and logs a `WARNING` at startup |
| `P2M_OAUTH_BASE_URL` | falls back to `P2M_PUBLIC_BASE_URL` | URL of the separate OAuth proxy service |
| `P2M_PROJECT_NUMBER` | unset | Derives the Gemini Enterprise service agent, granted `run.invoker` on private MCP servers |
| `P2M_MCP_INVOKER_PRINCIPALS` | derived | Explicit IAM members allowed to invoke a private generated MCP server |
| `P2M_PUBLIC_BASE_URL` | `http://localhost:8080` | Must be the externally reachable origin |
| `P2M_RUN_REGION` | `us-central1` | Where generated MCPs are deployed |
| `P2M_AGENT_REGISTRY_LOCATION` | `us-central1` | Only `global` or `us-central1` are valid |
| `P2M_DISCOVERY_ENGINE_LOCATION` | `global` | Must be `global` |
| `P2M_RUNTIME_IMAGE` | derived | The shared MCP runtime image |
| `P2M_MANIFEST_BUCKET` | unset | Required only for manifests over ~24 KB |
| `P2M_ALLOWED_UPSTREAM_HOSTS` | empty | Allowlist for doc fetching; empty disables the check |
| `P2M_GEMINI_MODEL` | `gemini-3.7-flash` | Drives manifest synthesis, diagnosis and the contract agent. Newest GA model; Gemini 3 has no GA pro tier, so set `gemini-3.1-pro-preview` if you want more reasoning headroom and accept preview status |
| `P2M_USE_MEMORY_STORE` | unset | Local dev without Firestore |

## Development

```bash
make install
make test     # 318 tests, hermetic
make test-live # 6 contract tests against the real Discovery Engine API
make lint
make run      # local control plane, in-memory stores, real Google APIs via ADC
```

Run a generated MCP locally against a manifest file:

```bash
MANIFEST=./manifest.json make run-mcp
```

### Test coverage focus

Tests target what actually carries risk rather than line count:

- **Runtime** — path-traversal escaping, header-injection rejection, unknown and
  missing arguments, nested body assembly, credential propagation, fail-closed
  on a missing token.
- **OAuth proxy** — full authorization-code flow, refresh, Basic and POST client
  auth, plus adversarial cases: open-redirect prevention, redirect pinning, PKCE
  failure, single-use codes, session replay, cross-client code theft, and
  indistinguishable responses for unknown-client vs. bad-secret.
- **Ingest** — `$ref` resolution, cycle protection, external-`$ref` refusal
  (SSRF), auth-header stripping, Swagger 2.0, YAML, SSRF URL policy.
- **API bodies** — regression guards pinning the exact verified shapes above, so
  a Google-side rename fails here rather than in production.
- **Connector negotiation** — converging on a shape the server demands, dropping
  one it has stopped accepting, refusing to invent a value the run never had,
  and terminating against an API that contradicts itself.
- **Resume** — `PARTIAL` vs `FAILED`, reuse of every prior stage's output, no
  second registration, no rotated client secret, and refusal to re-ingest from a
  truncated doc source.
- **Canary** — reading the live contract out of a rejection, catching a dropped
  or newly required param, and never creating a resource while doing it.
- **Pipeline** — all eight stages against fakes, including the secret and URL
  handoffs between stages, correct stage attribution on failure, and the
  `NameError` trap when the very first stage fails.
- **Dependencies** — every third-party import in `src/` and `runtime/` must be
  declared, implicit runtime deps must be present, and declared-but-unused deps
  are flagged. An undeclared `python-multipart` kills the container at import
  time, and dev environments hide it by supplying it transitively.
- **Transport** — a Cloud Run style `Host` header must not be rejected with
  421, which reproduces the mcp 2.x default exactly.

API bodies, connector negotiation and canary cover the failure mode the rest of
the suite structurally cannot: the API changing underneath code that did not.
Only `make test-live` can observe that, which is why it exists separately.

## Layout

```
src/prompt_to_mcp/
  config.py              settings + location constraints
  models.py              ToolManifest and the control-plane API types
  pipeline.py            the eight-stage orchestrator (resumable)
  main.py                FastAPI control plane (app factory) -- PRIVATE
  oauth_app.py           the OAuth proxy as its own service -- PUBLIC, by design
  auth.py                ID-token verification + principal allowlist
  build_info.py          build stamp: is the deployed service this source tree?
  canary.py              contract drift probes; creates nothing
  contract_agent.py      bounded probe loop that infers the current contract
  contract_knowledge.py  verified facts, golden payloads, documented traps
  sdk_agent.py           bounded loop recovering the HTTP API behind an SDK
  errors.py              exceptions shared across otherwise-circular layers
  diagnose.py            failure explanation: rules first, model as fallback
  redact.py              secret fingerprinting for the record store and UI
  ingest/
    openapi_loader.py    deterministic OpenAPI 3 / Swagger 2 -> manifest
    gemini_synth.py      freeform docs -> manifest, validated not trusted
    fetcher.py           SSRF-hardened document fetching
  oauth/
    metadata.py          RFC 9728 + RFC 8414 discovery chain
    dcr.py               RFC 7591 dynamic client registration
    proxy.py             the authorization-server shim
    store.py             proxy clients, sessions, one-time codes
  static/               dependency-free single-page UI (index.html, app.js, styles.css)
  gcp/
    agent_registry.py    services.create with TOOL_SPEC
    discovery_engine.py  authorizations + custom_mcp connector + engine attach
    secrets.py           Secret Manager
    records.py           provisioning results
  deployer/
    cloud_run.py         Cloud Run v2 deployment
runtime/
  server.py              the generic manifest-driven MCP server (mcp 2.x)
```

## Limitations

**Design constraints**

- Everything here rides on **v1alpha** APIs. They will change.
- Written against **mcp 2.x**; the 1.x decorator API (`@server.list_tools()`) is
  not compatible.
- Only APIs reachable over HTTP can be wrapped. An SDK that speaks gRPC, holds
  a websocket, or does real work locally has no HTTP operation to describe.
- Deleting an MCP detaches its data store from any Gemini Enterprise app and
  then removes the collection. Anything it could not remove is reported in
  `manual_cleanup_required`.
- Provisioning runs as an in-process background task. For production scale,
  move it to Cloud Tasks or Workflows so a cold-start eviction cannot orphan a
  half-finished run — though such a run is resumable rather than lost.
- The contract knowledge base is hand-curated and does not update itself from
  canary findings or agent investigations.

**Not yet exercised end to end**

These paths are covered by tests and verified as far as automated checks can
reach, but no real user has driven them in production. Expect to be the first.

- **The browser consent flow through the OAuth proxy.** Everything up to the
  upstream redirect is verified live and the token exchange has 14 hermetic
  adversarial tests, but no human has completed a consent against a deployment.
- **Per-user token propagation.** Whether Gemini Enterprise forwards a user's
  token through the proxy to the MCP server at query time is the last
  unverified link in the credential chain; one real query settles it.
- **Private MCP servers reached by Gemini Enterprise.** `api_key` and `none`
  servers grant `run.invoker` to the Discovery Engine service agent rather than
  `allUsers`. That depends on Gemini Enterprise presenting a Google-signed ID
  token audienced to the service, which has not been observed either way. If
  tool calls return 403, switch to `auth_kind: "oauth_user"` or the explicit
  `allow_public_unauthenticated` opt-in.
- **Attaching to an existing Gemini Enterprise app** (the `attach` stage).
- **The control plane / OAuth proxy split**, which is new in 1.0.2. The two
  services share a Firestore database, and a provisioning run writes a proxy
  client that the other service reads; that handoff has tests but no live
  consent flow behind it.

## License

Apache License 2.0. See [LICENSE](LICENSE) for the full text.

## Disclaimer

**This is not an officially supported Google product.** It is an independent
project, not affiliated with, endorsed by, or supported by Google. "Gemini
Enterprise", "Agent Registry", "Discovery Engine", "Cloud Run" and "Vertex AI"
are Google products referred to here descriptively.

It calls Google Cloud APIs on your behalf, and your use of those APIs remains
governed by your own agreement with Google. Several of the surfaces it depends
on are **v1alpha** and carry no compatibility guarantee: they can change
behaviour or disappear without notice, which is why the drift detection
described above exists.

The software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
OF ANY KIND, as set out in the License. It provisions real infrastructure —
Cloud Run services, service accounts, IAM bindings, secrets and Discovery
Engine resources — in a project you nominate, and it can incur cost. You are
responsible for what it creates. Read [Security posture](#security-posture-read-before-deploying)
and [Limitations](#limitations) before pointing it at anything you care about.
