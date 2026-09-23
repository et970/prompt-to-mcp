# Installation

Deploys two Cloud Run services into one Google Cloud project. Two commands,
roughly ten minutes, most of it waiting on image builds.

---

## Read this before you deploy

**The control plane must never be exposed unauthenticated.** It runs as a
service account that can create Cloud Run services, act as other service
accounts, write Secret Manager versions and administer Discovery Engine.
Anyone who can call `POST /v1/mcps` can run arbitrary workloads in your
project and reach every secret that service account can read. That is not a
theoretical ceiling; it is what one unauthenticated HTTP request buys.

Through 1.0.1 the shipped `deploy.sh` published it with
`--allow-unauthenticated` and the application performed no check of its own.
**If you are running 1.0.1 or earlier, treat the deployment as compromised
until proven otherwise**: check Cloud Run request logs and Secret Manager
access logs, and rotate anything the service account could read.

From 1.0.2:

- The control plane is deployed **private**. Reaching it needs both
  `roles/run.invoker` *and* membership of `P2M_ALLOWED_PRINCIPALS`.
- The **OAuth proxy is a separate service**, deployed public on purpose. It has
  to be: the end user's browser is redirected to it, and browsers hold no
  Google credential for your project. It runs as its own service account with
  two roles and holds nothing worth stealing.
- **Generated MCP servers that hold a credential are not published publicly.**
  See [Who can call a generated server](#who-can-call-a-generated-server).
- The interactive API docs (`/docs`, `/openapi.json`) are **off** unless the
  development escape hatch is set.

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| Google Cloud project | With billing enabled. APIs are enabled for you. |
| `gcloud` CLI | Authenticated: `gcloud auth login` and `gcloud auth application-default login` |
| Python 3.11+ | Only needed to run locally; deployment builds in Cloud Build |
| Project-level IAM | You need `roles/owner`, or enough to enable APIs, create service accounts and grant roles |

A Gemini Enterprise app is **optional**. Without one, servers are still built,
deployed, registered and given a data store — the data store is simply not
bound to an app. Supply `gemini_enterprise_engine_id` later to bind it.

Set your target project once:

```bash
export PROJECT_ID=my-project
export REGION=us-central1          # optional, this is the default
gcloud config set project "$PROJECT_ID"
```

---

## 2. Bootstrap the project

Run once per project.

```bash
make bootstrap
```

This enables nine APIs (`run`, `cloudbuild`, `artifactregistry`,
`agentregistry`, `discoveryengine`, `aiplatform`, `secretmanager`, `firestore`,
`cloudscheduler`), creates an Artifact Registry repository, a Firestore database
in `nam5`, a manifest bucket, and **two** service accounts.

### What the control plane's service account can do

`prompt-to-mcp@PROJECT.iam.gserviceaccount.com`. Read this list as "what an
attacker gets if they reach the API", because that is what it is:

| Role | What it permits |
|---|---|
| `roles/run.admin` | Create, update and delete **any** Cloud Run service in the project |
| `roles/iam.serviceAccountUser` | Deploy services running **as** other service accounts |
| `roles/artifactregistry.reader` | Pull images. Also the runtime identity of every generated MCP |
| `roles/agentregistry.admin` | Create/delete Agent Registry services and bindings |
| `roles/serviceusage.serviceUsageAdmin` | Enable **any** API in the project |
| `roles/discoveryengine.admin` | Create/delete authorizations, connectors and collections |
| `roles/aiplatform.user` | Call Vertex/Gemini — billable, unmetered |
| `roles/secretmanager.editor` | Create, update and delete secrets — but **not** set IAM policy on them |
| `roles/secretmanager.secretAccessor` | **Read every secret in the project** |
| `roles/datastore.user` | Read/write Firestore |
| `roles/storage.objectAdmin` | **On the manifest bucket only**, not project-wide |

Two of these were narrowed in 1.0.2. `roles/secretmanager.admin` became
`editor` + `secretAccessor`: the admin role additionally allowed
`secretmanager.secrets.setIamPolicy`, which lets its holder grant themselves
read access to every secret in the project by rewriting the policy — the single
most valuable thing reachable through the then-unauthenticated `POST /v1/mcps`.
(`secretVersionAdder` was tried first and cannot create secrets at all; an
`api_key` run fails at the deploy stage with `Permission
'secretmanager.secrets.create' denied`.)
`roles/storage.objectAdmin` moved from the project to the one bucket that needs
it.

`secretAccessor` is still broad, and it is genuinely required — the proxy has
to read the upstream client secrets it presents at `/token`, and generated
services resolve their API keys through it. If that is more than you are
willing to grant project-wide, bind it per-secret instead; nothing in the code
depends on the project-level grant.

### What the OAuth proxy's service account can do

`prompt-to-mcp-oauth@PROJECT.iam.gserviceaccount.com` gets exactly two roles:
`roles/datastore.user` and `roles/secretmanager.secretAccessor`. It cannot
deploy anything, cannot touch Discovery Engine, and cannot create secrets. This
is the service that is exposed to the internet, so its blast radius is the
whole point.

The script is idempotent — safe to re-run. Project-level IAM bindings are
applied with exponential backoff, because each one is a read-modify-write of
the whole project policy and issuing them back to back trips
concurrent-modification errors. The bucket binding is separate and needs no
retry.

---

## 3. Deploy

```bash
make deploy
```

This builds two images and deploys **two services**:

| Service | Exposure | Why |
|---|---|---|
| `prompt-to-mcp-oauth` | `--allow-unauthenticated` | The end user's browser is redirected to `/oauth/authorize` and the upstream provider redirects it back to `/oauth/callback`. Neither hop can carry a Google credential for your project, because obtaining a credential is the point of the exchange. Holds no project authority. |
| `prompt-to-mcp` | **private** | Runs as the service account described above. |

The proxy is deployed first, because its URL is passed to the control plane as
`P2M_OAUTH_BASE_URL` and gets baked into Gemini Enterprise authorization
resources at provisioning time.

**Each service deploys twice on the first run, by design.** Cloud Run only
reveals a URL after the service exists, and both have to advertise their own —
the proxy in its RFC 8414 metadata, the control plane in the links it renders.
Pass one creates; pass two sets the now-known URL. Subsequent deploys still run
both passes and are harmless.

`deploy.sh` also grants `roles/run.invoker` on the control plane to whoever ran
it, and sets `P2M_ALLOWED_PRINCIPALS` to the same identity. **Both layers must
name you**; Cloud Run IAM is the outer check and the allowlist is the inner one,
so the app still fails closed if ingress is ever misconfigured. Add colleagues
with:

```bash
gcloud run services add-iam-policy-binding prompt-to-mcp \
  --region "$REGION" --member user:them@example.com --role roles/run.invoker
gcloud run services update prompt-to-mcp --region "$REGION" \
  --update-env-vars '^|^P2M_ALLOWED_PRINCIPALS=you@example.com,them@example.com'
```

It also creates a Cloud Scheduler job that calls `/v1/canary` hourly, using an
OIDC token from the control plane's own service account.

---

## 4. Verify

```bash
URL=$(gcloud run services describe prompt-to-mcp \
        --region "$REGION" --format='value(status.url)')
TOKEN=$(gcloud auth print-identity-token)
# One header. Cloud Run makes its IAM decision from Authorization and forwards
# it to the container intact, so the same token satisfies both layers.
AUTH=(-H "Authorization: Bearer $TOKEN")

curl -s "${AUTH[@]}" "$URL/v1/buildinfo" | jq
curl -s "${AUTH[@]}" "$URL/v1/canary" | jq  # 503 = contract drifted
```

### Three things about calling it that will otherwise cost you an hour

**A browser cannot reach this service without IAP.** It cannot set an
`Authorization` header, so it can never present a bearer token. Enable
Identity-Aware Proxy on the control plane and open `$URL/ui/`; see
[Opening the web UI](#opening-the-web-ui). `gcloud run services proxy`
does not work — it authenticates through `X-Serverless-Authorization`.

**Do not send `X-Serverless-Authorization`.** Cloud Run treats it as its own
transport for the IAM check and [strips its
signature](https://cloud.google.com/iap/docs/enabling-cloud-run#known-limitations)
before the container sees it, so the application fails a perfectly good
credential with a misleading `invalid ID token`. Measured against a live
service, an 872-character ID token sent that way arrived as 557 characters.

Send **`Authorization`**; it is forwarded untouched, which the same measurement
confirms — the request returned 200 with the token verified by the application.
`X-P2M-Authorization` is still read first, as an override for any fronting
layer that does consume the standard header.

**Use a plain `gcloud auth print-identity-token`, with no `--audiences`.**
gcloud refuses that flag for user accounts (*"Invalid account type for
`--audiences`. Requires valid service account."*), so a human's token always
carries gcloud's own client ID as its audience. The control plane accepts it
for that reason; set `P2M_EXTRA_ALLOWED_AUDIENCES=` empty to require
service-account callers only. A service account *should* mint its token with
`--audiences="$URL"`.

**`/healthz` is not reachable from outside.** Google Front End intercepts that
exact path on Cloud Run and returns its own 404 before the request reaches the
container — on every Cloud Run service, not just this one. The route exists and
is genuinely unauthenticated (container-level startup probes use it, which is
why generated MCP servers still work), but it is useless as an external uptime
check. Point external monitoring at `/v1/canary` with an OIDC token instead;
`deploy.sh` configures Cloud Scheduler to do exactly that.

`/readyz` also returns a bare `{"status": "ok"}`, but it is authenticated like
everything else. It used to return the project id, every region setting, the
public base URL and the build fingerprint, which made it a free reconnaissance
summary for anyone who found the URL. All of that moved intact to
`/v1/buildinfo`.

### Opening the web UI

The UI is served from the private control plane, and a browser cannot
authenticate to it on its own: it cannot set an `Authorization` header, so it
can never present a bearer token. Put **Identity-Aware Proxy** in front, which
performs the Google sign-in and tells the application who arrived:

```bash
gcloud run services update prompt-to-mcp --region "$REGION" --iap

# IAP invokes the service on your behalf, so it needs permission to.
gcloud run services add-iam-policy-binding prompt-to-mcp --region "$REGION" \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com" \
  --role=roles/run.invoker

# ...and you need permission to get through IAP.
gcloud run services add-iam-policy-binding prompt-to-mcp --region "$REGION" \
  --member="user:$(gcloud config get-value account)" \
  --role=roles/iap.httpsResourceAccessor
```

Then open `$URL/ui/` and sign in. Three principals must agree: IAP must let you
through (`roles/iap.httpsResourceAccessor`), Cloud Run must let IAP in
(`roles/run.invoker` on the IAP service agent), and the application must accept
your email (`P2M_ALLOWED_PRINCIPALS`).

**Keep the invoker IAM check on.** It is a separate setting from
`--allow-unauthenticated`, and disabling it — the "Allow public access without
IAM" toggle in the console — leaves the `run.app` URL directly reachable,
making IAP decorative. `--no-allow-unauthenticated` does not restore it; use
`gcloud run services update prompt-to-mcp --region "$REGION" --invoker-iam-check`.

**Only the control plane gets IAP.** The OAuth proxy is a separate service that
must stay public: end users' browsers are redirected to `/oauth/authorize` and
upstream providers redirect back to `/oauth/callback`, and IAP in front of
either would break the consent flow for everyone.

`gcloud run services proxy` (and therefore `make ui`) does **not** work here.
It authenticates through `X-Serverless-Authorization`, whose signature Cloud Run
strips, so the application receives a token it cannot verify and returns
`401 invalid ID token`. Do not reach for `--allow-unauthenticated` when that
happens; that is the vulnerability, not a workaround for it.

Confirm the running service was built from this source tree:

```bash
P2M_URL="$URL" make check-deployed
# local    : 9c3adbc3b01a
# deployed : 9c3adbc3b01a (built ...)
# MATCH
```

Then provision something real, without deploying anything, to check ingest
works end to end:

```bash
curl -s -X POST "$URL/v1/inspect/manifest" \
  "${AUTH[@]}" \
  -H 'content-type: application/json' -d '{
    "description": "Tools to look up and create pets",
    "docs": {"openapi_url": "https://petstore3.swagger.io/api/v3/openapi.json"},
    "base_url": "https://petstore3.swagger.io/api/v3",
    "auth_kind": "none"
  }' | jq '.manifest.tools | length'
```

---

## 5. First real server

```bash
curl -s -X POST "$URL/v1/mcps?wait=true" \
  "${AUTH[@]}" \
  -H 'content-type: application/json' -d '{
    "description": "Tools to look up and create pets",
    "docs": {"openapi_url": "https://petstore3.swagger.io/api/v3/openapi.json"},
    "base_url": "https://petstore3.swagger.io/api/v3",
    "auth_kind": "none"
  }' | jq '{id, state, cloud_run_url}'
```

Use `POST /v1/preflight` first if you want to know what is missing before
committing to a run.

### Upstream authentication

`auth_kind` decides how the generated server authenticates to the API it wraps.

| Value | When | What you supply |
|---|---|---|
| `none` | The API is open, or takes no credential | nothing |
| `api_key` | One long-lived key, shared by every caller | `api_key` |
| `oauth_user` | Per-user access; the caller's own token is forwarded | usually nothing |
| `google_id_token` | A private Cloud Run service in your own project | nothing |

With `api_key`, the key is written to Secret Manager and bound to the generated
service as a secret reference. It is never stored in the manifest, the record
or the downloadable package.

```bash
curl -s -X POST "$URL/v1/mcps?wait=true" \
  "${AUTH[@]}" \
  -H 'content-type: application/json' -d '{
    "description": "Tools for the Gemini API",
    "docs": {"url": "https://ai.google.dev/api/rest"},
    "auth_kind": "api_key",
    "api_key": "AIza..."
  }' | jq '{id, state}'
```

Placement is inferred from the base URL — `x-goog-api-key` for Google, a bearer
token elsewhere — and can be overridden with `api_key_header`, or with
`api_key_query_param` for APIs that only accept `?key=`.

### Who can call a generated server

This changed in 1.0.2 and it is the second of the two breaking changes.

Through 1.0.1 **every** generated MCP server was granted `roles/run.invoker` to
`allUsers`. For `api_key` servers that was a confused deputy: the service holds
your upstream key in Secret Manager and attaches it to every outbound request,
and it checks nothing about who called it. Anyone who found the Cloud Run URL
could spend your key. For `auth_kind: "none"` it was an open relay to the
upstream, usable to launder traffic through your GCP identity.

The old code justified this with "the generated server is a pure pass-through:
it stores no credentials". That is true for two of the four kinds and false for
the other two:

| `auth_kind` | Holds a credential? | Published publicly? |
|---|---|---|
| `oauth_user` | No — forwards the caller's own token | **Yes**, unchanged |
| `google_id_token` | No — mints one per call from its own identity | **Yes**, unchanged |
| `api_key` | **Yes** — your key, from Secret Manager | **No** |
| `none` | No, but relays anywhere with no check | **No** |

For the two that are not published, the service is deployed private and
`roles/run.invoker` is granted to `P2M_MCP_INVOKER_PRINCIPALS` — by default the
Gemini Enterprise (Discovery Engine) service agent, derived from
`P2M_PROJECT_NUMBER`, which `deploy.sh` sets for you.

> **This path is unverified.** Cloud Run authorises a caller only if it presents
> a Google-signed ID token audienced to the service. Whether the Discovery
> Engine connector does so when calling an MCP endpoint has never been observed
> against a live Gemini Enterprise app — the 1.0.1 code asserted it does not,
> but that was an inference from the design, never a measurement. If tool calls
> come back **403**, that inference was right and you need one of the two
> options below. Confirming it either way takes one query in the GE UI and a
> look at the Cloud Run request log.

If neither `P2M_PROJECT_NUMBER` nor `P2M_MCP_INVOKER_PRINCIPALS` is set, there
is no identity to let in, so the run **stops at preflight** rather than creating
a service nothing can reach. Two ways forward, both named in the error:

1. **Use `auth_kind: "oauth_user"`.** Each end user presents their own
   credential, the server holds nothing, and it is published normally. This is
   the only option that gives per-user isolation, and it is the recommended one.
2. **Accept the exposure deliberately** with
   `"allow_public_unauthenticated": true` on the request. The server is granted
   `allUsers` and a `WARNING` naming the `mcp_id` is logged. Reasonable for a
   free read-only key or a throwaway sandbox. Not otherwise.

`POST /v1/preflight` reports which of these applies before anything is created.

`oauth_user` needs no configuration when the upstream supports dynamic client
registration. Google does not, so for a `*.googleapis.com` upstream create an
OAuth 2.0 Client ID (Web application) with redirect URI `$URL/oauth/callback`
and pass `"oauth": {"preset": "google", "client_id": "...", "client_secret": "..."}`.

> Do not paste credentials into `description`. If you do, they are detected,
> moved into `api_key` and removed from the text — but the reliable path is the
> field that is meant for them.

---

## Configuration

All settings are `P2M_`-prefixed environment variables on the control plane
service. `deploy.sh` sets the essential ones; override by editing the
`--set-env-vars` line or with `gcloud run services update`.

| Variable | Default | Notes |
|---|---|---|
| `P2M_PROJECT_ID` | — | **Required.** Project that owns everything created. |
| `P2M_ALLOWED_PRINCIPALS` | empty | **Who may call the control plane.** Comma-separated emails or service accounts. **Empty denies everyone** — it is not an "off" switch. Set by `deploy.sh` to whoever ran it. |
| `P2M_ALLOW_UNAUTHENTICATED` | unset | **Local development only.** Disables authentication entirely and logs a `WARNING` at every startup. Never set this on a deployed service. |
| `P2M_OAUTH_BASE_URL` | falls back to `P2M_PUBLIC_BASE_URL` | URL of the separate OAuth proxy service. Set automatically by `deploy.sh`. Baked into Gemini Enterprise authorization resources, so it cannot change later without rebuilding the connector. |
| `P2M_PROJECT_NUMBER` | unset | Used to derive the Gemini Enterprise service agent, which is granted `run.invoker` on MCP servers that cannot be published publicly. Set automatically by `deploy.sh`. |
| `P2M_MCP_INVOKER_PRINCIPALS` | derived from `P2M_PROJECT_NUMBER` | Explicit IAM members (`serviceAccount:...`) allowed to invoke a private generated MCP server. |
| `P2M_PUBLIC_BASE_URL` | `http://localhost:8080` | Must be the externally reachable origin. Set automatically by `deploy.sh`. |
| `P2M_RUN_REGION` | `us-central1` | Where generated MCP servers are deployed. |
| `P2M_AGENT_REGISTRY_LOCATION` | `us-central1` | Only `global` or `us-central1` are accepted by the API. |
| `P2M_DISCOVERY_ENGINE_LOCATION` | `global` | Must be `global`. |
| `P2M_ARTIFACT_REPO` | `prompt-to-mcp` | Artifact Registry repository. |
| `P2M_RUNTIME_IMAGE` | derived | The shared MCP runtime image. |
| `P2M_MCP_SERVICE_ACCOUNT` | unset | Service account for generated servers. Falls back to the default compute SA. |
| `P2M_FIRESTORE_DATABASE` | `(default)` | Firestore database holding records and OAuth state. |
| `P2M_GEMINI_MODEL` | `gemini-3.7-flash` | Drives ingest, diagnosis and the agents. See note below. |
| `P2M_GEMINI_LOCATION` | `global` | Vertex AI location. |
| `P2M_MANIFEST_BUCKET` | unset | Needed only for manifests over ~24 KB, which spill to Cloud Storage. |
| `P2M_ALLOWED_UPSTREAM_HOSTS` | empty | Allowlist for document fetching. Empty disables the check — not recommended in production. |
| `P2M_MAX_TOOLS` | `60` | Cap on tools per server. |
| `P2M_TOOL_SPEC_MAX_BYTES` | `10000` | Agent Registry's published-catalogue cap. |
| `P2M_USE_MEMORY_STORE` | unset | Local development without Firestore. |

### Choosing a model

`gemini-3.7-flash` is the default because it is the newest generally available
model. Gemini 3 has no GA pro-tier text model. If ingest quality matters more
than cost — particularly when building from prose or from SDKs with no
published spec — set `P2M_GEMINI_MODEL=gemini-3.1-pro-preview` and accept that
it is a preview model without a GA service level.

---

## Running locally

Uses in-memory stores, so no Firestore is required, but it still calls the real
Google APIs through your application-default credentials.

```bash
make install
make run          # http://localhost:8080
```

`make run` sets `P2M_ALLOW_UNAUTHENTICATED=1`. It has to: there is no Cloud Run
in front to mint a token against, and Google will not sign an ID token
audienced to `http://localhost:8080`. It logs a `WARNING` on every startup, and
it must never be set on a deployed service — it disables the check on
`POST /v1/mcps` and `DELETE /v1/mcps/{id}` too.

The OAuth proxy is a separate process in deployment, so it is a separate process
locally as well. Run it in another shell if you are exercising the consent flow:

```bash
make run-oauth    # http://localhost:8081
```

Run a generated MCP server locally against a saved manifest:

```bash
MANIFEST=./manifest.json make run-mcp
```

---

## Troubleshooting

**`PERMISSION_DENIED` during bootstrap.** You lack project-level IAM rights.
`roles/owner`, or the ability to enable services, create service accounts and
set IAM policy, is required.

**`location is not supported` from Agent Registry.** Only `global` and
`us-central1` are valid for `P2M_AGENT_REGISTRY_LOCATION`.

**`Incorrect API endpoint used` from Discovery Engine.** Gemini Enterprise
collections live under `global` and must be called on the global endpoint.
Leave `P2M_DISCOVERY_ENGINE_LOCATION` at `global`.

**A YAML parse error mentioning CSS.** A rendered documentation page was passed
in the `openapi_url` field. Use `url` for documentation pages, or `openapi_url`
only for machine-readable specs. The service reports this specifically.

**`401 missing credentials` from every endpoint.** Expected: the control plane
is private. Send `-H "Authorization: Bearer $(gcloud auth print-identity-token)"`.
From a browser there is nothing to send — enable IAP instead.

**`401 invalid ID token` when you did send one.** Two causes. Either the token
travelled in `X-Serverless-Authorization`, whose signature Cloud Run strips
(this is what `gcloud run services proxy` does) — send `Authorization` instead;
or IAP is enabled and the assertion failed verification, in which case the logs
name the reason.

**`401 this service cannot verify IAP assertions`.** IAP is in front but the
expected audience cannot be derived. Set `P2M_PROJECT_NUMBER`, or
`P2M_IAP_AUDIENCE` to
`/projects/<number>/locations/<region>/services/<service>` outright. The
service refuses assertions rather than accepting any audience.

**`403 principal ... is not allowed`.** Your token is valid but your identity is
not in `P2M_ALLOWED_PRINCIPALS`. Add it, and grant `roles/run.invoker` too —
both layers must name you.

**`403 no principals are allowed to call this service`.**
`P2M_ALLOWED_PRINCIPALS` is empty. That denies everyone by design, so that a
forgotten setting cannot silently publish the API. Set it.

**The run fails at preflight with "MCP server cannot be published and has no
permitted caller".** You asked for `auth_kind` `api_key` or `none`, which are
not published publicly, and no invoker principal is configured. See
[Who can call a generated server](#who-can-call-a-generated-server).

**Tool calls to an `api_key` MCP return 403.** Gemini Enterprise is not
presenting a Google ID token, so the private-deploy path does not work for your
setup. Use `auth_kind: "oauth_user"`, or set
`"allow_public_unauthenticated": true` and accept that the key is reachable by
anyone with the URL.

**`/v1/canary` returns 503.** The Gemini Enterprise connector API changed shape.
These are v1alpha surfaces and have moved before. The response body says which
parameter set is now expected.

**A run failed part-way.** Records are kept. `POST /v1/mcps/{id}/diagnose`
explains it, and `POST /v1/mcps/{id}/resume` retries from the stage that
stopped. Supply anything missing in the resume body, e.g.
`{"overrides": {"oauth": {"client_secret": "..."}}}` — secrets are fingerprinted
in records, never stored in recoverable form, so they must be resupplied.

**`could not discover an OAuth authorization server`.** The upstream publishes
no RFC 8414 metadata. For a Google API the preset is applied automatically and
the message will instead tell you to create an OAuth client. For anything else,
pass `oauth.authorization_endpoint` and `oauth.token_endpoint` — or use
`auth_kind: "api_key"` if the API is reached with a static key.

**Every tool call returns 401 on an `api_key` server.** Check
`GET <mcp-url>/healthz`: it reports `api_key: present|missing`. `missing` means
the Cloud Run secret binding was lost, or the service account can no longer read
the secret. `present` with a 401 means the key itself is wrong or lacks scope.

**The deployed service does not seem to have your change.** Ask it:
`P2M_URL=... make check-deployed` compares the running build against this
source tree.

---

## Uninstall

Generated MCP servers are independent of the control plane and are not removed
with it. To remove one completely:

```bash
ID=<record id>                       # e.g. petstore-a1b2c3
PROJECT_ID=$(gcloud config get-value project)
NUM=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
TOKEN=$(gcloud auth print-access-token)

# 1. Discovery Engine collection. The data store is deleted with it; deleting
#    the data store directly is refused ("connected data store").
curl -X DELETE "${AUTH[@]}" \
  "https://discoveryengine.googleapis.com/v1alpha/projects/$NUM/locations/global/collections/<collection-id>"

# 2. Agent Registry. Delete the *service*, not the mcpServers resource --
#    the mcpServers path does not accept DELETE.
curl -X DELETE "${AUTH[@]}" \
  "https://agentregistry.googleapis.com/v1alpha/projects/$PROJECT_ID/locations/us-central1/services/mcp-$ID"

# 3. Cloud Run service
gcloud run services delete "mcp-$ID" --region us-central1 --quiet

# 4. Record
curl -X DELETE "${AUTH[@]}" \
  "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/p2m_mcps/$ID"
```

The collection and service identifiers are on the record: `GET /v1/mcps/{id}`
returns `collection`, `registry_service` and `cloud_run_url`.

To remove the control plane itself:

```bash
gcloud run services delete prompt-to-mcp --region us-central1 --quiet
gcloud scheduler jobs delete prompt-to-mcp-canary --location us-central1 --quiet
```
