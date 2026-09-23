# Changelog

## 1.0.2

**Two BREAKING security fixes.** Existing deployments will start requiring
authentication, and existing `api_key` MCP servers will stop being publicly
reachable. Both defaults were intentional in 1.0.1 and both were wrong.

If you are running 1.0.1 or earlier: your control plane has been answering
unauthenticated requests from the internet, fronting a service account that
could read every secret in the project. **Treat it as compromised until the
logs say otherwise** — check Cloud Run request logs and Secret Manager access
logs, and rotate anything that service account could reach.

### BREAKING: the control plane now requires authentication

`create_app()` registered 18 routes and not one had an authentication
dependency. `deploy.sh` published the service with `--allow-unauthenticated`.
Behind it sat a service account holding ten broad project roles. Anyone who
found the Cloud Run URL could deploy services as that account, enumerate every
provisioned MCP with its secret resource names, tear everything down, and spend
Vertex quota — and `/docs` served them an indexed map of how.

Now:

- `deploy.sh` deploys the control plane **private**. Reaching it needs
  `roles/run.invoker`.
- Every route except `/healthz` independently verifies a Google-signed ID token
  and checks the principal against `P2M_ALLOWED_PRINCIPALS`. Defence in depth:
  `--allow-unauthenticated` is a deploy-time flag one careless edit from being
  re-added, and nothing in the running service would have noticed.
- **An empty `P2M_ALLOWED_PRINCIPALS` denies everyone.** It is not an "auth
  disabled" switch. Turning the check off is a separate, deliberate act
  (`P2M_ALLOW_UNAUTHENTICATED=1`) that logs a `WARNING` on every startup and is
  for local development only.
- `/docs`, `/redoc` and `/openapi.json` are disabled outside local development.
- `/readyz` is now a bare `{"status": "ok"}`, and is authenticated like every
  other route. It used to return the project id, every region setting, the
  public base URL and the build fingerprint to anyone who asked — a free
  reconnaissance summary. All of that moved intact to the authenticated
  `GET /v1/buildinfo`; `make check-deployed` and the UI health pill follow it
  there. **`/healthz` is the only unauthenticated route**, and discloses
  nothing; point external probes at it.
- The static UI mount is guarded too. A mount is an ASGI sub-application and
  bypasses route dependencies, so `/ui/app.js` would otherwise have stayed
  readable by anyone.

**Migrating.** `deploy.sh` grants `run.invoker` to whoever runs it and sets
`P2M_ALLOWED_PRINCIPALS` to the same identity. Both layers must name a caller.
Open the UI with `gcloud run services proxy prompt-to-mcp` (or `make ui`),
which attaches your identity token — do not re-add `--allow-unauthenticated`.

**Calling it with curl — two traps, both found by deploying this and trying:**

- **Send the token twice** — `X-Serverless-Authorization` for Cloud Run, and
  **`X-P2M-Authorization`** for the application. Cloud Run recognises a Google
  credential in either standard header and substitutes an assertion of its own,
  so the caller's token never reaches the container. Measured on a live service:
  an 872-character ID token came back as a different 557-character value in all
  three standard-header arrangements, while 905 characters of JWT-shaped junk
  passed through untouched — the platform is not truncating or blindly
  overwriting, it is deliberately withholding the credential. An application
  behind Cloud Run IAM can therefore only re-verify a caller's token if that
  token arrives in a header the platform ignores.
- Use a plain `gcloud auth print-identity-token`, with **no** `--audiences`.
  gcloud refuses that flag for user accounts, so a human's token always carries
  gcloud's client ID as its audience; `extra_allowed_audiences` accepts it by
  default and can be emptied to require service-account callers.

**`/healthz` is not reachable from outside Cloud Run.** Google Front End
intercepts that exact path and 404s it before the container sees it. The route
is still correct for container-level startup probes — which is what the
generated MCP servers use — but external uptime checks must target `/v1/canary`
with an OIDC token, as the Cloud Scheduler job `deploy.sh` creates now does.

### BREAKING: the OAuth proxy is now a separate Cloud Run service

This is the structural half of the fix above. The proxy and the provisioning
API shared a process, which forced one exposure decision onto two components
with opposite requirements: the API must never accept an anonymous request,
while the proxy exists to be reached by a browser that holds no credential at
all. Keeping them together meant the only way to make consent work was to
publish the provisioning API — which is exactly what happened.

`prompt-to-mcp-oauth` is deployed `--allow-unauthenticated`, deliberately, with
its own service account holding two roles (`datastore.user`,
`secretmanager.secretAccessor`). It cannot deploy anything, cannot touch
Discovery Engine and cannot create secrets. Its own protections are unchanged:
PKCE on both legs, single-use authorization codes deleted before the ownership
check, and client authentication at `/token`.

**Migrating.** `P2M_OAUTH_BASE_URL` is new and `deploy.sh` sets it. Existing
Gemini Enterprise connectors have the *old* combined URL baked into their
`Authorization` resource and cannot be edited in place — **an existing
`oauth_user` MCP must be torn down and re-provisioned** for its consent flow to
work. One image still serves both services; they differ only in entrypoint.

### BREAKING: MCP servers that hold a credential are no longer published publicly

Every generated service was granted `roles/run.invoker` to `allUsers`. The
module docstring justified it: *"the generated server is a pure pass-through: it
stores no credentials and grants no access of its own."*

That is true for `oauth_user` and `google_id_token`. It is **false** for the
other two:

- `api_key` — the service holds your upstream key, bound from Secret Manager,
  and attaches it to every outbound call. Nothing checks who called *it*. An
  internet-facing proxy that spends your key for anyone who finds the URL.
- `none` — an open relay to the upstream `base_url`, usable to launder traffic
  through your GCP identity.

Now:

- `allow_unauthenticated` defaults to `False` in `CloudRunDeployer.deploy()`.
  It was `True`, and `pipeline.py` never passed the argument at all, so every
  caller that did not think about the question published a service.
- The decision is made at the deploy stage from the **manifest's** auth kind and
  passed explicitly. `oauth_user` and `google_id_token` are published exactly as
  before.
- `api_key` and `none` are deployed private, with `run.invoker` granted to
  `P2M_MCP_INVOKER_PRINCIPALS` — by default the Gemini Enterprise service agent
  derived from `P2M_PROJECT_NUMBER`.
- If no invoker principal is configured, the run stops at **preflight** with an
  error naming the problem and the ways out, rather than creating a service
  nothing can reach. A security fix that is silently an outage is not a fix.
- `allow_public_unauthenticated` is a new request field, default `false`,
  honoured only for `api_key` and `none`. Using it logs a `WARNING` naming the
  `mcp_id`. `POST /v1/preflight` reports which case applies before anything is
  created.
- The module docstring now states accurately which kinds hold a credential and
  which are safe to publish. As written it would have persuaded the next
  reviewer that a real exposure was safe.

> **Unverified.** The private path depends on Gemini Enterprise presenting a
> Google-signed ID token audienced to the service. That has never been
> observed; 1.0.1 asserted it does not happen, but that was an inference from
> the design, not a measurement. If tool calls return 403, switch to
> `auth_kind: "oauth_user"` or set `allow_public_unauthenticated`. One query in
> the GE UI settles it either way.

### Least privilege

- `roles/secretmanager.admin` → `roles/secretmanager.editor` +
  `secretAccessor`. The admin role also granted
  `secretmanager.secrets.setIamPolicy`, which lets its holder grant themselves
  read access to every secret in the project — the most valuable thing
  reachable through the unauthenticated `POST /v1/mcps`. `editor` keeps
  create/delete/`versions.add` and drops exactly that.
  (`secretVersionAdder` cannot create secrets; upgrading deployments that
  received it briefly have it revoked.)
- `roles/storage.objectAdmin` is granted on the manifest bucket only, not
  project-wide. `bootstrap.sh` creates that bucket.
- The retry-with-backoff loop around project IAM bindings is unchanged;
  concurrent policy writes still fail.

### Fixed: `_allow_unauthenticated` silently discarded other IAM bindings

It POSTed a policy containing a single binding, which `setIamPolicy` treats as
a replace — any other binding on the service was lost, and two concurrent
writers clobbered each other with no error. It is now a read-modify-write:
`getIamPolicy`, append the member, send the `etag` back. A lost update is a 409
instead of a silent one. The existing warning for org policies that block
`allUsers` is unchanged; that behaviour was correct.

### Also

- `ingress` is configurable on `deploy()` rather than hardcoded to
  `INGRESS_TRAFFIC_ALL`. A service with no permitted caller also gets
  `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER`; IAM and ingress are independent
  controls, so a private service with a named invoker keeps normal ingress
  (Gemini Enterprise reaches it over the internet).
- List settings accept comma-separated environment variables as well as JSON.
  `P2M_ALLOWED_PRINCIPALS=a@x.com,b@x.com` previously aborted startup with a
  `SettingsError`, which on a security setting is how you get an operator who
  gives up and sets the escape hatch instead.
- `make ui` and `make run-oauth` are new; `make run` sets
  `P2M_ALLOW_UNAUTHENTICATED=1`, which is the only way to run locally.

## 1.0.1

Three fixes, all traced to one real run: a user pasted a Google API key into
the description box, asked for an MCP server over the Generative Language API,
and got a `FAILED` record three stages in — after a Cloud Run service had
already been created.

### API keys are a supported authentication mode

`auth_kind: "api_key"` is new. Before it, `AuthKind` offered only `none`,
`oauth_user` and `google_id_token`, so a pasted key was inert: nothing read it,
and the resolver fell back to `oauth_user` — which the user had not asked for
and which could not work.

The key is now written to Secret Manager during `deploy` and bound to the Cloud
Run service as a `secretKeyRef`, never a literal environment variable. The
manifest carries only the reference, which matters because the manifest is
persisted to Firestore, injected as a plain env var and served verbatim in the
downloadable package. Placement is resolved per provider: `*.googleapis.com`
hosts get a bare `x-goog-api-key`, everything else `Authorization: Bearer`, and
either can be overridden — including `?key=` query placement.

Resolution now detects a credential pasted into free text, lifts it into the
`api_key` field, removes it from the text and says so with a fingerprint. The
originating request resolves to a runnable plan instead of a doomed one.

Teardown deletes the key's secret. A live credential outliving the service that
used it is worse than an orphaned service.

### Pasted secrets no longer persist in the clear

Redaction matched on field *names*, so `client_secret` was fingerprinted and a
key inside `description` was not — it reached Firestore, the browser, and the
`record.json` in every downloadable package.

Values are now scrubbed too, against the shapes credentials actually take
(Google `AIza`/`AQ.`/`ya29.`, GitHub, Notion, OpenAI, Slack, AWS, JWTs, PEM
blocks, and anything the user labelled "api key"/"token"/"secret"). Matching is
prefix-anchored rather than entropy-based, because a "looks random" rule fires
on git SHAs, resource ids and URL segments — all things an operator needs to
read. Surrounding prose is preserved, so a record still shows that a credential
was supplied, and whether it was the same one as last time.

**If you ran an affected build, rotate any key pasted into a description and
delete the record.** Existing records are not rewritten.

### Google upstreams no longer fail at OAuth discovery

`preset_for_url()` has always returned `"google"` for any `*.googleapis.com`
host. The pipeline called it only to *phrase the error* after discovery had
already failed, so a run died at `oauth` telling the user to supply a preset the
code had itself identified. The preset lookup that did apply ran at resolve
time against `mcp_url`, which is `None` for generate-mode runs — and the base
URL that would have matched is not known until `ingest`, two stages later.

The preset is now applied as a discovery backstop. When it is, and dynamic
registration is unavailable — which is the actual situation for Google — the
error names the one thing only a human can do: create an OAuth client, with the
redirect URI to paste.

### Also

- `GET /healthz` on an API-key runtime reports `api_key: present|missing`, so a
  broken secret binding is visible without waiting for a tool call to 401.
- The reported version comes from package metadata. The hardcoded literal had
  drifted to `0.1.0` against a `1.0.0` release, because nothing failed when it
  did.
- `google-genai>=2.0`. The old `>=0.8` floor predates Gemini 3 and could
  resolve to a version that cannot run this code.
- `deploy/package.sh` (`make dist`) builds the handoff tarball. 1.0.0 was
  assembled by hand, so what belonged in it lived only in the tarball itself.
  The archive is reproducible: the same tree yields identical bytes.

## 1.0.0

First packaged release: prompt plus API documentation to a deployed MCP server
on Cloud Run, registered in Agent Registry and connected to Gemini Enterprise.

Includes the downloadable package endpoints (`GET /v1/mcps/{id}/bundle` and
`/bundle.zip`) and the in-browser file browser, which turn a provisioned server
into something reviewable and runnable offline.
