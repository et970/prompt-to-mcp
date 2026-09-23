#!/usr/bin/env bash
# Build and deploy the runtime image, the OAuth proxy and the control plane.
#
# Three services, and the order matters:
#
#   1. mcp-runtime          image only; every generated MCP shares it
#   2. prompt-to-mcp-oauth  the OAuth 2.1 proxy. PUBLIC, deliberately.
#   3. prompt-to-mcp        the provisioning API and UI. PRIVATE.
#
# The proxy is deployed first because its URL has to be handed to the control
# plane: the URLs it serves get baked into Discovery Engine Authorization
# resources at provisioning time and cannot be changed afterwards without
# rebuilding the connector.
#
# Each service is still deployed twice on first creation. Cloud Run only tells
# us a service's URL after it exists, and both services have to advertise their
# own URL -- the proxy in its RFC 8414 metadata, the control plane in the links
# it renders. Pass 1 creates, pass 2 sets the now-known URL.
#
# The control plane is NOT deployed --allow-unauthenticated. It runs as a
# service account that can create Cloud Run services, act as other service
# accounts and write Secret Manager versions; an anonymous caller reaching
# POST /v1/mcps owns the project. Reach it with an identity token, or with
# `gcloud run services proxy` for the UI. See the closing instructions.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-us-central1}"
REPO="${REPO:-prompt-to-mcp}"
SERVICE="${SERVICE:-prompt-to-mcp}"
OAUTH_SERVICE="${OAUTH_SERVICE:-prompt-to-mcp-oauth}"
SA="${SA:-prompt-to-mcp@${PROJECT_ID}.iam.gserviceaccount.com}"
OAUTH_SA="${OAUTH_SA:-prompt-to-mcp-oauth@${PROJECT_ID}.iam.gserviceaccount.com}"
AGENT_REGISTRY_LOCATION="${AGENT_REGISTRY_LOCATION:-us-central1}"
MANIFEST_BUCKET="${MANIFEST_BUCKET:-${PROJECT_ID}-prompt-to-mcp-manifests}"
TAG="${TAG:-$(date +%Y%m%d-%H%M%S)}"

# The Gemini Enterprise (Discovery Engine) service agent is addressable only by
# project NUMBER, and it is what gets roles/run.invoker on a generated MCP that
# holds an API key and therefore must not be published to allUsers.
PROJECT_NUMBER="${PROJECT_NUMBER:-$(gcloud projects describe "${PROJECT_ID}" \
  --format='value(projectNumber)' 2>/dev/null)}"

# Who may call the control plane. Defaults to whoever is running this script,
# which is the only identity we can infer and is right for a first deploy.
# Add teammates with P2M_ALLOWED_PRINCIPALS="a@x.com,b@x.com".
ALLOWED_PRINCIPALS="${P2M_ALLOWED_PRINCIPALS:-$(gcloud config get-value account 2>/dev/null)}"

REGISTRY="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}"
RUNTIME_IMAGE="${REGISTRY}/mcp-runtime:${TAG}"
RUNTIME_LATEST="${REGISTRY}/mcp-runtime:latest"
CONTROL_IMAGE="${REGISTRY}/control-plane:${TAG}"

cd "$(dirname "$0")/.."

if [[ -z "${ALLOWED_PRINCIPALS}" ]]; then
  echo "ERROR: could not determine who should be allowed to call the control plane." >&2
  echo "       Set P2M_ALLOWED_PRINCIPALS=you@example.com and re-run." >&2
  echo "       An empty allowlist denies everyone -- the service would deploy and" >&2
  echo "       then refuse every request, including yours." >&2
  exit 1
fi

# Stamp the tree before it is packaged, so the running service can be asked
# what it was built from. Deploying a fix and then debugging the old code is a
# mistake that has already been made once.
# Removed again once the images are built. A stamp left in the working tree
# would shadow the live source fingerprint and report a stale build as current
# -- reintroducing, locally, the exact confusion it exists to prevent.
STAMP="src/prompt_to_mcp/BUILD_STAMP"
trap 'rm -f "${STAMP}"' EXIT
echo "==> Stamping build"
PYTHONPATH=src python3 -m prompt_to_mcp.build_info

echo "==> Building MCP runtime image"
gcloud builds submit runtime \
  --tag "${RUNTIME_IMAGE}" --project "${PROJECT_ID}" --quiet
gcloud artifacts docker tags add "${RUNTIME_IMAGE}" "${RUNTIME_LATEST}" \
  --project "${PROJECT_ID}" --quiet

echo "==> Building control plane image"
# One image serves both the control plane and the OAuth proxy; they differ only
# in the uvicorn factory each is started with. Two images would be two things to
# keep in step for no benefit.
gcloud builds submit . \
  --tag "${CONTROL_IMAGE}" --project "${PROJECT_ID}" --quiet

# --------------------------------------------------------------------------
# OAuth proxy -- public on purpose
# --------------------------------------------------------------------------
# --allow-unauthenticated here is correct and load-bearing, not an oversight.
# The end user's browser is redirected to /oauth/authorize and the upstream
# provider redirects it back to /oauth/callback; neither hop can carry a Google
# credential, because obtaining a credential is the point of the exchange.
# This service holds no project authority to abuse: its service account can
# read its own Firestore records and the client secrets it must present at
# /token, and nothing else. Its own protections are PKCE on both legs,
# single-use authorization codes, and client authentication at /token.
deploy_oauth() {
  local public_url="$1"
  # --command/--args must use the =form. Written with a space, gcloud parses
  # the leading `-m` of the value as another flag and dies with
  # "argument --args: expected one argument".
  gcloud run deploy "${OAUTH_SERVICE}" \
    --image "${CONTROL_IMAGE}" \
    --region "${REGION}" \
    --project "${PROJECT_ID}" \
    --service-account "${OAUTH_SA}" \
    --command=python3 \
    --args=-m,prompt_to_mcp.oauth_app \
    --allow-unauthenticated \
    --memory 512Mi --cpu 1 --timeout 300 --max-instances 5 \
    --set-env-vars "P2M_PROJECT_ID=${PROJECT_ID},P2M_OAUTH_BASE_URL=${public_url},P2M_PUBLIC_BASE_URL=${public_url}" \
    --quiet
}

echo "==> Deploying OAuth proxy (pass 1)"
deploy_oauth "https://placeholder.invalid"

OAUTH_URL="$(gcloud run services describe "${OAUTH_SERVICE}" \
  --region "${REGION}" --project "${PROJECT_ID}" --format='value(status.url)')"

echo "==> Re-deploying OAuth proxy with resolved URL: ${OAUTH_URL}"
deploy_oauth "${OAUTH_URL}"

# --------------------------------------------------------------------------
# Control plane -- private
# --------------------------------------------------------------------------
deploy() {
  local public_url="$1"
  gcloud run deploy "${SERVICE}" \
    --image "${CONTROL_IMAGE}" \
    --region "${REGION}" \
    --project "${PROJECT_ID}" \
    --service-account "${SA}" \
    --no-allow-unauthenticated \
    --memory 1Gi --cpu 1 --timeout 3600 --max-instances 5 \
    --set-env-vars "^|^P2M_PROJECT_ID=${PROJECT_ID}|P2M_PROJECT_NUMBER=${PROJECT_NUMBER}|P2M_RUN_REGION=${REGION}|P2M_AGENT_REGISTRY_LOCATION=${AGENT_REGISTRY_LOCATION}|P2M_DISCOVERY_ENGINE_LOCATION=global|P2M_ARTIFACT_REPO=${REPO}|P2M_RUNTIME_IMAGE=${RUNTIME_LATEST}|P2M_MCP_SERVICE_ACCOUNT=${SA}|P2M_MANIFEST_BUCKET=${MANIFEST_BUCKET}|P2M_PUBLIC_BASE_URL=${public_url}|P2M_OAUTH_BASE_URL=${OAUTH_URL}|P2M_ALLOWED_PRINCIPALS=${ALLOWED_PRINCIPALS}" \
    --quiet
}

echo "==> Deploying control plane (pass 1)"
deploy "https://placeholder.invalid"

URL="$(gcloud run services describe "${SERVICE}" \
  --region "${REGION}" --project "${PROJECT_ID}" --format='value(status.url)')"

echo "==> Re-deploying with resolved public URL: ${URL}"
deploy "${URL}"

# Cloud Run IAM is the outer layer; P2M_ALLOWED_PRINCIPALS is the inner one.
# Both have to name you or nothing works, which is the intended behaviour --
# the app fails closed if ingress is ever misconfigured.
echo "==> Granting run.invoker to the allowed principals"
IFS=',' read -ra PRINCIPALS <<< "${ALLOWED_PRINCIPALS}"
for P in "${PRINCIPALS[@]}"; do
  P="$(echo "${P}" | xargs)"
  [[ -z "${P}" ]] && continue
  # A bare email is a user unless it looks like a service account.
  if [[ "${P}" == *".iam.gserviceaccount.com" ]]; then
    MEMBER="serviceAccount:${P}"
  else
    MEMBER="user:${P}"
  fi
  gcloud run services add-iam-policy-binding "${SERVICE}" \
    --region "${REGION}" --project "${PROJECT_ID}" \
    --member "${MEMBER}" --role roles/run.invoker --quiet >/dev/null
  echo "    ${MEMBER}"
done

# The connect stage talks to a v1alpha API with an untyped request field that
# has changed shape underneath a working deployment before. No test can catch
# that, because our code is not what changed -- only asking the live API can.
# Hourly is frequent enough to hear about it before a user does, and the probe
# creates nothing: it is rejected during request validation.
#
# The canary endpoint is now authenticated, so Scheduler has to present an OIDC
# token. It uses the control plane's own service account, which is already an
# allowed principal by construction -- but it must also be named in
# P2M_ALLOWED_PRINCIPALS, so it is appended below.
echo "==> Contract canary"
gcloud run services add-iam-policy-binding "${SERVICE}" \
  --region "${REGION}" --project "${PROJECT_ID}" \
  --member "serviceAccount:${SA}" --role roles/run.invoker --quiet >/dev/null
if gcloud scheduler jobs describe "${SERVICE}-canary" \
     --location "${REGION}" --project "${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud scheduler jobs update http "${SERVICE}-canary" \
    --location "${REGION}" --project "${PROJECT_ID}" \
    --schedule "0 * * * *" --uri "${URL}/v1/canary" --http-method GET \
    --oidc-service-account-email "${SA}" --oidc-token-audience "${URL}" --quiet
else
  gcloud scheduler jobs create http "${SERVICE}-canary" \
    --location "${REGION}" --project "${PROJECT_ID}" \
    --schedule "0 * * * *" --uri "${URL}/v1/canary" --http-method GET \
    --oidc-service-account-email "${SA}" --oidc-token-audience "${URL}" \
    --description "Fails when the Discovery Engine connector contract drifts" \
    --quiet
fi

cat <<EOF

Deployed.

  Control plane : ${URL}   (PRIVATE -- requires roles/run.invoker)
  OAuth proxy   : ${OAUTH_URL}   (public, by design)
  Runtime image : ${RUNTIME_LATEST}
  Allowed       : ${ALLOWED_PRINCIPALS}

The control plane is not reachable without an identity token, and the
interactive API docs are disabled. Both are deliberate: this service acts as a
service account that can create Cloud Run services and write Secret Manager
versions.

Open the UI in a browser:
  gcloud run services proxy ${SERVICE} --region ${REGION} --project ${PROJECT_ID}
  # then http://localhost:8080/ui/  -- the proxy attaches your identity token

Reaching it with curl -- send the token TWICE, in these two headers.
X-Serverless-Authorization is what Cloud Run checks; X-P2M-Authorization is
what the application checks. Cloud Run replaces a Google credential found in
Authorization or X-Serverless-Authorization with an assertion of its own, so a
token the app can verify has to travel in a header the platform ignores.
A plain \`gcloud auth print-identity-token\` is correct for a human; gcloud
refuses --audiences for user accounts.

  TOKEN=\$(gcloud auth print-identity-token)
  AUTH=(-H "X-Serverless-Authorization: Bearer \$TOKEN" -H "X-P2M-Authorization: Bearer \$TOKEN")

Smoke test:
  curl -s "\${AUTH[@]}" ${URL}/v1/buildinfo | jq

Check the connector contract has not drifted (503 means it has):
  curl -s "\${AUTH[@]}" ${URL}/v1/canary | jq

Provision an MCP:
  curl -s -X POST "${URL}/v1/mcps?wait=true" \\
    "\${AUTH[@]}" \\
    -H 'content-type: application/json' \\
    -d '{
      "description": "Tools to look up and create pets",
      "docs": {"openapi_url": "https://petstore3.swagger.io/api/v3/openapi.json"},
      "base_url": "https://petstore3.swagger.io/api/v3",
      "auth_kind": "none"
    }' | jq

Note on auth_kind: 'none' and 'api_key' servers hold or relay a credential and
are NOT published to allUsers. They are deployed private, with run.invoker
granted to the Gemini Enterprise service agent
(service-${PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com).
That path is unverified against a live Gemini Enterprise app -- if tool calls
come back 403, use auth_kind='oauth_user', or set
"allow_public_unauthenticated": true to accept the exposure knowingly.

Grant a colleague access:
  gcloud run services add-iam-policy-binding ${SERVICE} \\
    --region ${REGION} --project ${PROJECT_ID} \\
    --member user:them@example.com --role roles/run.invoker
  # ...and add them to P2M_ALLOWED_PRINCIPALS; both layers must name them.
EOF
