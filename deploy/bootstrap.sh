#!/usr/bin/env bash
# One-time bootstrap: APIs, Artifact Registry, Firestore, service account, IAM.
#
# Usage: PROJECT_ID=my-project ./deploy/bootstrap.sh
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-us-central1}"
REPO="${REPO:-prompt-to-mcp}"
SA_NAME="${SA_NAME:-prompt-to-mcp}"
SA="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
# The OAuth proxy runs as its own identity. It is the only half of the system
# that is deployed publicly, so it gets the two roles it actually needs rather
# than sharing the control plane's ten.
OAUTH_SA_NAME="${OAUTH_SA_NAME:-prompt-to-mcp-oauth}"
OAUTH_SA="${OAUTH_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
# Manifests larger than Cloud Run's 32 KiB env-var cap spill to this bucket.
# Named here because storage.objectAdmin is granted on the bucket alone, not
# project-wide.
MANIFEST_BUCKET="${MANIFEST_BUCKET:-${PROJECT_ID}-prompt-to-mcp-manifests}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "PROJECT_ID is required" >&2
  exit 1
fi

echo "==> Project: ${PROJECT_ID}  Region: ${REGION}"

echo "==> Enabling APIs"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  agentregistry.googleapis.com \
  discoveryengine.googleapis.com \
  aiplatform.googleapis.com \
  secretmanager.googleapis.com \
  firestore.googleapis.com \
  cloudscheduler.googleapis.com \
  --project "${PROJECT_ID}"

echo "==> Artifact Registry repo"
gcloud artifacts repositories create "${REPO}" \
  --repository-format=docker --location="${REGION}" \
  --description="prompt-to-mcp images" --project "${PROJECT_ID}" 2>/dev/null \
  || echo "    (already exists)"

echo "==> Firestore database"
gcloud firestore databases create --location="nam5" --project "${PROJECT_ID}" 2>/dev/null \
  || echo "    (already exists)"

echo "==> Manifest bucket"
gcloud storage buckets create "gs://${MANIFEST_BUCKET}" \
  --location="${REGION}" --uniform-bucket-level-access \
  --project "${PROJECT_ID}" 2>/dev/null \
  || echo "    (already exists)"

echo "==> Service accounts"
gcloud iam service-accounts create "${SA_NAME}" \
  --display-name="prompt-to-mcp control plane" --project "${PROJECT_ID}" 2>/dev/null \
  || echo "    (already exists)"
gcloud iam service-accounts create "${OAUTH_SA_NAME}" \
  --display-name="prompt-to-mcp OAuth proxy" --project "${PROJECT_ID}" 2>/dev/null \
  || echo "    (already exists)"

echo "==> IAM roles"
# Each add-iam-policy-binding is a read-modify-write of the whole project
# policy. Issuing them back to back reliably trips
# "There were concurrent policy changes", so retry with backoff.
add_binding() {
  local role="$1" member="${2:-serviceAccount:${SA}}" attempt=1 delay=3
  until gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
      --member="${member}" --role="${role}" \
      --condition=None --quiet >/dev/null 2>&1; do
    if (( attempt >= 6 )); then
      echo "    FAILED ${role} after ${attempt} attempts" >&2
      return 1
    fi
    sleep "${delay}"
    delay=$(( delay * 2 ))
    attempt=$(( attempt + 1 ))
  done
  echo "    granted ${role} to ${member#serviceAccount:}"
}

# Revoking matters as much as granting, and is easy to leave out.
#
# This script is documented as idempotent and is meant to be re-run on an
# existing project. Narrowing a role therefore has to be two operations: grant
# the replacement, then remove what it replaced. Without the second, an
# upgrading deployment keeps `secretmanager.admin` AND gains the narrower pair
# -- strictly more privilege than before, while the release notes claim the
# opposite. A least-privilege change that only ever adds is not one.
#
# Ordering is deliberate: the replacements are granted above, before anything
# is taken away, so there is no window in which the running service cannot
# reach its own secrets.
remove_binding() {
  local role="$1" member="${2:-serviceAccount:${SA}}" attempt=1 delay=3 output
  # Not an error: a fresh project never had the role, and a second run has
  # already removed it.
  if ! gcloud projects get-iam-policy "${PROJECT_ID}" \
       --flatten='bindings[].members' \
       --filter="bindings.members:${member#*:} AND bindings.role:${role}" \
       --format='value(bindings.role)' 2>/dev/null | grep -q .; then
    return 0
  fi
  until output="$(gcloud projects remove-iam-policy-binding "${PROJECT_ID}" \
      --member="${member}" --role="${role}" \
      --condition=None --quiet 2>&1)"; do
    if (( attempt >= 6 )); then
      echo "    FAILED to revoke ${role}: ${output}" >&2
      echo "    Revoke it by hand -- it is broader than this release needs." >&2
      return 1
    fi
    sleep "${delay}"
    delay=$(( delay * 2 ))
    attempt=$(( attempt + 1 ))
  done
  echo "    REVOKED ${role} from ${member#serviceAccount:}"
}

# run.admin              : create the generated MCP services
# iam.serviceAccountUser : act as the runtime SA when deploying them
# artifactregistry.reader: the SA is ALSO the runtime identity of every
#                          generated MCP service, so it must be able to pull
#                          the shared runtime image. Without this, Cloud Run
#                          rejects the create with
#                          "artifactregistry.repositories.downloadArtifacts denied".
# agentregistry.admin    : services.create/delete and bindings.*. Agent
#                          Registry has its OWN IAM surface -- aiplatform.user
#                          does NOT grant it, despite the API sharing the
#                          Vertex/AI Platform branding. agentregistry.editor is
#                          not enough either: it omits bindings.*.
# serviceusage.serviceUsageAdmin : auto-enable provider APIs (e.g. drivemcp)
# discoveryengine.admin  : authorizations + data connectors
# aiplatform.user        : Gemini/Vertex model calls for doc synthesis
# secretmanager.editor + secretAccessor
#                        : create, read, update and delete the OAuth client
#                          secrets and upstream API keys. Replaces
#                          secretmanager.admin, whose extra permission --
#                          secretmanager.secrets.setIamPolicy -- was the single
#                          most valuable thing an attacker could have reached
#                          through the (then unauthenticated) POST /v1/mcps:
#                          it grants the holder read access to every secret in
#                          the project by rewriting its policy. `editor` has
#                          create/delete/versions.add and NOT setIamPolicy,
#                          which is exactly the line we want.
#
#                          secretVersionAdder alone is not enough and was tried:
#                          it lacks secretmanager.secrets.create, so the first
#                          api_key provisioning run fails at the deploy stage
#                          with "Permission 'secretmanager.secrets.create'
#                          denied". It also lacks versions.access, which is why
#                          secretAccessor is granted alongside -- `editor`
#                          deliberately cannot read secret *values*.
# datastore.user         : Firestore state
#
# NOT granted project-wide: storage.objectAdmin. The only object access needed
# is the manifest spill-over bucket, so it is bound on that bucket below.
for ROLE in \
  roles/run.admin \
  roles/iam.serviceAccountUser \
  roles/artifactregistry.reader \
  roles/agentregistry.admin \
  roles/serviceusage.serviceUsageAdmin \
  roles/discoveryengine.admin \
  roles/aiplatform.user \
  roles/secretmanager.editor \
  roles/secretmanager.secretAccessor \
  roles/datastore.user
do
  add_binding "${ROLE}"
done

# The OAuth proxy is deployed publicly, so it gets the smallest surface that
# still lets it work: read/write its own Firestore client records, and read the
# upstream client secrets it has to present at /token. It cannot create
# secrets, deploy services, or touch Discovery Engine.
echo "    -- OAuth proxy service account --"
for ROLE in \
  roles/datastore.user \
  roles/secretmanager.secretAccessor
do
  add_binding "${ROLE}" "serviceAccount:${OAUTH_SA}"
done

# Bucket-scoped, not project-wide. A project-level objectAdmin lets the holder
# read and overwrite every object in every bucket, which for a service that
# only ever writes manifests/<id>.json is several orders too much.
echo "==> Manifest bucket IAM"
gcloud storage buckets add-iam-policy-binding "gs://${MANIFEST_BUCKET}" \
  --member="serviceAccount:${SA}" --role="roles/storage.objectAdmin" \
  --project "${PROJECT_ID}" --quiet >/dev/null
echo "    granted roles/storage.objectAdmin on gs://${MANIFEST_BUCKET}"

# Now withdraw what the grants above replaced. Only reachable once the
# replacements are in place, so an upgrade never leaves the service unable to
# read the secrets it is mid-flight on.
#
#   secretmanager.admin  -> secretVersionAdder + secretAccessor (granted above).
#       The admin role additionally allows setting IAM policy on every secret
#       in the project, which was the single most valuable thing reachable
#       through the previously unauthenticated POST /v1/mcps.
#   storage.objectAdmin  -> the same role, bound on the manifest bucket only
#       (granted above). Project-wide it permits reading and overwriting every
#       object in every bucket, for a service that writes manifests/<id>.json.
echo "==> Revoking superseded roles"
remove_binding "roles/secretmanager.admin"
# Granted by 1.0.2 before it was found to be insufficient; `editor` supersedes it.
remove_binding "roles/secretmanager.secretVersionAdder"
remove_binding "roles/storage.objectAdmin"

echo
echo "Bootstrap complete."
echo "  Control plane SA : ${SA}"
echo "  OAuth proxy SA   : ${OAUTH_SA}"
echo "  Manifest bucket  : gs://${MANIFEST_BUCKET}"
echo
echo "The control plane will NOT be publicly reachable. Grant yourself access:"
echo "  gcloud run services add-iam-policy-binding prompt-to-mcp \\"
echo "    --region ${REGION} --project ${PROJECT_ID} \\"
echo "    --member=user:\$(gcloud config get-value account) --role=roles/run.invoker"
echo "and set P2M_ALLOWED_PRINCIPALS to the same identity (deploy.sh does this"
echo "for the account running it)."
echo
echo "  Next: ./deploy/deploy.sh"
