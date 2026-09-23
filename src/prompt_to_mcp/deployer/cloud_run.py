"""Deploy a generated MCP server to Cloud Run (``run.googleapis.com`` v2).

Design note: every generated MCP shares **one** prebuilt runtime image. The
manifest is injected as configuration, so provisioning a new MCP is a Cloud Run
service create (seconds) rather than a container build (minutes), and no
model-authored code is ever compiled or executed.

Ingress and IAM
---------------
Through 1.0.1 every generated service was granted ``roles/run.invoker`` to
``allUsers``, justified by this argument:

    the generated server is a pure pass-through: it stores no credentials and
    grants no access of its own, so every request must still carry a bearer
    token that the upstream API independently validates.

**That is true for two of the four auth kinds and false for the other two**,
and the version of it that used to sit here did not say which. Stated
accurately:

``oauth_user``
    Safe to publish. The service holds nothing. The end user's upstream token
    arrives on the request and is forwarded unvalidated
    (``runtime/server.py:142-156``); a request without a usable token gets an
    error from the upstream, not data. Anonymous transport access buys an
    attacker no credential.
``google_id_token``
    Safe to publish. The token is minted per call from the service's own
    metadata-server identity and is scoped to the upstream audience. Reaching
    the service does not yield the token.
``api_key``
    **Not safe to publish.** The service *does* hold a credential: ``P2M_API_KEY``
    is bound to a Secret Manager version below (``_api_key_env``) and
    ``runtime/server.py:158-166,179-187`` injects it into every upstream call.
    No inbound credential is required or checked. Published to ``allUsers``
    this is an internet-facing proxy that spends the customer's API key for
    anyone who finds the URL -- a confused deputy, and depending on the
    upstream either direct financial loss or data exfiltration.
``none``
    **Not safe to publish.** An open relay to ``base_url``, usable to launder
    traffic through the customer's GCP identity.

So ``allow_unauthenticated`` now defaults to ``False`` and the caller must ask
for public exposure deliberately. :mod:`prompt_to_mcp.pipeline` makes that
decision from the manifest's auth kind at the deploy stage.

For the two unsafe kinds the service is instead deployed private, with
``roles/run.invoker`` granted to the principals in ``invoker_principals`` --
by default the Gemini Enterprise (Discovery Engine) service agent.

    **Unverified.** Cloud Run authorises a caller only if it presents a
    Google-signed ID token audienced to the service. Whether the Discovery
    Engine connector does so when calling an MCP endpoint has never been
    observed: the note this docstring replaced asserted it does not, but that
    was an inference from the design, and ``SESSION.md`` §24 records that no
    real Gemini Enterprise query was ever traced to a generated server. It is
    worth noting the collision that inference was probably reasoning about --
    in ``oauth_user`` mode the upstream token occupies ``Authorization``, where
    a Cloud Run ID token also wants to sit. That collision does not exist for
    ``api_key`` or ``none``, which ignore the inbound header entirely, so the
    private path is unobstructed for exactly the kinds that need it.

    If it turns out GE sends no ID token, tool calls return 403 and the
    operator has two documented ways forward: switch to
    ``auth_kind="oauth_user"``, or set ``allow_public_unauthenticated`` on the
    request and accept the exposure knowingly.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from ..gcp.base import GoogleApiClient, GoogleApiError

log = logging.getLogger(__name__)

BASE = "https://run.googleapis.com/v2"

#: Cloud Run caps the *total* size of environment variables at 32 KiB. Stay
#: well clear of it and spill larger manifests to Cloud Storage.
INLINE_MANIFEST_LIMIT = 24_000

#: Reachable from anywhere. Correct for a service published to ``allUsers``,
#: and also for a private service that a Google-managed caller such as Gemini
#: Enterprise reaches over the internet with an ID token -- ingress and IAM are
#: independent controls.
INGRESS_ALL = "INGRESS_TRAFFIC_ALL"

#: Reachable only from within the VPC or an internal load balancer. Used when
#: public access was refused *and* no invoker principal is configured, i.e.
#: when there is no identified caller to let in: closing the network as well as
#: IAM makes the intent unambiguous to anyone reading the console later.
INGRESS_INTERNAL_LB = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"


@dataclass(slots=True)
class DeploymentResult:
    service_name: str
    uri: str
    mcp_endpoint: str
    revision: str | None = None
    manifest_location: str = "inline"


class CloudRunDeployer:
    def __init__(
        self,
        api: GoogleApiClient,
        project_id: str,
        region: str,
        *,
        runtime_image: str,
        service_account: str | None = None,
        manifest_bucket: str | None = None,
    ) -> None:
        self.api = api
        self.project_id = project_id
        self.region = region
        self.runtime_image = runtime_image
        self.service_account = service_account
        self.manifest_bucket = manifest_bucket

    @property
    def parent(self) -> str:
        return f"projects/{self.project_id}/locations/{self.region}"

    # ------------------------------------------------------------------
    async def _manifest_env(self, service_id: str, manifest: dict[str, Any]) -> tuple[dict, str]:
        blob = json.dumps(manifest, separators=(",", ":"))
        if len(blob.encode()) <= INLINE_MANIFEST_LIMIT:
            return {"name": "P2M_MANIFEST", "value": blob}, "inline"

        if not self.manifest_bucket:
            raise ValueError(
                f"manifest is {len(blob.encode())} bytes, over the {INLINE_MANIFEST_LIMIT} byte "
                "inline limit, and no manifest_bucket is configured. Set P2M_MANIFEST_BUCKET."
            )

        import asyncio

        from google.cloud import storage

        def _upload() -> str:
            client = storage.Client(project=self.project_id)
            bucket = client.bucket(self.manifest_bucket)
            blob_obj = bucket.blob(f"manifests/{service_id}.json")
            blob_obj.upload_from_string(blob, content_type="application/json")
            return f"gs://{self.manifest_bucket}/manifests/{service_id}.json"

        uri = await asyncio.to_thread(_upload)
        log.info("manifest for %s spilled to %s", service_id, uri)
        return {"name": "P2M_MANIFEST_GCS", "value": uri}, uri

    @staticmethod
    def _api_key_env(secret_ref: str) -> dict[str, Any]:
        """Bind ``P2M_API_KEY`` to a Secret Manager version.

        A ``secretKeyRef`` rather than a literal, so the key never appears in
        the service's configuration, in `gcloud run services describe`, or in
        the deployment audit log -- all of which a plain env var would expose to
        anyone with viewer access. Cloud Run resolves it at instance start-up
        using the service account's own permissions.

        Accepts either a bare secret id, ``projects/P/secrets/S`` or a pinned
        ``projects/P/secrets/S/versions/N``; the API wants the secret and the
        version as separate fields.
        """
        version = "latest"
        ref = secret_ref
        if "/versions/" in ref:
            ref, _, version = ref.partition("/versions/")
        return {
            "name": "P2M_API_KEY",
            "valueSource": {"secretKeyRef": {"secret": ref, "version": version}},
        }

    def _service_body(
        self,
        manifest_env: dict[str, Any],
        *,
        description: str,
        labels: dict[str, str] | None = None,
        min_instances: int = 0,
        max_instances: int = 10,
        api_key_secret: str | None = None,
        ingress: str = INGRESS_ALL,
    ) -> dict[str, Any]:
        env = [
            manifest_env,
            {"name": "LOG_LEVEL", "value": "INFO"},
        ]
        if api_key_secret:
            env.append(self._api_key_env(api_key_secret))
        template: dict[str, Any] = {
            "containers": [
                {
                    "image": self.runtime_image,
                    "ports": [{"name": "http1", "containerPort": 8080}],
                    "env": env,
                    "resources": {
                        # `limits` accepts only cpu / memory / nvidia.com/gpu,
                        # and every value must be a string. `cpuIdle` is a
                        # sibling boolean, not a limit -- and when `resources`
                        # is set at all it must be stated explicitly to keep
                        # the default request-scoped CPU behaviour.
                        "limits": {"cpu": "1", "memory": "512Mi"},
                        "cpuIdle": True,
                        "startupCpuBoost": True,
                    },
                    "startupProbe": {
                        "httpGet": {"path": "/healthz", "port": 8080},
                        "initialDelaySeconds": 2,
                        "periodSeconds": 3,
                        "failureThreshold": 10,
                    },
                }
            ],
            "scaling": {"minInstanceCount": min_instances, "maxInstanceCount": max_instances},
            "timeout": "300s",
            "maxInstanceRequestConcurrency": 40,
        }
        if self.service_account:
            template["serviceAccount"] = self.service_account

        return {
            "description": description[:512],
            "labels": {"managed-by": "prompt-to-mcp", **(labels or {})},
            "ingress": ingress,
            "launchStage": "GA",
            "template": template,
            "traffic": [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST", "percent": 100}],
        }

    # ------------------------------------------------------------------
    async def deploy(
        self,
        service_id: str,
        manifest: dict[str, Any],
        *,
        description: str = "",
        labels: dict[str, str] | None = None,
        allow_unauthenticated: bool = False,
        invoker_principals: list[str] | None = None,
        ingress: str | None = None,
        wait: bool = True,
        api_key_secret: str | None = None,
    ) -> DeploymentResult:
        """Create or update the service, then grant invoke access.

        ``allow_unauthenticated`` defaults to ``False``. It used to default to
        ``True``, which meant every caller that did not think about the
        question published a service to the whole internet -- including
        :mod:`prompt_to_mcp.pipeline`, which never passed the argument at all.
        The unsafe choice now has to be made out loud.

        ``invoker_principals`` is the alternative to public exposure: IAM
        members granted ``roles/run.invoker``. Both may be supplied; they are
        not mutually exclusive.
        """
        invokers = list(invoker_principals or [])
        if ingress is None:
            # Public, or private-but-reachable-by-someone, both need ordinary
            # ingress; IAM is what distinguishes them. Only a service nobody is
            # allowed to call gets the network closed too.
            ingress = INGRESS_ALL if (allow_unauthenticated or invokers) else INGRESS_INTERNAL_LB

        manifest_env, location = await self._manifest_env(service_id, manifest)
        body = self._service_body(
            manifest_env,
            description=description,
            labels=labels,
            api_key_secret=api_key_secret,
            ingress=ingress,
        )
        services_url = f"{BASE}/{self.parent}/services"

        try:
            operation = await self.api.post(
                services_url, json=body, params={"serviceId": service_id}
            )
        except GoogleApiError as exc:
            if exc.status != 409:
                raise
            log.info("cloud run service %s exists; updating", service_id)
            operation = await self.api.patch(f"{services_url}/{service_id}", json=body)

        service: dict[str, Any] = operation
        if wait and "/operations/" in operation.get("name", ""):
            service = await self.api.poll_operation(
                f"{BASE}/{operation['name']}", interval=4.0, timeout=600.0
            )

        if not service.get("uri"):
            service = await self.api.get(f"{services_url}/{service_id}")

        uri = service.get("uri")
        if not uri:
            raise RuntimeError(f"cloud run service {service_id} reported no URI: {service}")

        members = list(invokers)
        if allow_unauthenticated:
            log.warning(
                "publishing %s to allUsers: anyone who finds its URL may invoke it",
                service_id,
            )
            members.append("allUsers")
        if members:
            await self._grant_invoker(service_id, members)

        return DeploymentResult(
            service_name=service.get("name", f"{self.parent}/services/{service_id}"),
            uri=uri,
            mcp_endpoint=f"{uri.rstrip('/')}/mcp",
            revision=service.get("latestReadyRevision"),
            manifest_location=location,
        )

    async def _grant_invoker(self, service_id: str, members: list[str]) -> None:
        """Add ``members`` to ``roles/run.invoker``, preserving the rest of the policy.

        Read-modify-write with the ``etag``. The previous implementation POSTed
        a policy containing one binding and nothing else, which is a *replace*:
        any other binding on the service was silently discarded, and two
        concurrent writers would clobber each other with no error. Sending back
        the etag makes a lost update a 409 instead of a silent one.
        """
        service = f"{BASE}/{self.parent}/services/{service_id}"
        try:
            policy: dict[str, Any] = await self.api.get(f"{service}:getIamPolicy")
        except GoogleApiError as exc:
            # A service with no policy yet can 404 here; starting from an empty
            # policy is correct in that case and harmless otherwise.
            log.info("no existing IAM policy on %s (%s); starting from empty", service_id, exc)
            policy = {}

        bindings: list[dict[str, Any]] = list(policy.get("bindings") or [])
        binding = next((b for b in bindings if b.get("role") == "roles/run.invoker"), None)
        if binding is None:
            binding = {"role": "roles/run.invoker", "members": []}
            bindings.append(binding)

        existing = list(binding.get("members") or [])
        added = [m for m in members if m not in existing]
        if not added:
            log.info("%s already grants run.invoker to %s", service_id, ", ".join(members))
            return
        binding["members"] = existing + added

        new_policy: dict[str, Any] = {"bindings": bindings}
        if policy.get("etag"):
            new_policy["etag"] = policy["etag"]

        try:
            await self.api.post(f"{service}:setIamPolicy", json={"policy": new_policy})
            log.info("granted run.invoker on %s to %s", service_id, ", ".join(added))
        except GoogleApiError as exc:
            # Org policy `iam.allowedPolicyMemberDomains` commonly blocks
            # allUsers. Surface it clearly instead of failing the whole run.
            log.warning(
                "could not grant run.invoker on %s to %s (%s). Gemini Enterprise will not be "
                "able to reach the MCP until ingress is resolved; check the "
                "iam.allowedPolicyMemberDomains org policy.",
                service_id,
                ", ".join(added),
                exc,
            )

    async def delete(self, service_id: str) -> None:
        try:
            await self.api.delete(f"{BASE}/{self.parent}/services/{service_id}")
        except GoogleApiError as exc:
            if exc.status != 404:
                raise
