"""Authentication for the control plane.

Why this exists
---------------
The provisioning API runs as a service account that can create Cloud Run
services, act as other service accounts, write Secret Manager versions and
administer Discovery Engine. An unauthenticated request to ``POST /v1/mcps`` is
therefore not "an unwanted MCP server" -- it is arbitrary workload execution
inside the customer's project. Through 1.0.1 there was no check of any kind and
``deploy.sh`` published the service with ``--allow-unauthenticated``.

Two layers, deliberately
------------------------
``deploy/deploy.sh`` no longer passes ``--allow-unauthenticated``, so Cloud Run
requires ``roles/run.invoker`` before a request reaches this process. That is
the primary control, and on its own it would be enough -- right up until
somebody re-adds the flag, fronts the service with a load balancer that strips
the requirement, or copies the deploy command into their own pipeline. It is a
deploy-time argument, which means it is one careless edit from being gone, and
nothing in the running service would notice.

So the same check is made again here, in the application, against the same
Google-signed ID token. Defence in depth is worth the duplication when the
failure mode of the outer layer is silent.

Two credentials, because a browser has no bearer token
------------------------------------------------------
A browser cannot set an ``Authorization`` header, so it can never satisfy a
bearer check -- no amount of being signed in to Google helps. Opening the UI
therefore requires something in front that authenticates the human and tells
the application who they are, which is Identity-Aware Proxy.

Two credential types are accepted, in this order:

* an **IAP assertion** (``X-Goog-IAP-JWT-Assertion``), which is how a browser
  arrives once IAP is enabled on the service;
* a **Google-signed OIDC ID token** in a bearer header, which is how ``curl``,
  CI and ``make check-deployed`` arrive.

Both end at the same allowlist check, so authorization is decided in one place
regardless of how the caller authenticated.

Fail closed
-----------
An empty ``allowed_principals`` denies everyone. It is tempting to treat "no
allowlist configured" as "allowlist not in use, let everything through", and
that reading is how unauthenticated defaults get reintroduced by accident --
the service comes up, answers requests, and looks healthy. Opening the service
requires setting ``P2M_ALLOW_UNAUTHENTICATED=1``, which is loud, logs a warning
on every startup, and is obviously wrong in a production environment listing.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import Settings, get_settings

log = logging.getLogger(__name__)

#: Environment variable that disables authentication entirely.
#:
#: Local development only. Named for what it does rather than something
#: reassuring like ``P2M_DEV_MODE``, so that finding it set on a deployed
#: service is self-evidently a problem.
ALLOW_UNAUTHENTICATED_ENV = "P2M_ALLOW_UNAUTHENTICATED"

#: ``auto_error=False`` so a missing header reaches our own handler and gets a
#: 401 describing what to send, rather than FastAPI's bare ``Not authenticated``.
_bearer = HTTPBearer(auto_error=False, description="Google-signed OIDC ID token")

#: gcloud's own OAuth client ID, and the audience of every ID token minted for
#: a *user* account.
#:
#: This is not a nicety. ``gcloud auth print-identity-token --audiences=URL``
#: fails outright for a human:
#:
#:     ERROR: (gcloud.auth.print-identity-token) Invalid account type for
#:     `--audiences`. Requires valid service account.
#:
#: so an operator cannot mint a token audienced to this service at all. Without
#: accepting this audience the control plane is reachable only by service
#: accounts, and every documented ``curl`` -- including ``make check-deployed``
#: and the deploy.sh smoke test -- returns 401. Cloud Run's own IAM check
#: accepts it, which is exactly why
#: ``curl -H "Authorization: Bearer $(gcloud auth print-identity-token)"`` is
#: the documented way to call a private service.
#:
#: The trade-off is real and worth stating: this audience is universal, so a
#: token a user obtained through gcloud for some other purpose satisfies the
#: audience check here. Two things still stand between that and access -- the
#: principal allowlist, and Cloud Run's ``roles/run.invoker`` requirement --
#: and ``extra_allowed_audiences`` can be set empty to refuse it entirely and
#: accept service-account callers only.
GCLOUD_CLI_AUDIENCE = "32555940559.apps.googleusercontent.com"


def allow_unauthenticated() -> bool:
    """Whether the development escape hatch is set. Defaults to off."""
    return os.getenv(ALLOW_UNAUTHENTICATED_ENV, "").strip().lower() in ("1", "true", "yes")


def warn_if_unauthenticated() -> None:
    """Log the escape hatch at startup, every time, at WARNING."""
    if allow_unauthenticated():
        log.warning(
            "%s is set: the control plane accepts UNAUTHENTICATED requests. "
            "This is for local development only. On Cloud Run it exposes "
            "provisioning, teardown and secret writes to anyone who finds the "
            "URL. Unset it and grant roles/run.invoker instead.",
            ALLOW_UNAUTHENTICATED_ENV,
        )


class Principal:
    """The verified caller.

    ``email`` is preferred over ``sub`` because it is what an operator writes
    in ``allowed_principals`` and what shows up in audit logs; ``sub`` is the
    stable fallback for tokens issued without an email claim.
    """

    __slots__ = ("email", "subject", "claims")

    def __init__(self, *, email: str | None, subject: str, claims: dict[str, Any]) -> None:
        self.email = email
        self.subject = subject
        self.claims = claims

    @property
    def name(self) -> str:
        return self.email or self.subject

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Principal({self.name!r})"


#: The principal attached to requests when the escape hatch is on. Given a name
#: that cannot be mistaken for a real identity if it ends up in a log line.
DEV_PRINCIPAL = Principal(
    email="dev-unauthenticated@localhost", subject="dev", claims={"dev": True}
)

#: Attached to requests on an exempt path. Distinct from :data:`DEV_PRINCIPAL`
#: so a log line can tell "auth was off" apart from "this route never had auth".
ANONYMOUS = Principal(email=None, subject="anonymous", claims={})


def _audiences(settings: Settings) -> list[str]:
    """Acceptable ``aud`` values for an inbound ID token.

    Three groups:

    * the service URL, which is what a *service account* sends, and what Cloud
      Run's own IAM check audiences against;
    * the same with a trailing slash, because that mismatch produces a 401 that
      looks nothing like its cause;
    * whatever ``extra_allowed_audiences`` adds, which defaults to
      :data:`GCLOUD_CLI_AUDIENCE` so that a human operator can authenticate at
      all. See that constant for why there is no alternative.
    """
    base = settings.public_base_url.rstrip("/")
    return [base, f"{base}/", *settings.extra_allowed_audiences]


def verify_id_token(token: str, settings: Settings, *, source: str = "authorization") -> Principal:
    """Verify a Google-signed OIDC ID token, or raise 401.

    Signature, issuer and expiry are checked by ``google-auth`` against
    Google's published certificates. Audience is checked here rather than by
    passing it in, so that a mismatch can be reported as its own message --
    ``aud`` errors are otherwise indistinguishable from a bad signature, and
    the two have completely different fixes.
    """
    # Imported lazily: google-auth pulls in a certificate cache and a transport
    # at import time, which is wasted work for a process that never sees a
    # request (tests, --check, the packaging smoke test).
    import google.auth.transport.requests
    import google.oauth2.id_token
    from google.auth.exceptions import GoogleAuthError

    try:
        claims: dict[str, Any] = google.oauth2.id_token.verify_oauth2_token(
            token, google.auth.transport.requests.Request()
        )
    except (GoogleAuthError, ValueError) as exc:
        # The exception text can contain fragments of the token, so log the
        # type -- plus the length and segment count, which carry no token
        # material and are the two facts that actually distinguish the causes.
        # A MalformedError on a 3-segment token of plausible length means a
        # genuinely bad signature; on anything else it means the header was
        # mangled before it arrived, and chasing that as a crypto problem
        # wastes an afternoon.
        log.info(
            "ID token rejected: %s (from %s, %d chars, %d segments, jwt-shaped=%s)",
            type(exc).__name__,
            source,
            len(token),
            token.count(".") + 1,
            token.startswith("eyJ"),
        )
        raise HTTPException(
            status_code=401,
            detail="invalid ID token: not a valid, unexpired, Google-signed OIDC token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    audience = claims.get("aud")
    if audience not in _audiences(settings):
        log.info("ID token audience mismatch: %r", audience)
        raise HTTPException(
            status_code=401,
            detail=(
                "ID token audience does not match this service. A service account "
                f"should mint it with --audiences={settings.public_base_url}; a user "
                "account should use a plain `gcloud auth print-identity-token` "
                "(gcloud refuses --audiences for user accounts)."
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = claims.get("email")
    if email is not None and claims.get("email_verified") is False:
        # An unverified email must not be matched against the allowlist: the
        # allowlist is written in terms of addresses, and an unverified one is
        # an assertion the issuer declined to stand behind.
        log.info("ID token carries an unverified email claim")
        email = None

    subject = str(claims.get("sub") or "")
    if not subject and not email:
        raise HTTPException(
            status_code=401,
            detail="ID token carries neither a subject nor a verified email claim",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Principal(email=email, subject=subject, claims=claims)


def _unverified_claim(token: str, name: str) -> Any:
    """Read one claim without verifying anything. Diagnostics only.

    Never use the result for a decision: the payload of an unverified JWT is
    attacker-controlled. It exists so a rejected assertion can say *why* in a
    log line instead of leaving an operator to guess.
    """
    import base64
    import json

    try:
        payload = token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(padded)).get(name)
    except Exception:  # noqa: BLE001 - a malformed token is the normal case here
        return None


def verify_iap_assertion(token: str, settings: Settings) -> Principal:
    """Verify an Identity-Aware Proxy JWT assertion, or raise 401.

    This is the browser path. A browser cannot set an ``Authorization`` header,
    so it can never present a bearer token; IAP performs the Google sign-in in
    front of Cloud Run and states the result in a signed assertion.

    Three checks, none of them optional:

    * **Signature**, against IAP's own key set. These are not the certificates
      that sign OIDC ID tokens, which is why this cannot reuse
      :func:`verify_id_token`.
    * **Audience**, naming this exact Cloud Run service. An assertion proves
      "IAP authenticated this person for *some* resource"; without pinning the
      resource, an assertion minted for an unrelated IAP-protected app in an
      unrelated project would be accepted here.
    * **Issuer**, which ``verify_token`` does not check for us.

    The ``X-Goog-Authenticated-User-Email`` header carries the same identity
    and is deliberately ignored: it is a plain unsigned string, so anything
    that reaches the container without going through IAP can set it freely.
    """
    import google.auth.transport.requests
    import google.oauth2.id_token
    from google.auth.exceptions import GoogleAuthError

    audience = settings.expected_iap_audience
    if not audience:
        # Fail closed. The alternative -- skipping the audience check when it
        # cannot be derived -- turns a missing config value into "accept any
        # IAP assertion from anywhere", which is the failure this check exists
        # to prevent.
        log.warning(
            "received an IAP assertion but no audience is configured. Set "
            "P2M_PROJECT_NUMBER (preferred) or P2M_IAP_AUDIENCE to "
            "/projects/<number>/locations/<region>/services/<service>."
        )
        raise HTTPException(
            status_code=401,
            detail=(
                "this service cannot verify IAP assertions: no expected audience "
                "is configured. Set P2M_PROJECT_NUMBER or P2M_IAP_AUDIENCE."
            ),
        )

    try:
        claims: dict[str, Any] = google.oauth2.id_token.verify_token(
            token,
            google.auth.transport.requests.Request(),
            audience=audience,
            certs_url=IAP_CERTS_URL,
        )
    except (GoogleAuthError, ValueError) as exc:
        # Report the audience we were offered alongside the one we wanted.
        #
        # An audience mismatch and a bad signature raise the same exception
        # type, and they have nothing in common as problems: one is a
        # configuration error that every request will repeat, the other is an
        # attack or a key rotation. Without the two values side by side the
        # operator's only evidence is "IAP says you are signed in, the app says
        # you are not". The claims are read *unverified* and used for nothing
        # but this log line.
        log.info(
            "IAP assertion rejected: %s (%d chars, %d segments, aud=%r, iss=%r, "
            "expected aud=%r)",
            type(exc).__name__,
            len(token),
            token.count(".") + 1,
            _unverified_claim(token, "aud"),
            _unverified_claim(token, "iss"),
            audience,
        )
        raise HTTPException(
            status_code=401,
            detail=(
                "invalid IAP assertion: not a valid, unexpired assertion for "
                "this service"
            ),
        ) from exc

    issuer = claims.get("iss")
    if issuer != IAP_ISSUER:
        log.info("IAP assertion issuer mismatch: %r", issuer)
        raise HTTPException(status_code=401, detail="IAP assertion has an unexpected issuer")

    # For Google identities `email` is a bare address and `sub` is prefixed
    # with `accounts.google.com:`. The allowlist is written in addresses, so a
    # token without one cannot be authorized no matter what else it carries --
    # which is also the correct outcome for Identity Platform identities, whose
    # email claim is prefixed and will not match.
    email = claims.get("email")
    if not email:
        raise HTTPException(
            status_code=401, detail="IAP assertion carries no email claim"
        )
    return Principal(email=email, subject=str(claims.get("sub") or ""), claims=claims)


def check_allowed(principal: Principal, settings: Settings) -> None:
    """Authorize a verified principal, or raise 403.

    Separate from verification because the two failures mean different things
    to whoever is holding the token: 401 is "this token is no good", 403 is
    "this token is fine and you still may not".
    """
    allowed = {p.strip().lower() for p in settings.allowed_principals if p.strip()}
    if not allowed:
        log.warning(
            "denying %s: allowed_principals is empty. An empty allowlist denies "
            "everyone by design. Set P2M_ALLOWED_PRINCIPALS to the operators who "
            "may provision MCP servers.",
            principal.name,
        )
        raise HTTPException(
            status_code=403,
            detail=(
                "no principals are allowed to call this service. Set "
                "P2M_ALLOWED_PRINCIPALS to a comma-separated list of the identities "
                "that may provision MCP servers."
            ),
        )

    candidates = {c.lower() for c in (principal.email, principal.subject) if c}
    if not (candidates & allowed):
        log.warning("denying %s: not in allowed_principals", principal.name)
        raise HTTPException(
            status_code=403,
            detail=f"principal {principal.name!r} is not allowed to call this service",
        )


def settings_for(request: Request) -> Settings:
    """The settings this app was built with.

    Read off ``app.state`` rather than via :func:`get_settings`, whose
    ``lru_cache`` returns the process-wide instance built from the environment.
    ``create_app`` accepts an explicit ``Settings``, and an auth check that
    consulted a different object than the rest of the app would be a subtle and
    very unpleasant bug.
    """
    configured = getattr(request.app.state, "settings", None)
    return configured if isinstance(configured, Settings) else get_settings()


#: Paths served without authentication.
#:
#: Exactly one entry, and it should stay that way. ``/healthz`` is the Cloud Run
#: startup probe: it is called by the platform before any identity exists, and
#: it discloses nothing -- a literal ``{"status": "ok"}`` with no build, project
#: or configuration detail. Everything that used to be readable from ``/readyz``
#: now lives behind auth at ``/v1/buildinfo``.
EXEMPT_PATHS: frozenset[str] = frozenset({"/healthz"})


#: Headers a bearer token may arrive in, in priority order.
#:
#: ``X-Serverless-Authorization`` is deliberately **absent**, and that is the
#: whole subtlety of this list.
#:
#: Cloud Run treats that header as its own transport for the IAM check, and
#: documents what it does with it: "Cloud Run passes this header to your
#: service after stripping its signature."[1] The container therefore receives
#: a JWT-shaped value -- three segments, correct prefix, ~557 characters -- that
#: can never verify. Measured against a live service, an 872-character ID token
#: sent in that header arrived as 557 characters and failed as ``MalformedError``.
#:
#: Listing it as a fallback is worse than useless. Anything fronted by Cloud Run
#: IAM populates it on *every* request, so a caller who correctly authenticated
#: some other way would have their real credential ignored in favour of a
#: guaranteed-invalid one, and be told their token was bad. Under IAP that is
#: permanent: IAP authenticates to Cloud Run through this very header, so every
#: IAP request carries a stripped token and the IAP assertion would never be
#: reached.
#:
#: ``Authorization`` *is* forwarded intact -- verified against a live private
#: service, where a plain ``Authorization: Bearer <id-token>`` both satisfied
#: Cloud Run's IAM check and arrived verifiable. It is the normal case.
#: ``X-P2M-Authorization`` is kept ahead of it as an explicit override for any
#: future platform that does consume the standard header.
#:
#: [1] https://cloud.google.com/iap/docs/enabling-cloud-run#known-limitations
BEARER_HEADERS = ("x-p2m-authorization", "authorization")

#: Header carrying IAP's signed statement about the end user.
#:
#: Distinct from the bearer headers because it is not a bearer credential: it
#: has no ``Bearer`` prefix, a different issuer, a different key set and a
#: different audience format.
IAP_ASSERTION_HEADER = "x-goog-iap-jwt-assertion"

#: Issuer of every IAP assertion.
IAP_ISSUER = "https://cloud.google.com/iap"

#: IAP's signing keys. A distinct key set from Google's OIDC certificates,
#: which is why the assertion cannot be checked with ``verify_oauth2_token``.
IAP_CERTS_URL = "https://www.gstatic.com/iap/verify/public_key"


def _bearer_token(request: Request) -> tuple[str, str]:
    """The inbound bearer token and the header it came from.

    A header sent twice is joined by the ASGI layer into ``Bearer a, Bearer b``.
    Feeding that whole string to the JWT parser reports a malformed *token*,
    which blames the credential for what is really a duplicated header. JWTs are
    base64url and contain no commas, so taking the first credential is
    unambiguous.
    """
    for name in BEARER_HEADERS:
        raw = request.headers.get(name, "").split(",")[0].strip()
        if not raw:
            continue
        scheme, _, token = raw.partition(" ")
        token = token.strip()
        if scheme.lower() == "bearer" and token:
            return token, name
    return "", ""


async def authenticate(request: Request) -> Principal:
    """Verify and authorize a raw request, or raise ``HTTPException``.

    Kept separate from the FastAPI dependency below so the same code path can
    guard the mounted static UI, which is an ASGI sub-application and therefore
    invisible to route dependencies. One implementation, two callers: a second
    copy of this logic is exactly how one of them would end up subtly weaker.
    """
    if allow_unauthenticated():
        request.state.principal = DEV_PRINCIPAL
        return DEV_PRINCIPAL

    if request.url.path in EXEMPT_PATHS:
        request.state.principal = ANONYMOUS
        return ANONYMOUS

    settings = settings_for(request)

    # IAP first. When it is in front, every request carries an assertion, and
    # a browser has nothing else to offer -- it cannot set a bearer header at
    # all. Checking it first also keeps the bearer branch's error messages
    # about bearer tokens, rather than reporting "missing bearer token" to a
    # user who authenticated perfectly well by signing in to Google.
    assertion = request.headers.get(IAP_ASSERTION_HEADER, "").strip()
    if assertion:
        principal = verify_iap_assertion(assertion, settings)
        check_allowed(principal, settings)
        request.state.principal = principal
        return principal

    token, source = _bearer_token(request)
    if not token:
        raise HTTPException(
            status_code=401,
            detail=(
                "missing credentials. From a browser, reach this service through "
                "Identity-Aware Proxy. Programmatically, send a Google-signed ID "
                "token: TOKEN=$(gcloud auth print-identity-token); curl -H "
                '"Authorization: Bearer $TOKEN" <url>. Use X-P2M-Authorization '
                "instead if something in front of this service consumes the "
                "standard header."
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )

    principal = verify_id_token(token, settings, source=source)
    check_allowed(principal, settings)
    request.state.principal = principal
    return principal


async def require_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    """FastAPI dependency: a verified, allowlisted caller.

    Attached to the whole app in :func:`prompt_to_mcp.main.create_app`, so a
    route added later is guarded by default. Forgetting to protect a new
    endpoint is the realistic failure here, not forgetting to unprotect one.

    ``credentials`` is declared but unused: it exists so the bearer scheme
    appears in the OpenAPI document and the ``Authorize`` button works in the
    dev-mode docs UI. The header is re-read from the request inside
    :func:`authenticate`, which is the shared implementation.
    """
    del credentials  # documented above; the real read happens in authenticate()
    return await authenticate(request)
