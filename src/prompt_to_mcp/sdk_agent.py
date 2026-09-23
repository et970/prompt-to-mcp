"""Work backwards from a client library to the HTTP API underneath it.

An SDK reference is not documentation of an API; it is documentation of *method
calls*. A tool needs an HTTP method and a path (see
:class:`~prompt_to_mcp.models.ToolDef`), and ``stripe.Customer.create`` says
neither. Somebody has to supply that mapping, and the SDK's own docs usually do
not: they are written for a reader who never sees the wire.

So this is a search problem rather than a parsing problem, and it is handled the
same way :mod:`prompt_to_mcp.contract_agent` handles its own: a bounded loop
with tools, grounded in evidence gathered *before* the model is asked anything,
and a gate at the end that will not let the model claim more than it proved.

Two properties are worth stating plainly.

**The best outcome involves no model at all.** Most SDKs for large APIs are
generated *from* an OpenAPI document, and that document is often published --
next to the docs, or in the repository. Finding it collapses the whole problem
onto the deterministic parser, which is exact and stable across runs. So the
deterministic hunt runs first, and the agent only starts if it fails. This is
the repo's "OpenAPI beats the model" rule applied to a case where the spec has
to be looked for rather than handed over.

**Probes cannot change anything.** Only GET, HEAD and OPTIONS are ever sent, the
URL policy from :mod:`prompt_to_mcp.ingest.fetcher` is enforced on every hop,
and the interesting answer is usually a rejection: 401 and 403 prove a path
exists just as well as 200 does, and better than 200 does for an API that
returns a login page for everything. That is what makes it defensible to point
this at somebody else's production API without their credentials.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import Settings
from .errors import SdkResolutionError
from .ingest import openapi_loader
from .ingest.fetcher import FetchError, assert_safe_url, fetch_document
from .models import ToolDef, ToolEvidence, ToolManifest

log = logging.getLogger(__name__)

#: Hard bounds on one investigation. An SDK hunt fans out much wider than the
#: contract agent's, so the fetch budget is the one that usually binds.
MAX_STEPS = 16
MAX_PROBES = 25
MAX_FETCHES = 20

#: The only methods a probe may use. Not a configuration knob: a POST here
#: could create something in a stranger's account.
PROBE_METHODS = ("GET", "HEAD", "OPTIONS")

PROBE_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

#: Where a published OpenAPI document tends to live, relative to an API origin
#: or a documentation site.
WELL_KNOWN_SPEC_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/v1/openapi.json",
    "/api/openapi.json",
    "/.well-known/openapi.json",
    "/docs/openapi.json",
    "/spec/openapi.json",
)

#: Where it tends to live inside a repository that generates an SDK.
REPO_SPEC_PATHS = (
    "openapi.json",
    "openapi.yaml",
    "openapi/spec.json",
    "api/openapi.yaml",
    "spec/openapi.yaml",
    "swagger.json",
    ".stats.yml",
)


# ---------------------------------------------------------------------------
# Reference normalisation
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SdkRef:
    """A parsed ``docs.sdk`` value."""

    #: ``package`` | ``repo`` | ``docs``
    kind: str
    #: For packages: the ecosystem (``pypi``/``npm``). Empty otherwise.
    ecosystem: str = ""
    #: Package name, or the URL.
    value: str = ""

    def describe(self) -> str:
        if self.kind == "package":
            return f"{self.ecosystem} package {self.value!r}"
        return f"{self.kind} {self.value}"


def parse_reference(raw: str) -> SdkRef:
    """Work out what kind of thing the caller named.

    Accepts ``pypi:stripe``, ``npm:@octokit/rest``, a git repository URL, or a
    documentation URL. The ``ecosystem:name`` form is checked before URL
    parsing, because ``pypi:stripe`` is a valid URI with scheme ``pypi``.
    """
    value = (raw or "").strip()
    if not value:
        raise SdkResolutionError("empty sdk reference")

    for ecosystem in ("pypi", "npm"):
        prefix = f"{ecosystem}:"
        if value.lower().startswith(prefix):
            name = value[len(prefix) :].strip()
            if not name:
                raise SdkResolutionError(f"{ecosystem}: reference has no package name")
            return SdkRef(kind="package", ecosystem=ecosystem, value=name)

    if not value.startswith("https://"):
        raise SdkResolutionError(
            f"sdk reference {value!r} is not usable: give an https URL to the "
            f"docs or repository, or an 'ecosystem:name' package reference "
            f"such as 'pypi:stripe' or 'npm:@octokit/rest'"
        )

    host = (urlparse(value).hostname or "").lower()
    if host in ("github.com", "www.github.com", "gitlab.com", "www.gitlab.com"):
        return SdkRef(kind="repo", value=value)
    return SdkRef(kind="docs", value=value)


def _origin_root(url: str) -> str:
    """``https://host/a/b`` -> ``https://host``."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _github_raw_base(repo_url: str) -> str | None:
    """``https://github.com/o/r`` -> the raw-content base for its default branch."""
    parsed = urlparse(repo_url)
    if (parsed.hostname or "").lower() not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1].removesuffix(".git")
    return f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ProbeResult:
    method: str
    path: str
    status: int | None
    #: ``exists`` | ``exists_gated`` | ``wrong_method`` | ``absent`` | ``inconclusive``
    outcome: str
    note: str = ""

    @property
    def confirms(self) -> bool:
        """Whether this is positive evidence that the path is real."""
        return self.outcome in ("exists", "exists_gated", "wrong_method")


def classify(status: int) -> tuple[str, str]:
    """Turn a status code into evidence about whether a path exists.

    The rejections are the useful part. An API that requires auth answers 401
    for a real path and 404 for an invented one, which is exactly the
    discrimination needed -- and it needs no credentials to obtain.
    """
    if status in (401, 403):
        return "exists_gated", f"{status}: path exists but is gated"
    if status == 405:
        return "wrong_method", f"{status}: path exists, method not allowed"
    if status in (404, 410):
        return "absent", f"{status}: no such path"
    if 200 <= status < 400:
        return "exists", f"{status}: ok"
    if status == 429:
        return "inconclusive", f"{status}: rate limited, try fewer probes"
    if status >= 500:
        return "inconclusive", f"{status}: upstream error, says nothing about the path"
    return "inconclusive", f"{status}: unexpected"


@dataclass
class SdkHarness:
    """The agent's whole action surface. Nothing here can mutate anything."""

    settings: Settings
    #: Where probes are sent. Until this is known, probing is unavailable.
    base_url: str | None = None
    #: Optional bearer token supplied by the caller for probing.
    token: str | None = None
    search_model: str = "gemini-3.7-flash"

    probes: list[ProbeResult] = field(default_factory=list)
    fetches: int = 0
    #: Specs found by URL, so a second look costs nothing.
    specs: dict[str, str] = field(default_factory=dict)
    _seen_probe: dict[str, ProbeResult] = field(default_factory=dict)
    _seen_fetch: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def allowed(self) -> list[str] | None:
        return self.settings.allowed_upstream_hosts or None

    @property
    def probes_exhausted(self) -> bool:
        return len(self.probes) >= MAX_PROBES

    @property
    def fetches_exhausted(self) -> bool:
        return self.fetches >= MAX_FETCHES

    # -- documents ------------------------------------------------------

    async def fetch(self, url: str, *, budgeted: bool = True) -> dict[str, Any]:
        """Retrieve a document. Cached, and budgeted.

        ``budgeted=False`` is for the terminal act of adopting a specification.
        That fetch is the *result*, not part of the search, and making it
        compete with exploration meant a run that spent its budget hunting
        well-known paths could identify the right spec and then be unable to
        retrieve it.
        """
        if url in self._seen_fetch:
            return self._seen_fetch[url]
        if budgeted and self.fetches_exhausted:
            return {"error": f"fetch budget of {MAX_FETCHES} exhausted"}
        self.fetches += 1
        try:
            doc = await fetch_document(url, allowed_hosts=self.allowed)
        except (FetchError, httpx.HTTPError) as exc:
            result = {"error": str(exc)[:400], "url": url}
            self._seen_fetch[url] = result
            return result

        body = doc.text
        result = {
            "url": doc.url,
            "content_type": doc.content_type,
            # Enough to recognise a spec or read a reference page, not enough to
            # spend the whole context window on one navigation sidebar.
            "body": body[:20000],
            "truncated": len(body) > 20000,
        }
        if self._looks_like_spec(body):
            self.specs[doc.url] = body
            result["is_openapi"] = True
        self._seen_fetch[url] = result
        return result

    @staticmethod
    def _looks_like_spec(body: str) -> bool:
        try:
            parsed = openapi_loader.parse_document(body)
        except openapi_loader.OpenAPIError:
            return False
        return isinstance(parsed, dict) and ("openapi" in parsed or "swagger" in parsed)

    async def find_openapi(self, origins: list[str]) -> dict[str, Any]:
        """Try the places a published spec is usually published at.

        This is the cheapest possible win and the reason the agent often does
        not need to reason at all.
        """
        tried: list[str] = []
        for origin in origins[:6]:
            base = origin.rstrip("/")
            raw_base = _github_raw_base(base)
            if raw_base:
                candidates = [f"{raw_base}/{p}" for p in REPO_SPEC_PATHS]
            else:
                # Both the URL as given and its host root. A documentation URL
                # is usually a sub-path (`https://host/docs`), while the spec is
                # commonly published at the root -- trying only the sub-path
                # misses the more likely of the two locations.
                candidates = [
                    f"{b}{p}"
                    for b in _dedupe([base, _origin_root(base)])
                    for p in WELL_KNOWN_SPEC_PATHS
                ]
            for url in candidates:
                if self.fetches_exhausted:
                    return {"found": None, "tried": tried, "error": "fetch budget exhausted"}
                tried.append(url)
                result = await self.fetch(url)
                if result.get("is_openapi"):
                    return {"found": url, "tried": tried}
        return {"found": None, "tried": tried}

    async def search(self, query: str, model: Any = None) -> dict[str, Any]:
        """Grounded web search. Hypotheses only, never a justification.

        Separate model call rather than a grounding tool on the main loop, for
        the same reasons as :meth:`ContractAgent.search_docs`: mixing search
        grounding with function declarations is not reliably supported, and the
        separation keeps the epistemic boundary visible.
        """
        if model is None:
            return {"error": "no model available for search"}
        try:
            from google.genai import types

            resp = await asyncio.to_thread(
                model.generate_content,
                model=self.search_model,
                contents=(
                    "Answer only from search results. Quote exact HTTP methods, "
                    "paths and host names where you find them, and say plainly "
                    f"when you do not.\n\n{query}"
                ),
                config=types.GenerateContentConfig(
                    tools=[types.Tool(google_search=types.GoogleSearch())],
                    temperature=0.0,
                    max_output_tokens=2048,
                ),
            )
        except Exception as exc:  # noqa: BLE001 - advisory tool, never fatal
            log.warning("sdk doc search failed: %s", exc)
            return {"error": str(exc)}

        citations: list[str] = []
        try:
            for candidate in resp.candidates or []:
                meta = getattr(candidate, "grounding_metadata", None)
                for chunk in getattr(meta, "grounding_chunks", None) or []:
                    web = getattr(chunk, "web", None)
                    if web is not None and getattr(web, "uri", None):
                        citations.append(web.uri)
        except Exception:  # noqa: BLE001 - citations are a nicety
            pass

        return {
            "answer": (resp.text or "")[:4000],
            "citations": citations[:10],
            "reliability": (
                "UNVERIFIED. SDK guides routinely describe method calls without "
                "the wire format, and blog posts go stale. Use this to form a "
                "hypothesis, then confirm the path with probe()."
            ),
        }

    # -- the live API ---------------------------------------------------

    async def probe(self, method: str, path: str) -> dict[str, Any]:
        """Check whether a path exists, without being able to change anything."""
        method = (method or "GET").upper()
        if method not in PROBE_METHODS:
            return {
                "error": (
                    f"{method} is not probeable. Only {', '.join(PROBE_METHODS)} are "
                    f"sent, because a probe must not be able to alter the upstream "
                    f"account. Probe the path with GET to establish that it exists; "
                    f"the method for the tool itself comes from the documentation."
                )
            }
        if not self.base_url:
            return {"error": "no base_url established yet; find the API origin first"}

        signature = f"{method} {path}"
        if signature in self._seen_probe:
            cached = self._seen_probe[signature]
            return {"outcome": cached.outcome, "status": cached.status, "cached": True}
        if self.probes_exhausted:
            return {"error": f"probe budget of {MAX_PROBES} exhausted"}

        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        # A path template cannot be requested literally; a placeholder would be
        # read as a path segment and answer 404 for a route that exists.
        if "{" in url:
            return {
                "error": (
                    "path contains a placeholder. Probe a concrete path -- "
                    "substitute a plainly invalid id, since 404-for-the-id and "
                    "404-for-the-route are distinguishable only by trying a "
                    "collection path too."
                )
            }

        headers = {"accept": "application/json"}
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"

        try:
            assert_safe_url(url, self.allowed)
            async with httpx.AsyncClient(timeout=PROBE_TIMEOUT, follow_redirects=False) as client:
                resp = await client.request(method, url, headers=headers)
            outcome, note = classify(resp.status_code)
            status: int | None = resp.status_code
        except FetchError as exc:
            return {"error": f"refused by URL policy: {exc}"}
        except httpx.HTTPError as exc:
            outcome, note, status = "inconclusive", f"transport error: {exc}", None

        result = ProbeResult(method=method, path=path, status=status, outcome=outcome, note=note)
        self.probes.append(result)
        self._seen_probe[signature] = result
        return {
            "outcome": outcome,
            "status": status,
            "note": note,
            "authenticated": bool(self.token),
            "probes_left": MAX_PROBES - len(self.probes),
        }

    def confirmed_paths(self) -> set[str]:
        """Concrete paths a probe positively confirmed."""
        return {p.path for p in self.probes if p.confirms}

    def match_confirmed(self, tool_path: str) -> ProbeResult | None:
        """Find a probe confirming a tool's (usually templated) path.

        A probe has to be concrete -- ``/users/octocat`` -- while the tool it
        supports is templated -- ``/users/{username}``. Comparing the two as
        strings never matches, which is how a run against the live GitHub API
        confirmed eight paths and still labelled eight of its nine tools
        `inferred`. Each placeholder stands for exactly one segment, so the
        comparison is a segment-wise match rather than a substring one: it will
        not let ``/users/{u}`` claim credit for a probe of ``/users/u/repos``.
        """
        segments = tool_path.split("/")
        pattern = re.compile(
            "^"
            + "/".join(
                "[^/]+" if s.startswith("{") and s.endswith("}") else re.escape(s)
                for s in segments
            )
            + "$"
        )
        for probe in self.probes:
            if probe.confirms and pattern.match(probe.path.split("?")[0]):
                return probe
        return None


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


_SYSTEM = """\
You recover the HTTP API that sits underneath a client library, so it can be
wrapped as MCP tools.

WHAT A RESULT LOOKS LIKE. Every tool needs an HTTP method and a path relative
to one base URL. `sdk.customers.create(...)` is not an answer; `POST /v1/customers`
is. If you cannot get to methods and paths, say so via propose() with the tools
you do have rather than inventing the rest.

FIND THE SPEC FIRST. Most SDKs for large APIs are generated from an OpenAPI
document, and it is frequently published. use_openapi() on a real spec beats
anything you can assemble by hand: it is exact, it has real JSON Schemas, and it
ends the search. Spend your first steps looking for one -- in the docs site, in
the repository, in the package metadata.

EVIDENCE HIERARCHY. Sources are not equal:
  1. use_openapi()  -- a machine-readable spec. Decisive, ends the task.
  2. probe()        -- the only thing that can confirm a path you inferred.
                       401 and 403 confirm a path as well as 200 does; 404
                       disproves it. Probe before you propose.
  3. fetch()        -- the SDK's own docs and source. Strong for method names
                       and arguments, often silent on the wire format.
  4. search()       -- hypothesis generation only. Never propose on this alone.

PROBES ARE READ-ONLY. GET, HEAD and OPTIONS are all you get, because this may be
someone's production API and you have no permission to change anything in it.
Establish that a path exists with GET; take the tool's real method from the
documentation.

BUDGETS. You have a limited number of steps, probes and fetches. Do not re-fetch
a page or re-probe a path -- repeats are answered from cache and waste a step.
Call propose() before you run out; a partial answer is useful, no answer is not.

HONESTY. Mark nothing as confirmed that you did not confirm. Unproven tools are
still worth proposing, and they are recorded as inferred rather than dropped, so
there is nothing to gain by overstating them.
"""


def _tool_declarations() -> list[Any]:
    from google.genai import types

    return [
        types.FunctionDeclaration(
            name="fetch",
            description=(
                "Retrieve a URL: a documentation page, a repository file, a "
                "package metadata endpoint. Returns the body, truncated."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={"url": types.Schema(type=types.Type.STRING, description="https URL")},
                required=["url"],
            ),
        ),
        types.FunctionDeclaration(
            name="find_openapi",
            description=(
                "Try the conventional locations for a published OpenAPI document "
                "under each given origin (or inside a GitHub repository). The "
                "cheapest way to finish the task."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "origins": types.Schema(
                        type=types.Type.ARRAY,
                        items=types.Schema(type=types.Type.STRING),
                        description="API origins or GitHub repository URLs.",
                    )
                },
                required=["origins"],
            ),
        ),
        types.FunctionDeclaration(
            name="search",
            description=(
                "Grounded web search. Hypothesis generation only; its answers "
                "cannot justify a proposal on their own."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={"query": types.Schema(type=types.Type.STRING)},
                required=["query"],
            ),
        ),
        types.FunctionDeclaration(
            name="set_base_url",
            description=(
                "Record the API origin that tool paths are relative to. Required "
                "before probing, and required by propose()."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "base_url": types.Schema(
                        type=types.Type.STRING,
                        description="Absolute https origin, optionally with a base path.",
                    )
                },
                required=["base_url"],
            ),
        ),
        types.FunctionDeclaration(
            name="probe",
            description=(
                "Send a read-only request to a concrete path on the API to find "
                "out whether it exists. 401/403 confirm existence; 404 refutes it."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "method": types.Schema(
                        type=types.Type.STRING,
                        description="GET, HEAD or OPTIONS.",
                    ),
                    "path": types.Schema(
                        type=types.Type.STRING,
                        description="Concrete path, no {placeholders}.",
                    ),
                },
                required=["method", "path"],
            ),
        ),
        types.FunctionDeclaration(
            name="use_openapi",
            description=(
                "TERMINAL. Adopt a real OpenAPI document found at this URL. It is "
                "parsed deterministically and the search ends. Always prefer this."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={"url": types.Schema(type=types.Type.STRING)},
                required=["url"],
            ),
        ),
        types.FunctionDeclaration(
            name="propose",
            description=(
                "TERMINAL. Hand over the tools you assembled. Use when no spec "
                "exists. Paths must be relative to base_url."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "base_url": types.Schema(type=types.Type.STRING),
                    "display_name": types.Schema(type=types.Type.STRING),
                    "tools": types.Schema(
                        type=types.Type.ARRAY,
                        description="One entry per HTTP operation.",
                        # Spelled out rather than described in prose. An
                        # untyped OBJECT gives the model nothing to populate,
                        # and under forced tool-calling it answered with a list
                        # of empty objects -- every tool then failed validation
                        # for a missing name and path.
                        items=types.Schema(
                            type=types.Type.OBJECT,
                            properties={
                                "name": types.Schema(
                                    type=types.Type.STRING,
                                    description="Lowercase, [a-z0-9_] only.",
                                ),
                                "description": types.Schema(type=types.Type.STRING),
                                "method": types.Schema(
                                    type=types.Type.STRING,
                                    description="GET, POST, PUT, PATCH, DELETE or HEAD.",
                                ),
                                "path": types.Schema(
                                    type=types.Type.STRING,
                                    description=(
                                        "Relative to base_url, leading slash, "
                                        "{placeholders} for path parameters."
                                    ),
                                ),
                                "params": types.Schema(
                                    type=types.Type.ARRAY,
                                    items=types.Schema(
                                        type=types.Type.OBJECT,
                                        properties={
                                            "name": types.Schema(type=types.Type.STRING),
                                            "location": types.Schema(
                                                type=types.Type.STRING,
                                                description="path, query, header or body.",
                                            ),
                                            "required": types.Schema(
                                                type=types.Type.BOOLEAN
                                            ),
                                            "description": types.Schema(
                                                type=types.Type.STRING
                                            ),
                                            "type": types.Schema(
                                                type=types.Type.STRING,
                                                description="string, integer, boolean, ...",
                                            ),
                                        },
                                        required=["name", "location"],
                                    ),
                                ),
                            },
                            required=["name", "method", "path"],
                        ),
                    ),
                    "notes": types.Schema(
                        type=types.Type.STRING,
                        description="What you could not establish, and why.",
                    ),
                },
                required=["base_url", "tools"],
            ),
        ),
    ]


@dataclass(slots=True)
class SdkFinding:
    """What an investigation produced."""

    manifest: ToolManifest
    #: ``spec`` when a real OpenAPI document was adopted, ``agent`` when the
    #: tools were assembled by the model, ``none`` when nothing was found.
    resolution: str
    notes: str = ""
    probes: int = 0
    confirmed: int = 0


class SdkAgent:
    """Bounded tool-using loop over :class:`SdkHarness`.

    The model is injected exactly as :class:`~prompt_to_mcp.contract_agent.
    ContractAgent` injects it, so tests drive the loop with a scripted model and
    never reach Vertex.
    """

    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        self.settings = settings
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            from google import genai  # heavy; imported lazily

            self._client = genai.Client(
                vertexai=True,
                project=self.settings.project_id,
                location=self.settings.gemini_location,
            )
        return self._client

    def _turn(self, contents: list[Any], *, force_finish: bool = False) -> Any:
        from google.genai import types

        config: dict[str, Any] = {
            "system_instruction": _SYSTEM,
            "tools": [types.Tool(function_declarations=_tool_declarations())],
            "temperature": 0.0,
            "max_output_tokens": 8192,
            # The SDK enables automatic function calling by default and then
            # warns that it is not recommended here. Our declarations are
            # schemas, not Python callables, so AFC has nothing to execute --
            # turning it off removes a moving part rather than changing
            # behaviour.
            "automatic_function_calling": types.AutomaticFunctionCallingConfig(
                disable=True
            ),
        }
        if force_finish:
            # Asking nicely is not enough. Against the live GitHub API the model
            # spent all sixteen steps probing -- gathering good evidence the
            # whole time -- and never volunteered a proposal, so the run
            # returned nothing despite having everything it needed.
            config["tool_config"] = types.ToolConfig(
                function_calling_config=types.FunctionCallingConfig(
                    mode="ANY", allowed_function_names=["propose", "use_openapi"]
                )
            )
        return self._get_client().models.generate_content(
            model=self.settings.gemini_model,
            contents=contents,
            config=types.GenerateContentConfig(**config),
        )

    # -- seeding --------------------------------------------------------

    async def _seed(self, harness: SdkHarness, ref: SdkRef) -> tuple[str, str | None]:
        """Gather evidence before the model forms a hypothesis.

        Same lesson as the contract agent, which ignored an instruction to read
        working examples first and guessed instead. Resolving the package and
        hunting for a spec is cheap, deterministic, and frequently finishes the
        job outright -- so it is a precondition, not a suggestion.
        """
        lines: list[str] = [f"Reference: {ref.describe()}"]
        origins: list[str] = []

        if ref.kind == "package":
            meta = await self._package_metadata(harness, ref)
            if meta:
                lines.append(f"Package metadata: {json.dumps(meta)[:1500]}")
                origins.extend(meta.get("urls", []))
            else:
                lines.append("Package metadata: not retrievable.")
        else:
            origins.append(ref.value)
            page = await harness.fetch(ref.value)
            if page.get("error"):
                lines.append(f"Could not fetch {ref.value}: {page['error']}")
            else:
                if page.get("is_openapi"):
                    # The reference itself was a spec.
                    return "\n".join(lines), ref.value
                lines.append(
                    f"Fetched {page['url']} ({page['content_type']}), first 2000 chars:\n"
                    f"{str(page.get('body', ''))[:2000]}"
                )

        found = await harness.find_openapi(_dedupe(origins))
        if found.get("found"):
            return "\n".join(lines), str(found["found"])
        lines.append(
            f"No OpenAPI document at the conventional locations "
            f"(tried {len(found.get('tried', []))}). You will have to work it out."
        )
        return "\n".join(lines), None

    async def _package_metadata(self, harness: SdkHarness, ref: SdkRef) -> dict[str, Any] | None:
        """Registry metadata, for the repository and documentation links."""
        if ref.ecosystem == "pypi":
            url = f"https://pypi.org/pypi/{ref.value}/json"
        else:
            url = f"https://registry.npmjs.org/{ref.value}"
        result = await harness.fetch(url)
        if result.get("error"):
            return None
        try:
            data = json.loads(str(result.get("body") or ""))
        except (ValueError, TypeError):
            return None

        urls: list[str] = []
        summary = ""
        if ref.ecosystem == "pypi":
            info = data.get("info") or {}
            summary = str(info.get("summary") or "")
            for candidate in (info.get("home_page"), info.get("docs_url")):
                if candidate:
                    urls.append(str(candidate))
            for candidate in (info.get("project_urls") or {}).values():
                if candidate:
                    urls.append(str(candidate))
        else:
            summary = str(data.get("description") or "")[:400]
            if data.get("homepage"):
                urls.append(str(data["homepage"]))
            repo = data.get("repository")
            if isinstance(repo, dict) and repo.get("url"):
                urls.append(str(repo["url"]).removeprefix("git+").removesuffix(".git"))

        https = [u for u in _dedupe(urls) if u.startswith("https://")]
        return {"summary": summary[:400], "urls": https[:8]}

    # -- the loop -------------------------------------------------------

    async def investigate(
        self,
        harness: SdkHarness,
        ref: SdkRef,
        *,
        description: str = "",
        name: str | None = None,
        max_tools: int = 60,
    ) -> SdkFinding:
        """Run the loop. Always returns a finding, or raises SdkResolutionError."""
        from google.genai import types

        seed, spec_url = await self._seed(harness, ref)
        if spec_url is not None:
            try:
                # The deterministic path won outright; the model is never asked.
                log.info("sdk %s resolved to a spec at %s without the agent", ref.value, spec_url)
                return await self._from_spec(harness, spec_url, description, name, max_tools)
            except (SdkResolutionError, openapi_loader.OpenAPIError) as exc:
                # A spec that looked right but cannot be used is a reason to
                # keep searching, not to give up: the agent still has its whole
                # budget, and something else may serve. OpenAPIError belongs
                # here too: a document can parse as JSON, look like a spec, and
                # still be unusable (no server URL, no operations).
                log.info("seed spec %s unusable (%s); continuing with the agent", spec_url, exc)
                seed += f"\n\nA specification at {spec_url} looked promising but "
                seed += f"is unusable: {exc}. Do not try it again."

        opening = (
            f"Recover the HTTP API behind this SDK so it can be wrapped as MCP "
            f"tools.\n\nWhat the caller wants: {description or '(not stated)'}\n\n"
            f"{seed}\n\nProbing is "
            + (
                "authenticated with a caller-supplied token."
                if harness.token
                else "unauthenticated."
            )
        )
        contents: list[Any] = [types.Content(role="user", parts=[types.Part(text=opening)])]

        for step in range(MAX_STEPS):
            steps_left = MAX_STEPS - step
            try:
                response = self._turn(contents, force_finish=steps_left <= 2)
            except Exception as exc:  # noqa: BLE001 - degrade, never raise
                log.warning("sdk agent model call failed: %s", exc)
                raise SdkResolutionError(
                    f"could not resolve the SDK reference {ref.value!r}: the model "
                    f"was unavailable ({exc}). Supply `openapi_url` or `text` "
                    f"documentation instead."
                ) from exc

            calls = list(getattr(response, "function_calls", None) or [])
            if not calls:
                break

            contents.append(response.candidates[0].content)
            replies = []
            for call in calls:
                args = dict(call.args or {})
                if call.name == "use_openapi":
                    try:
                        return await self._from_spec(
                            harness, str(args.get("url", "")), description, name, max_tools
                        )
                    except (SdkResolutionError, openapi_loader.OpenAPIError) as exc:
                        # Terminal only when it works. Aborting the run instead
                        # threw away a perfectly good partial answer because one
                        # candidate spec was too large to fetch.
                        replies.append(
                            types.Part.from_function_response(
                                name=call.name,
                                response={"error": str(exc), "advice": "try another "
                                          "source, or propose what you have"},
                            )
                        )
                        continue
                if call.name == "propose":
                    return self._finalise(harness, args, description, name, max_tools)
                result = await self._invoke(harness, call.name, args)
                replies.append(types.Part.from_function_response(name=call.name, response=result))
            contents.append(types.Content(role="user", parts=replies))

            # The step budget is usually what binds, not the probe or fetch
            # budgets, so it needs its own warning -- and it has to arrive with
            # enough steps left to act on.
            if steps_left <= 4 or harness.probes_exhausted or harness.fetches_exhausted:
                contents.append(
                    types.Content(
                        role="user",
                        parts=[
                            types.Part(
                                text=(
                                    f"{steps_left - 1} step(s) left. Stop investigating "
                                    f"and call propose now with what you have "
                                    f"(or use_openapi if you found a spec). "
                                    f"{len(harness.confirmed_paths())} path(s) are "
                                    f"already confirmed."
                                )
                            )
                        ],
                    )
                )

        raise SdkResolutionError(
            f"could not recover an HTTP API from {ref.describe()} in {MAX_STEPS} "
            f"steps. Supply `openapi_url`, or `text` documentation that states "
            f"the methods and paths."
        )

    async def _invoke(self, harness: SdkHarness, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "fetch":
            return await harness.fetch(str(args.get("url", "")))
        if tool == "find_openapi":
            origins = [str(o) for o in (args.get("origins") or [])]
            return await harness.find_openapi(origins)
        if tool == "search":
            return await harness.search(str(args.get("query", "")), self._get_client().models)
        if tool == "set_base_url":
            base = str(args.get("base_url", "")).rstrip("/")
            if not base.startswith("https://"):
                return {"error": f"base_url must be https, got {base!r}"}
            harness.base_url = base
            return {"ok": True, "base_url": base}
        if tool == "probe":
            return await harness.probe(str(args.get("method", "GET")), str(args.get("path", "")))
        return {"error": f"unknown tool {tool!r}"}

    # -- terminals ------------------------------------------------------

    async def _from_spec(
        self,
        harness: SdkHarness,
        url: str,
        description: str,
        name: str | None,
        max_tools: int,
    ) -> SdkFinding:
        """Adopt a real specification. The model's opinion stops mattering here.

        The URL is only trusted as far as fetching it: it goes through the same
        SSRF policy as everything else and has to parse as OpenAPI before it is
        adopted. What is *not* required is that the document already be in the
        cache. Requiring that looked like a tighter guard and was really just a
        bug -- spotting a spec link on a landing page and going straight to
        use_openapi is the single most common way this succeeds, and it failed
        against the live Petstore for exactly that reason.
        """
        body = harness.specs.get(url)
        if body is None:
            result = await harness.fetch(url, budgeted=False)
            # `fetch` keys the cache by the post-redirect URL.
            body = harness.specs.get(str(result.get("url") or url)) or harness.specs.get(url)
            if body is None:
                # Say which of the three things went wrong. "could not be
                # fetched, or did not parse" sent an operator looking for a
                # network fault when the real answer was that GitHub's
                # description is ~90 MB and hit the fetcher's size cap.
                reason = result.get("error") or "it did not parse as an OpenAPI document"
                raise SdkResolutionError(f"{url!r} is not usable: {reason}")
        manifest = openapi_loader.build_manifest(
            body,
            name=name,
            description=description,
            include_operations=None,
            max_tools=max_tools,
            document_url=url,
        )
        manifest.source = {
            "kind": "sdk",
            "resolution": "spec",
            "spec_url": url,
        }
        return SdkFinding(
            manifest=manifest,
            resolution="spec",
            notes=f"resolved to the OpenAPI document at {url}",
            probes=len(harness.probes),
            confirmed=len(harness.confirmed_paths()),
        )

    def _finalise(
        self,
        harness: SdkHarness,
        args: dict[str, Any],
        description: str,
        name: str | None,
        max_tools: int,
    ) -> SdkFinding:
        """Accept the model's tools, and label each one with what backs it.

        Unproven tools ship. A plausible endpoint is worth having, and dropping
        it silently would publish a smaller API than the SDK documents -- which
        this codebase treats as actively misleading elsewhere. What is *not*
        acceptable is presenting a guess as a fact, so the label is derived from
        the probe log rather than from anything the model asserts.
        """
        base_url = str(args.get("base_url") or harness.base_url or "").rstrip("/")
        if not base_url.startswith("https://"):
            raise SdkResolutionError(
                f"the agent proposed an unusable base_url {base_url!r}; it must be https"
            )

        confirmed = harness.confirmed_paths()
        raw_tools = args.get("tools") or []
        tools: list[ToolDef] = []
        seen: set[str] = set()
        for entry in raw_tools[:max_tools]:
            if not isinstance(entry, dict):
                continue
            try:
                tool = ToolDef.model_validate(_normalise_tool(entry))
            except Exception as exc:  # noqa: BLE001 - one bad tool is not fatal
                log.info(
                    "sdk agent proposed an invalid tool %r, dropped: %s",
                    entry.get("name"),
                    str(exc).replace("\n", " ")[:300],
                )
                continue
            if tool.name in seen:
                continue
            seen.add(tool.name)
            match = harness.match_confirmed(tool.path)
            if match is not None:
                tool.evidence = ToolEvidence.PROBED
                tool.evidence_note = f"{match.method} {match.path} -> {match.note}"
            else:
                tool.evidence = ToolEvidence.INFERRED
                tool.evidence_note = "not confirmed against the live API"
            tools.append(tool)

        if not tools:
            raise SdkResolutionError(
                "the agent proposed no usable tools. Supply `openapi_url`, or "
                "`text` documentation stating the methods and paths."
            )

        manifest = ToolManifest(
            name=_slug(name or str(args.get("display_name") or "sdk-api")),
            display_name=str(args.get("display_name") or name or "SDK API"),
            description=(description or "")[:2048],
            base_url=base_url,
            tools=tools,
            source={
                "kind": "sdk",
                "resolution": "agent",
                "notes": str(args.get("notes") or "")[:2000],
                "probes": len(harness.probes),
                "confirmed_paths": sorted(confirmed)[:50],
            },
        )
        n_probed = sum(1 for t in tools if t.evidence is ToolEvidence.PROBED)
        log.info("sdk agent proposed %d tools, %d confirmed by probe", len(tools), n_probed)
        return SdkFinding(
            manifest=manifest,
            resolution="agent",
            notes=str(args.get("notes") or ""),
            probes=len(harness.probes),
            confirmed=n_probed,
        )


def _normalise_tool(entry: dict[str, Any]) -> dict[str, Any]:
    """Accept the parameter shapes a model actually emits.

    ``ToolDef`` wants a list of parameter objects, each saying where it goes in
    the request. Models overwhelmingly reach for JSON Schema instead --
    ``{"type": "object", "properties": {...}, "required": [...]}`` -- because
    that is what a function signature looks like everywhere else, including in
    the MCP spec these tools are destined for.

    That was a defect in the declaration, not in the model. Against the live
    GitHub API every single proposed tool was dropped for it, and the run failed
    with "no usable tools" while holding a perfectly good set of endpoints.

    Where a parameter goes is then inferred: named in the path template means
    path, otherwise query for read methods and body for writes. That is the
    convention these APIs follow, and it is a far better guess than discarding
    the tool.
    """
    entry = dict(entry)
    if "parameters" in entry and "params" not in entry:
        entry["params"] = entry.pop("parameters")
    entry.pop("parameters", None)

    params = entry.get("params")
    path = str(entry.get("path") or "")
    method = str(entry.get("method") or "GET").upper()
    placeholders = set(re.findall(r"\{([^}]+)\}", path))

    def location_for(name: str) -> str:
        if name in placeholders:
            return "path"
        return "query" if method in ("GET", "HEAD", "DELETE") else "body"

    if isinstance(params, dict) and isinstance(params.get("properties"), dict):
        required = set(params.get("required") or [])
        converted: list[dict[str, Any]] = []
        for pname, pschema in params["properties"].items():
            schema = dict(pschema) if isinstance(pschema, dict) else {"type": "string"}
            description = str(schema.pop("description", ""))
            converted.append(
                {
                    "name": str(pname),
                    "location": location_for(str(pname)),
                    "required": pname in required or pname in placeholders,
                    "description": description,
                    "schema": schema or {"type": "string"},
                }
            )
        entry["params"] = converted
    elif isinstance(params, list):
        converted = []
        for raw in params:
            if not isinstance(raw, dict) or not raw.get("name"):
                continue
            item = dict(raw)
            if "location" not in item and "in" in item:
                item["location"] = item.pop("in")
            if "schema" not in item and "type" in item:
                item["schema"] = {"type": str(item.pop("type"))}
            item.pop("type", None)
            if item.get("location") not in ("path", "query", "header", "body"):
                item["location"] = location_for(str(item["name"]))
            converted.append(item)
        entry["params"] = converted
    else:
        entry["params"] = []

    # A placeholder with no declared parameter is fatal to ToolDef, and it is
    # also unambiguous: `{username}` in the path is a required path parameter,
    # whatever the model did or did not list. Synthesising it rescues a tool
    # that would otherwise be dropped for a purely clerical omission.
    declared = {
        str(param.get("name"))
        for param in entry["params"]
        if param.get("location") == "path"
    }
    for missing in sorted(placeholders - declared):
        entry["params"].append(
            {
                "name": missing,
                "location": "path",
                "required": True,
                "description": "",
                "schema": {"type": "string"},
            }
        )
    return entry


def _slug(value: str) -> str:
    from .models import slugify

    return slugify(value)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


async def resolve_sdk_source(
    reference: str,
    settings: Settings,
    *,
    description: str = "",
    name: str | None = None,
    base_url: str | None = None,
    probe_token: str | None = None,
    agent: SdkAgent | None = None,
) -> SdkFinding:
    """Turn a ``docs.sdk`` value into a manifest. The ingest entry point."""
    ref = parse_reference(reference)
    harness = SdkHarness(settings=settings, base_url=base_url, token=probe_token)
    return await (agent or SdkAgent(settings)).investigate(
        harness,
        ref,
        description=description,
        name=name,
        max_tools=settings.max_tools,
    )
