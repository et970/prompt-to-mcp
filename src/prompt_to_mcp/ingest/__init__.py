"""Turn a :class:`CreateMcpRequest` into a validated :class:`ToolManifest`."""

from __future__ import annotations

import logging
from typing import Any

from ..config import Settings
from ..errors import SdkResolutionError
from ..models import (
    CreateMcpRequest,
    DocSource,
    ToolDef,
    ToolManifest,
    build_upstream_auth,
    slugify,
)
from . import openapi_loader
from .fetcher import SPEC_ACCEPT, FetchError, fetch_document, fetch_text
from .gemini_synth import ManifestSynthesizer, SynthesisError

log = logging.getLogger(__name__)


class MergeError(ValueError):
    """Several doc sources were supplied that cannot be combined."""


#: Failures caused by the caller's input rather than by us. The control plane
#: maps these to 400; the pipeline records them as a failed ``ingest`` stage.
INGEST_INPUT_ERRORS = (
    openapi_loader.OpenAPIError,
    FetchError,
    SynthesisError,
    MergeError,
    SdkResolutionError,
)

__all__ = [
    "build_manifest_from_request",
    "openapi_loader",
    "ManifestSynthesizer",
    "INGEST_INPUT_ERRORS",
    "MergeError",
    "fetch_document",
    "fetch_text",
]


async def _fetch_spec(url: str, allowed_hosts: list[str] | None) -> str:
    """Fetch a document the caller asserted is an OpenAPI spec.

    The assertion is frequently wrong: pasting a provider's documentation page
    into the OpenAPI field is the single most common ingest mistake, and the
    resulting YAML parse error points at a line of inlined CSS. Reject the page
    here, where we still know the URL and the media type.
    """
    doc = await fetch_document(url, allowed_hosts=allowed_hosts, accept=SPEC_ACCEPT)
    obvious_json = doc.text.lstrip()[:1] in ("{", "[")
    if doc.is_html() and not obvious_json:
        raise openapi_loader.OpenAPIError(
            f"{url} returned {doc.content_type!r}: {openapi_loader.HTML_HINT}"
        )
    return doc.text


async def _load(source: DocSource, settings: Settings) -> tuple[str, bool]:
    """Fetch one document and decide whether to parse it as OpenAPI.

    An explicit OpenAPI document always wins over model synthesis. Freeform text
    falls back to Gemini. If the caller passes freeform content that *happens*
    to parse as OpenAPI, we take the deterministic path anyway.
    """
    allowed = settings.allowed_upstream_hosts or None

    if source.openapi_url:
        return await _fetch_spec(source.openapi_url, allowed), True
    if source.openapi_inline:
        return source.openapi_inline, True

    if source.url:
        raw = await fetch_text(source.url, allowed_hosts=allowed)
    else:
        raw = source.text or ""

    # Opportunistic upgrade: freeform input that is actually a spec.
    try:
        parsed = openapi_loader.parse_document(raw)
        if isinstance(parsed, dict) and ("openapi" in parsed or "swagger" in parsed):
            log.info("freeform doc detected as OpenAPI; using deterministic parser")
            return raw, True
    except openapi_loader.OpenAPIError:
        pass
    return raw, False


def _merge(
    parts: list[tuple[DocSource, ToolManifest]],
    settings: Settings,
) -> ToolManifest:
    """Fold per-document manifests into one.

    Merging is only coherent for documents describing the same API, because
    ``ToolDef.path`` is relative to a single manifest-level ``base_url``. Two
    disagreeing origins are therefore a rejected input rather than something to
    reconcile: adopting one would silently point the other document's tools at
    the wrong host, and the failure would surface as a 404 at tool-call time.
    """
    _, first = parts[0]
    if len(parts) == 1:
        return first

    # Two inline documents render identically ("openapi_inline (180 chars)"),
    # so the position is what actually identifies them to the caller.
    def at(index: int) -> str:
        return f"source #{index + 1} [{parts[index][0].label()}]"

    # base_url: all documents must agree. `req.base_url` is passed down to every
    # part, so setting it explicitly is the escape hatch for specs that differ
    # only cosmetically (a trailing /v1, say).
    for i, (_, part) in enumerate(parts[1:], start=1):
        if part.base_url != first.base_url:
            raise MergeError(
                f"doc sources disagree about the API base URL: "
                f"{at(0)} resolved {first.base_url!r} but "
                f"{at(i)} resolved {part.base_url!r}. Merged sources must "
                f"describe one API; set `base_url` explicitly to override both."
            )

    # Tool names: a collision means two documents describe the same operation,
    # or two different operations that happen to collide after name derivation.
    # Either way the caller has to decide, because keeping one silently drops a
    # capability the other document promised.
    tools: list[ToolDef] = []
    origin: dict[str, int] = {}
    for i, (_, part) in enumerate(parts):
        for tool in part.tools:
            previous = origin.get(tool.name)
            if previous is not None:
                raise MergeError(
                    f"tool name {tool.name!r} is defined by two doc sources: "
                    f"{at(previous)} and {at(i)}. Rename the operation "
                    f"in one document, or use `include_operations` to take it from "
                    f"only one of them."
                )
            origin[tool.name] = i
            tools.append(tool)

    # The per-document cap already applied inside each parser; this is the cap
    # on what actually ships. Truncating here would publish a partial catalog,
    # which reads as "this API has 60 operations" and is worse than refusing.
    if len(tools) > settings.max_tools:
        raise MergeError(
            f"merged doc sources produced {len(tools)} tools, over the limit of "
            f"{settings.max_tools}. Narrow the set with `include_operations`, "
            f"split them across separate MCP servers, or raise P2M_MAX_TOOLS."
        )

    return ToolManifest(
        name=first.name,
        display_name=first.display_name,
        description=first.description,
        base_url=first.base_url,
        tools=tools,
        source={
            "kind": "merged",
            "count": len(parts),
            "sources": [
                {"position": i + 1, "source": s.label(), **p.source}
                for i, (s, p) in enumerate(parts)
            ],
        },
    )


async def build_manifest_from_request(
    req: CreateMcpRequest,
    settings: Settings,
    *,
    synthesizer: ManifestSynthesizer | None = None,
    sdk_agent: Any | None = None,
) -> ToolManifest:
    """Resolve every doc source and produce one manifest.

    Sources are handled in order of how much they know, not in the order they
    were supplied: specs first, then SDK references, then prose. Each stage
    establishes the API's origin for the next, which is what stops the weaker
    stages from having to guess it.
    """
    sources = req.docs or []
    if not sources:
        raise SynthesisError("no doc source supplied")

    loaded: list[tuple[DocSource, str, bool]] = []
    for source in sources:
        if source.kind == "sdk":
            # Not a document: there is nothing to fetch until something works
            # out what the reference points at. Handled in pass 2.
            loaded.append((source, source.value, False))
        else:
            loaded.append((source, *await _load(source, settings)))
    built: list[ToolManifest | None] = [None] * len(loaded)

    def anchor_now() -> str | None:
        """The API origin established so far, if any."""
        return req.base_url or next((m.base_url for m in built if m is not None), None)

    # Pass 1 -- deterministic parsing.
    for i, (source, raw, is_openapi) in enumerate(loaded):
        if is_openapi:
            built[i] = openapi_loader.build_manifest(
                raw,
                name=req.name,
                description=req.description,
                base_url=req.base_url,
                include_operations=req.include_operations,
                max_tools=settings.max_tools,
                # Needed to resolve relative `servers` entries, which OpenAPI
                # 3.x says resolve against wherever the document was served
                # from.
                document_url=source.openapi_url or source.url,
            )

    # Pass 2 -- SDK references, via the ingest agent. Before prose, because the
    # agent frequently finds the spec the SDK was generated from, and a found
    # spec is a far better anchor than anything the synthesiser will produce.
    for i, (source, _, _) in enumerate(loaded):
        if source.kind == "sdk":
            # Imported here, not at module scope: sdk_agent needs this
            # package's parser and fetcher, so a top-level import is a cycle.
            from ..sdk_agent import resolve_sdk_source

            finding = await resolve_sdk_source(
                source.value,
                settings,
                description=req.description,
                name=req.name,
                base_url=anchor_now(),
                probe_token=req.probe_token,
                agent=sdk_agent,
            )
            log.info(
                "sdk source %s resolved via %s (%d tools, %d probe-confirmed)",
                source.value,
                finding.resolution,
                len(finding.manifest.tools),
                finding.confirmed,
            )
            built[i] = finding.manifest

    # Pass 3 -- model synthesis, anchored to what the earlier passes established.
    #
    # Left alone the model invents a base_url, and a guess that disagrees with
    # the spec is indistinguishable from two genuinely different APIs -- so the
    # merge would reject a request that is in fact perfectly coherent. Handing
    # the model the spec's origin removes the guess rather than forgiving it,
    # and its paths are then written relative to the origin they get called on.
    # `synthesize` pins base_url from this argument, so it is not a hint the
    # model can decline.
    anchor = anchor_now()
    for i, (source, raw, is_openapi) in enumerate(loaded):
        if not is_openapi and source.kind != "sdk":
            synth = synthesizer or ManifestSynthesizer(settings)
            built[i] = synth.synthesize(
                description=req.description,
                docs=raw,
                name=req.name,
                base_url=anchor,
                include_operations=req.include_operations,
            )

    parts = [(source, m) for (source, _, _), m in zip(loaded, built, strict=True) if m is not None]
    manifest = _merge(parts, settings)

    if req.name:
        manifest.name = slugify(req.name)

    # Resolved against the manifest's own base_url: API-key placement is
    # provider-specific and the base URL is not known before this point.
    manifest.auth = build_upstream_auth(req, manifest.base_url)
    return manifest
