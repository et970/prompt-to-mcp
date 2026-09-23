"""Deterministic OpenAPI 3.x / Swagger 2.0 -> :class:`ToolManifest` conversion.

This path involves no model inference at all. When the user supplies a real
OpenAPI document we prefer it over Gemini synthesis: it is exact, stable across
runs, and produces JSON Schemas we can actually validate requests against.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin

import yaml

from ..models import (
    ParamLocation,
    ToolDef,
    ToolEvidence,
    ToolManifest,
    ToolParam,
    slugify,
)

log = logging.getLogger(__name__)

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head")
_MUTATING = {"post", "put", "patch", "delete"}

#: A rendered documentation page fed to PyYAML produces a baffling error about
#: some line of inlined CSS. Recognise HTML up front and say what is wrong.
_HTML_RE = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<\?xml[^>]*\?>\s*<html\b)", re.IGNORECASE)

#: What to tell a user who pointed the OpenAPI source at a documentation page.
HTML_HINT = (
    "this looks like a rendered documentation page, not a spec file. "
    "Use the freeform docs source (`docs.url`) instead of `docs.openapi_url`, "
    "or point at the raw .json/.yaml spec"
)


class OpenAPIError(ValueError):
    pass


def looks_like_html(raw: str) -> bool:
    """True if the body is an HTML page rather than a JSON/YAML document."""
    return bool(_HTML_RE.match(raw))


def parse_document(raw: str) -> dict[str, Any]:
    """Parse JSON or YAML into a dict."""
    raw = raw.strip()
    if not raw:
        raise OpenAPIError("empty document")
    if looks_like_html(raw):
        raise OpenAPIError(f"document is HTML, not an OpenAPI document: {HTML_HINT}")
    try:
        if raw[0] in "{[":
            return json.loads(raw)
        return yaml.safe_load(raw)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise OpenAPIError(f"could not parse document as JSON or YAML: {exc}") from exc


class _RefResolver:
    """Resolves local ``#/...`` refs with cycle protection."""

    def __init__(self, root: dict[str, Any], max_depth: int = 24) -> None:
        self.root = root
        self.max_depth = max_depth

    def resolve(self, node: Any, _depth: int = 0, _seen: frozenset[str] = frozenset()) -> Any:
        if _depth > self.max_depth:
            # Cyclic or pathologically nested schema; degrade to a permissive object.
            return {"type": "object"}
        if isinstance(node, list):
            return [self.resolve(n, _depth + 1, _seen) for n in node]
        if not isinstance(node, dict):
            return node
        ref = node.get("$ref")
        if isinstance(ref, str):
            if not ref.startswith("#/"):
                # Remote refs are not fetched: that would be an SSRF vector.
                return {"type": "object", "description": f"unresolved external ref {ref}"}
            if ref in _seen:
                return {"type": "object"}
            target: Any = self.root
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or part not in target:
                    return {"type": "object", "description": f"broken ref {ref}"}
                target = target[part]
            return self.resolve(target, _depth + 1, _seen | {ref})
        return {k: self.resolve(v, _depth + 1, _seen) for k, v in node.items() if k != "$ref"}


def _pick_base_url(
    doc: dict[str, Any], override: str | None, document_url: str | None = None
) -> str:
    if override:
        return override.rstrip("/")
    relative: list[str] = []
    for server in doc.get("servers") or []:
        url = server.get("url", "")
        # Substitute server variable defaults, e.g. https://{region}.api.com
        for var, spec in (server.get("variables") or {}).items():
            default = spec.get("default")
            if default is not None:
                url = url.replace("{" + var + "}", str(default))
        if url.startswith("https://"):
            return url.rstrip("/")
        if url:
            relative.append(url)

    # OpenAPI 3.x: "If the server URL is a relative URL, it MUST be resolved
    # against the URL the document was served from." Swagger's own petstore
    # does exactly this (`servers: [{url: /api/v3}]`), so refusing it rejected
    # the single most common spec anyone would try first -- including the
    # example in this repo's own quickstart.
    if relative and document_url:
        resolved = urljoin(document_url, relative[0])
        if resolved.startswith("https://"):
            log.info("resolved relative server URL %r against %s", relative[0], document_url)
            return resolved.rstrip("/")

    # Swagger 2.0
    host = doc.get("host")
    if host:
        base = doc.get("basePath", "") or ""
        return f"https://{host}{base}".rstrip("/")

    if relative:
        raise OpenAPIError(
            f"document declares only relative server URL(s) {relative} and was not "
            "fetched from a URL they can be resolved against; pass base_url explicitly"
        )
    raise OpenAPIError(
        "document declares no usable https server URL; pass base_url explicitly in the request"
    )


def _tool_name(operation: dict[str, Any], method: str, path: str, used: set[str]) -> str:
    raw = operation.get("operationId") or f"{method}_{path}"
    name = re.sub(r"[^a-zA-Z0-9_]+", "_", raw).strip("_").lower()[:64] or "op"
    if name[0].isdigit():
        name = f"op_{name}"[:64]
    candidate, n = name, 2
    while candidate in used:
        suffix = f"_{n}"
        candidate = name[: 64 - len(suffix)] + suffix
        n += 1
    used.add(candidate)
    return candidate


def _schema_of(param: dict[str, Any]) -> dict[str, Any]:
    schema = param.get("schema")
    if isinstance(schema, dict) and schema:
        return schema
    # Swagger 2.0 puts type info directly on the parameter.
    out = {k: v for k, v in param.items() if k in ("type", "format", "enum", "items", "default")}
    return out or {"type": "string"}


def _flatten_body(schema: dict[str, Any]) -> list[ToolParam]:
    """Expose top-level body properties as individual tool params.

    Flat argument lists are markedly easier for a model to fill correctly than
    one opaque nested ``body`` object. Anything that is not a plain object
    falls back to a single ``body`` parameter.
    """
    if schema.get("type") != "object" or not isinstance(schema.get("properties"), dict):
        return [
            ToolParam(
                name="body",
                location=ParamLocation.BODY,
                required=True,
                description="Request body.",
                schema=schema or {"type": "object"},
                body_path="",
            )
        ]
    required = set(schema.get("required") or [])
    params: list[ToolParam] = []
    for prop, prop_schema in schema["properties"].items():
        if not isinstance(prop_schema, dict):
            prop_schema = {"type": "string"}
        params.append(
            ToolParam(
                name=re.sub(r"[^a-zA-Z0-9_]+", "_", prop),
                location=ParamLocation.BODY,
                required=prop in required,
                description=prop_schema.get("description", ""),
                schema=prop_schema,
                body_path=prop,
            )
        )
    return params


def _request_body_params(operation: dict[str, Any]) -> list[ToolParam]:
    body = operation.get("requestBody")
    if not isinstance(body, dict):
        return []
    content = body.get("content") or {}
    media = content.get("application/json")
    if media is None:
        media = next(
            (v for k, v in content.items() if isinstance(k, str) and k.endswith("json")), None
        )
    if not isinstance(media, dict):
        return []
    schema = media.get("schema") or {"type": "object"}
    params = _flatten_body(schema)
    if body.get("required"):
        return params
    return [p.model_copy(update={"required": False}) for p in params]


def build_manifest(
    document: str | dict[str, Any],
    *,
    name: str | None = None,
    display_name: str | None = None,
    description: str = "",
    base_url: str | None = None,
    include_operations: list[str] | None = None,
    max_tools: int = 60,
    document_url: str | None = None,
) -> ToolManifest:
    doc = parse_document(document) if isinstance(document, str) else document
    if not isinstance(doc, dict):
        raise OpenAPIError("document root must be an object")

    resolver = _RefResolver(doc)
    info = doc.get("info") or {}
    title = info.get("title") or "API"
    resolved_base = _pick_base_url(doc, base_url, document_url)

    include = {o.lower() for o in (include_operations or [])}
    used_names: set[str] = set()
    tools: list[ToolDef] = []

    paths = doc.get("paths") or {}
    if not isinstance(paths, dict):
        raise OpenAPIError("`paths` must be an object")

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        shared = resolver.resolve(path_item.get("parameters") or [])
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            if operation.get("deprecated"):
                continue

            op_id = (operation.get("operationId") or "").lower()
            if include and op_id not in include and path.lower() not in include:
                continue

            operation = resolver.resolve(operation)
            params: list[ToolParam] = []
            seen: set[str] = set()

            for p in [*shared, *(operation.get("parameters") or [])]:
                if not isinstance(p, dict) or "name" not in p:
                    continue
                loc = p.get("in")
                if loc == "formData":  # Swagger 2.0 form bodies: unsupported.
                    continue
                if loc == "body":  # Swagger 2.0 body parameter.
                    params.extend(_flatten_body(p.get("schema") or {"type": "object"}))
                    continue
                if loc not in ("path", "query", "header"):
                    continue
                # Auth headers are injected by the runtime, never by the model.
                if loc == "header" and p["name"].lower() in ("authorization", "cookie"):
                    continue
                key = f"{loc}:{p['name']}"
                if key in seen:
                    continue
                seen.add(key)
                params.append(
                    ToolParam(
                        name=re.sub(r"[^a-zA-Z0-9_]+", "_", p["name"]),
                        location=ParamLocation(loc),
                        required=bool(p.get("required")) or loc == "path",
                        description=p.get("description", ""),
                        schema=_schema_of(p),
                        body_path=None,
                    )
                )

            if method in _MUTATING:
                params.extend(_request_body_params(operation))

            summary = operation.get("summary") or operation.get("description") or ""
            tools.append(
                ToolDef(
                    name=_tool_name(operation, method, path, used_names),
                    description=summary.strip()[:1024],
                    # Read straight out of the document, so it is exact.
                    evidence=ToolEvidence.SPEC,
                    evidence_note=f"declared in {title}",
                    method=method.upper(),  # type: ignore[arg-type]
                    path=path if path.startswith("/") else f"/{path}",
                    params=params,
                    read_only=method in ("get", "head"),
                    idempotent=method in ("get", "head", "put", "delete"),
                    destructive=method == "delete",
                )
            )
            if len(tools) >= max_tools:
                break
        if len(tools) >= max_tools:
            break

    if not tools:
        raise OpenAPIError("no usable operations found in document")

    slug = slugify(name or title)
    return ToolManifest(
        name=slug,
        display_name=display_name or title,
        description=(description or info.get("description") or "").strip()[:2048],
        base_url=resolved_base,
        tools=tools,
        source={"kind": "openapi", "title": title, "version": info.get("version", "")},
    )
