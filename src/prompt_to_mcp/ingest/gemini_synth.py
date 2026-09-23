"""Freeform API documentation -> :class:`ToolManifest` via Gemini.

Used only when the caller has no machine-readable OpenAPI document. The model
never emits code: it emits a JSON manifest that is validated by Pydantic before
anything is deployed. A malformed or malicious response fails validation and is
retried, then rejected -- it cannot become a running server.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from ..config import Settings
from ..models import ToolManifest, slugify

log = logging.getLogger(__name__)

MAX_DOC_CHARS = 400_000


class SynthesisError(ValueError):
    """The docs could not be turned into a valid manifest.

    A distinct type so the control plane can answer 400 (your documentation was
    unusable) rather than 500 (we broke).
    """


_SYSTEM = """\
You convert HTTP API documentation into a strict JSON tool manifest for an MCP \
(Model Context Protocol) server. You never write code. You only describe HTTP \
operations that are explicitly documented in the supplied material.

Rules:
- Emit ONLY a single JSON object. No markdown fences, no commentary.
- Invent nothing. If an endpoint, parameter, or base URL is not in the docs, omit it.
- `base_url` must be an absolute https origin (optionally with a base path), no trailing slash.
- Each tool's `path` is relative to base_url and starts with "/".
- Every `{placeholder}` in a path MUST have a matching param with location "path".
- Never emit an Authorization, Cookie, or API-key parameter: credentials are
  injected by the runtime, not by the caller.
- `name` fields: lowercase snake_case, <=64 chars, unique across tools.
- `schema` is a JSON Schema fragment, e.g. {"type":"string"} or
  {"type":"array","items":{"type":"number"}}.
- Prefer flat body params (one per top-level JSON field) over one nested object.

Output shape:
{
  "display_name": str,
  "description": str,
  "base_url": "https://...",
  "tools": [
    {
      "name": str,
      "description": str,
      "method": "GET"|"POST"|"PUT"|"PATCH"|"DELETE"|"HEAD",
      "path": "/...",
      "read_only": bool,
      "idempotent": bool,
      "destructive": bool,
      "params": [
        {
          "name": str,
          "location": "path"|"query"|"header"|"body",
          "required": bool,
          "description": str,
          "schema": {...},
          "body_path": str|null
        }
      ]
    }
  ]
}
"""

_USER_TEMPLATE = """\
The operator described the MCP server they want as follows:
<description>
{description}
</description>

{base_url_hint}{operations_hint}
Here is the API documentation:
<documentation>
{docs}
</documentation>

Emit at most {max_tools} tools, prioritising those relevant to the operator's \
description. Return only the JSON object.
"""


def _strip_fences(text: str) -> str:
    text = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.S)
    if fence:
        return fence.group(1).strip()
    # Fall back to the outermost brace pair.
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return text[start : end + 1]
    return text


class ManifestSynthesizer:
    """Wraps the Gemini call. Injected so tests can substitute a fake."""

    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        self.settings = settings
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            from google import genai  # imported lazily; heavy dependency

            self._client = genai.Client(
                vertexai=True,
                project=self.settings.project_id,
                location=self.settings.gemini_location,
            )
        return self._client

    def _generate(self, prompt: str) -> str:
        from google.genai import types

        resp = self._get_client().models.generate_content(
            model=self.settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM,
                response_mime_type="application/json",
                temperature=0.1,
                max_output_tokens=32768,
            ),
        )
        return resp.text or ""

    def synthesize(
        self,
        *,
        description: str,
        docs: str,
        name: str | None = None,
        base_url: str | None = None,
        include_operations: list[str] | None = None,
        attempts: int = 2,
    ) -> ToolManifest:
        if len(docs) > MAX_DOC_CHARS:
            log.warning("truncating docs from %d to %d chars", len(docs), MAX_DOC_CHARS)
            docs = docs[:MAX_DOC_CHARS]

        prompt = _USER_TEMPLATE.format(
            description=description,
            docs=docs,
            max_tools=self.settings.max_tools,
            base_url_hint=(f"Use exactly this base URL: {base_url}\n\n" if base_url else ""),
            operations_hint=(
                f"Restrict output to these operations: {', '.join(include_operations)}\n\n"
                if include_operations
                else ""
            ),
        )

        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                raw = _strip_fences(self._generate(prompt))
                payload = json.loads(raw)
            except (json.JSONDecodeError, ValueError) as exc:
                last_error = exc
                log.warning("manifest synthesis attempt %d: unparseable output: %s", attempt, exc)
                prompt += "\n\nYour previous reply was not valid JSON. Return only a JSON object."
                continue

            if base_url:
                payload["base_url"] = base_url
            payload.setdefault("display_name", name or "Generated MCP")
            payload["name"] = slugify(name or payload.get("display_name", "mcp"))
            payload.setdefault("description", description)
            payload["source"] = {"kind": "gemini", "model": self.settings.gemini_model}
            payload["tools"] = (payload.get("tools") or [])[: self.settings.max_tools]

            try:
                return ToolManifest.model_validate(payload)
            except Exception as exc:  # pydantic ValidationError
                last_error = exc
                log.warning("manifest synthesis attempt %d failed validation: %s", attempt, exc)
                prompt += (
                    f"\n\nYour previous reply failed validation with:\n{exc}\n"
                    "Fix these problems and return only the corrected JSON object."
                )

        raise SynthesisError(f"could not synthesise a valid tool manifest: {last_error}")
