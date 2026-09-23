"""A reviewable, runnable package for one provisioned MCP server.

Why this exists
---------------
Provisioning is a black box from the outside. A user types a prompt and gets a
URL back; what actually got deployed lives in three places they cannot see --
a ``ToolManifest`` inside a Cloud Run environment variable, a shared runtime
image they never chose, and a Firestore record. "What is my MCP server actually
going to do when Gemini calls it?" is the question this module answers, by
handing over every input to that behaviour in one archive.

There is no code to collect
---------------------------
This system never generates code, on purpose (see
:mod:`prompt_to_mcp.models` and :mod:`prompt_to_mcp.deployer.cloud_run`): every
MCP runs the *same* prebuilt image, configured by a declarative manifest. So a
"code package" cannot be fetched from anywhere -- it is assembled here, from the
record's manifest plus a verbatim copy of the runtime source that interprets it.

That assembly is the honest representation of the deployment. The manifest is
the only thing that varies between two MCPs, and ``server.py`` is byte-identical
to what is running, so together they fully determine behaviour. Shipping them
together is also what makes the package *runnable*: ``docker build && docker
run`` reproduces the deployed service locally, which is the difference between
reading a config dump and being able to test a claim about it.

Determinism
-----------
File contents are hashed into a :attr:`Bundle.fingerprint`, and the zip is
written with a fixed timestamp so the same record always produces byte-identical
output. Without that, every download differs from the last one and the archive
is useless for answering "did this change since I reviewed it?" -- which is most
of the point.

Redaction
---------
``manifest.json`` is verbatim, because a redacted manifest would not run and the
record's manifest is already served unredacted by ``GET /v1/mcps/{id}``, so this
exposes nothing new. ``record.json`` is passed through :func:`redact.redact`
anyway: it carries provisioning config from every stage, which is a much wider
surface, and it is the file most likely to be pasted into a bug report.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import pathlib
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .build_info import STAGED_RUNTIME_DIRNAME, BuildInfo, read_build_info, repo_root
from .config import Settings
from .models import McpRecord, slugify
from .redact import redact

log = logging.getLogger(__name__)

#: Every file in the package, as ``(path, kind, description)``, in the order a
#: reviewer is shown them. Single source of truth: the same description labels
#: the file in the API and the UI *and* documents it in the generated README,
#: so a file can never be added to the package without appearing in its own
#: table of contents.
FILE_NOTES: tuple[tuple[str, str, str], ...] = (
    (
        "README.md",
        "docs",
        "what this package is, how to run it, and what to review",
    ),
    (
        "manifest.json",
        "manifest",
        "the declarative tool definitions the runtime executes; the only thing "
        "that differs between two MCP servers",
    ),
    (
        "agent_registry_tool_spec.json",
        "manifest",
        "the tool list published to Agent Registry, as Gemini Enterprise sees it",
    ),
    (
        "server.py",
        "runtime",
        "the generic MCP runtime, byte-identical to the deployed image",
    ),
    (
        "Dockerfile",
        "runtime",
        "builds the runtime image; unchanged per MCP",
    ),
    (
        "requirements.txt",
        "runtime",
        "runtime dependencies",
    ),
    (
        ".env.example",
        "runtime",
        "environment variables the runtime reads",
    ),
    (
        "record.json",
        "record",
        "the full provisioning record: per-stage config, errors, diagnosis",
    ),
)

#: ``path -> (kind, description)``.
NOTES: dict[str, tuple[str, str]] = {p: (k, d) for p, k, d in FILE_NOTES}

#: The subset copied verbatim off disk from the runtime source directory.
RUNTIME_FILES: tuple[str, ...] = ("server.py", "Dockerfile", "requirements.txt")

#: Fixed zip timestamp. Zip stores mtimes, so using the real clock would make
#: every download of an unchanged package a different file and defeat the
#: fingerprint. 1980-01-01 is the earliest a zip can represent.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

#: Guard on the JSON view, which inlines every file's content. The runtime
#: source is ~15 KB and manifests are capped well below this by Cloud Run's
#: env-var limit, so hitting it means something has gone wrong upstream.
MAX_INLINE_BUNDLE_BYTES = 4 * 1024 * 1024


class BundleError(RuntimeError):
    """The record cannot produce a package. Reported to the caller as 4xx."""


@dataclass(frozen=True, slots=True)
class BundleFile:
    """One file in the package."""

    path: str
    text: str
    #: Grouping for the UI: ``docs`` | ``manifest`` | ``runtime`` | ``record``.
    kind: str
    #: One line explaining why this file is in here.
    description: str

    @property
    def data(self) -> bytes:
        return self.text.encode("utf-8")

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def to_dict(self, *, include_content: bool) -> dict[str, Any]:
        out: dict[str, Any] = {
            "path": self.path,
            "kind": self.kind,
            "description": self.description,
            "bytes": self.size,
            "sha256": self.sha256,
        }
        if include_content:
            out["content"] = self.text
        return out


@dataclass(frozen=True, slots=True)
class Bundle:
    """Everything needed to review and re-run one provisioned MCP server."""

    mcp_id: str
    name: str
    generated_at: str
    files: list[BundleFile]
    #: Where the runtime source came from: ``packaged`` (staged into the image),
    #: ``repo`` (source checkout) or ``unavailable``.
    runtime_source: str
    #: Non-fatal gaps, e.g. a runtime source the image was built without. Shown
    #: to the user rather than silently producing a package that will not build.
    warnings: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Content hash of the package. Same record in, same hash out.

        Path-and-content, sorted, matching :func:`build_info.source_fingerprint`
        so the two read the same way when they appear side by side.
        """
        digest = hashlib.sha256()
        for f in sorted(self.files, key=lambda x: x.path):
            digest.update(f.path.encode())
            digest.update(f.data)
        return digest.hexdigest()[:12]

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)

    @property
    def filename(self) -> str:
        """Download name, carrying the fingerprint so two saved copies sort out."""
        return f"{slugify(self.name)}-{self.fingerprint}.zip"

    def to_dict(self, *, include_content: bool = True) -> dict[str, Any]:
        if include_content and self.total_bytes > MAX_INLINE_BUNDLE_BYTES:
            raise BundleError(
                f"package is {self.total_bytes} bytes, over the "
                f"{MAX_INLINE_BUNDLE_BYTES} byte inline limit; download the zip instead"
            )
        return {
            "mcp_id": self.mcp_id,
            "name": self.name,
            "generated_at": self.generated_at,
            "fingerprint": self.fingerprint,
            "runtime_source": self.runtime_source,
            "warnings": list(self.warnings),
            "filename": self.filename,
            "download_url": f"/v1/mcps/{self.mcp_id}/bundle.zip",
            "total_bytes": self.total_bytes,
            "files": [f.to_dict(include_content=include_content) for f in self.files],
        }

    def to_zip(self) -> bytes:
        """Deterministic zip: fixed mtimes, sorted entries, fixed compression."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for f in sorted(self.files, key=lambda x: x.path):
                info = zipfile.ZipInfo(f"{slugify(self.name)}/{f.path}", _ZIP_EPOCH)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                zf.writestr(info, f.data)
        return buf.getvalue()


# ---------------------------------------------------------------------------
# Runtime source lookup
# ---------------------------------------------------------------------------


def runtime_dir() -> tuple[pathlib.Path | None, str]:
    """Locate the generic MCP runtime's source.

    Two layouts, both legitimate. In the image the Dockerfile stages ``runtime/``
    into the package as ``runtime_src/``, because ``pip install .`` only ships
    what is under ``src/``. In a source checkout that directory does not exist
    and the repo's own ``runtime/`` is the live copy -- which is the *better*
    answer during development, since it is what ``make run-mcp`` executes.
    """
    packaged = pathlib.Path(__file__).parent / STAGED_RUNTIME_DIRNAME
    if (packaged / "server.py").is_file():
        return packaged, "packaged"

    checkout = repo_root() / "runtime"
    if (checkout / "server.py").is_file():
        return checkout, "repo"

    return None, "unavailable"


# ---------------------------------------------------------------------------
# Generated documentation
# ---------------------------------------------------------------------------


def _tool_table(record: McpRecord) -> str:
    manifest = record.manifest
    if manifest is None or not manifest.tools:
        return "_No tools in this manifest._\n"

    rows = [
        "| Tool | Method | Path | Evidence | Read-only |",
        "| --- | --- | --- | --- | --- |",
    ]
    for t in manifest.tools:
        # Evidence is the single most important column for review: `inferred`
        # means a model proposed this operation and nothing ever confirmed it.
        note = f" ({t.evidence_note})" if t.evidence_note else ""
        rows.append(
            f"| `{t.name}` | {t.method} | `{t.path}` | "
            f"{t.evidence.value}{note} | {'yes' if t.read_only else 'no'} |"
        )
    return "\n".join(rows) + "\n"


def _file_table() -> str:
    """The package's own table of contents, from :data:`FILE_NOTES`."""
    rows = ["| File | What it is |", "| --- | --- |"]
    rows += [f"| `{path}` | {description} |" for path, _, description in FILE_NOTES]
    return "\n".join(rows) + "\n"


def _readme(record: McpRecord, *, settings: Settings, build: BuildInfo) -> str:
    manifest = record.manifest
    assert manifest is not None  # guarded by build_bundle
    endpoint = record.mcp_endpoint or "(not deployed)"
    unproven = [t.name for t in manifest.tools if t.evidence.value == "inferred"]

    review = (
        "\n".join(f"- `{name}`" for name in unproven)
        if unproven
        else "None: every tool came from a specification or a live probe."
    )

    return f"""# {manifest.display_name}

Generated package for MCP server `{record.id}`, produced by prompt-to-mcp.

| | |
| --- | --- |
| MCP endpoint | {endpoint} |
| Upstream API | {manifest.base_url} |
| Upstream auth | `{manifest.auth.kind.value}` |
| Tools | {len(manifest.tools)} |
| Run state | `{record.state}` |
| Control plane build | `{build.fingerprint}` ({build.source}) |
| Project / region | {settings.project_id} / {settings.run_region} |

## What this package is

prompt-to-mcp does not generate code. Every MCP server it provisions runs the
**same** prebuilt image, whose source is `server.py` here, configured by the
declarative `manifest.json` here. Those two files together fully determine what
your MCP server does -- there is no third thing running somewhere else.

That is why this package is enough to reproduce the deployment locally.

## Run it

```sh
docker build -t {slugify(manifest.name)} .
docker run --rm -p 8080:8080 \\
  -e P2M_MANIFEST="$(cat manifest.json)" \\
  {slugify(manifest.name)}
```

The MCP endpoint is then `http://localhost:8080/mcp`, and `GET /healthz`
answers once the manifest has loaded.

Without Docker:

```sh
pip install -r requirements.txt
P2M_MANIFEST_FILE=./manifest.json python server.py
```

## Review it

**Tools that were inferred rather than verified** -- a model proposed the HTTP
operation and nothing confirmed it exists, so these are the ones worth checking
against the upstream API's real documentation:

{review}

### All tools

{_tool_table(record)}
## Files

{_file_table()}
## A note on secrets

`record.json` has been redacted: secret values are replaced with a
`***<hash> (<n> chars)` fingerprint. Identical secrets fingerprint identically,
so you can tell whether two runs used the same credential without the value
being recoverable. `manifest.json` is verbatim, and by design contains no
credentials -- the runtime forwards the caller's token and stores nothing.
"""


_ENV_EXAMPLE = """# Environment read by server.py. Exactly one manifest source is required.

# Inline JSON. This is what the deployed Cloud Run service uses, up to 24000
# bytes (Cloud Run caps total env-var size at 32 KiB).
# P2M_MANIFEST='{"name":"..."}'

# A gs:// URI, used instead when the manifest is too large to inline.
# P2M_MANIFEST_GCS=gs://bucket/manifests/service-id.json

# A local file. Easiest for running this package by hand.
P2M_MANIFEST_FILE=./manifest.json

# Optional.
LOG_LEVEL=INFO
P2M_UPSTREAM_TIMEOUT=45
P2M_MAX_RESPONSE_BYTES=1048576
PORT=8080
"""


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _json(value: Any) -> str:
    """Pretty, stable JSON. Trailing newline so the files are diff-friendly."""
    return json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def build_bundle(
    record: McpRecord,
    *,
    settings: Settings,
    build: BuildInfo | None = None,
) -> Bundle:
    """Assemble the package for ``record``.

    Raises :class:`BundleError` when the record has no manifest. That is not a
    bug: a run that registered an *existing* MCP server never produced one, and
    that server's code is not ours to hand out. Saying so plainly beats emitting
    a package that is missing the only file anyone wanted.
    """
    if record.manifest is None:
        raise BundleError(
            f"{record.id} has no manifest, so there is no package to build. "
            "Runs that register an existing MCP server (`mcp_url`) do not generate "
            "one, and runs that failed before `ingest` never got that far."
        )

    manifest = record.manifest
    build = build or read_build_info()
    warnings: list[str] = []
    files: list[BundleFile] = []

    def add(path: str, text: str) -> None:
        kind, description = NOTES[path]
        files.append(BundleFile(path=path, text=text, kind=kind, description=description))

    add("README.md", _readme(record, settings=settings, build=build))
    add("manifest.json", _json(manifest.model_dump(mode="json", by_alias=True)))
    add("agent_registry_tool_spec.json", _json(manifest.to_mcp_tool_spec()))

    source_dir, source_kind = runtime_dir()
    if source_dir is None:
        # Do not fail the whole package for this. The manifest is still the
        # thing worth reviewing, and a loud warning beats a 500 that makes the
        # feature look broken when it is the image that is missing a file.
        warnings.append(
            "The runtime source is not present in this build, so the package "
            "contains no server.py and will not build as-is. The control-plane "
            "image was built without staging runtime/ into the package."
        )
        log.warning("runtime source unavailable; package for %s omits it", record.id)
    else:
        for name in RUNTIME_FILES:
            path = source_dir / name
            if not path.is_file():
                warnings.append(f"runtime file {name!r} is missing from this build")
                continue
            add(name, path.read_text(encoding="utf-8"))

    add(".env.example", _ENV_EXAMPLE)

    # `manifest` is dropped: it is already its own file, and shipping a second,
    # redacted copy invites someone to diff the two and conclude the deployed
    # manifest differs from the reviewed one.
    add("record.json", _json(redact(record.model_dump(mode="json", exclude={"manifest"}))))

    return Bundle(
        mcp_id=record.id,
        name=manifest.name or record.display_name or record.id,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        files=files,
        runtime_source=source_kind,
        warnings=warnings,
    )
