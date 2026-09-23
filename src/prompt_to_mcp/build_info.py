"""What code is actually running.

This module exists because of a specific incident. A fix was written, tested,
reviewed and reported as done -- and never deployed. The next run failed
identically, and the failure was indistinguishable from the fix not working,
because the only evidence available was the behaviour of the old code. Roughly
an hour went into re-diagnosing a bug that had already been fixed.

The repository has no commits, so a git SHA is not available and would not be
the right signal anyway: what matters is whether the *source tree* differs from
what the running service was built from. So the stamp is a content fingerprint
over the files that end up in the image. Comparing the local fingerprint to the
one on ``/readyz`` answers "is my fix live?" in one call.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
from dataclasses import dataclass
from datetime import UTC, datetime

#: Written by ``deploy/deploy.sh`` into the build context immediately before
#: submitting, so it is baked into the image and travels with it.
STAMP_FILENAME = "BUILD_STAMP"

#: Everything that changes behaviour. The UI is included because a stale
#: ``app.js`` produces exactly the same "my change isn't there" confusion.
_SOURCE_GLOBS = ("src/**/*.py", "runtime/**/*.py", "src/prompt_to_mcp/static/*")

#: Build-time staging directory: a verbatim copy of ``runtime/`` placed inside
#: the package so the control plane can serve it as a downloadable package.
#: Excluded from the fingerprint because ``runtime/**/*.py`` already counts the
#: canonical copy, and counting it twice would make the same tree fingerprint
#: differently depending on whether a build had been staged into it.
STAGED_RUNTIME_DIRNAME = "runtime_src"

UNKNOWN = "unknown"


@dataclass(frozen=True)
class BuildInfo:
    #: Content fingerprint of the source tree this build came from.
    fingerprint: str
    #: When the stamp was written, ISO-8601. ``unknown`` for an unstamped run.
    built_at: str
    #: ``stamped`` when read from the image, ``live`` when computed from disk.
    source: str

    def to_dict(self) -> dict[str, str]:
        return {
            "fingerprint": self.fingerprint,
            "built_at": self.built_at,
            "source": self.source,
        }


def repo_root(start: pathlib.Path | None = None) -> pathlib.Path:
    """The directory containing ``pyproject.toml``, or the package parent."""
    here = start or pathlib.Path(__file__).resolve()
    for candidate in [here, *here.parents]:
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return pathlib.Path(__file__).resolve().parents[2]


def source_fingerprint(root: pathlib.Path | None = None) -> str:
    """Content hash of every file that can change the service's behaviour.

    Path-and-content, sorted, so it is stable across machines and independent
    of mtimes. Returns :data:`UNKNOWN` if the source tree is not present --
    which is the normal case inside the image, where the stamp file is used
    instead.
    """
    root = root or repo_root()
    digest = hashlib.sha256()
    seen = 0
    for pattern in _SOURCE_GLOBS:
        for path in sorted(root.glob(pattern)):
            if not path.is_file() or path.name == STAMP_FILENAME:
                continue
            if STAGED_RUNTIME_DIRNAME in path.parts:
                continue
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
            seen += 1
    return digest.hexdigest()[:12] if seen else UNKNOWN


def write_stamp(root: pathlib.Path | None = None) -> BuildInfo:
    """Record the current fingerprint into the package, for the build to copy."""
    root = root or repo_root()
    info = BuildInfo(
        fingerprint=source_fingerprint(root),
        built_at=datetime.now(UTC).isoformat(timespec="seconds"),
        source="stamped",
    )
    target = root / "src" / "prompt_to_mcp" / STAMP_FILENAME
    target.write_text(f"{info.fingerprint}\n{info.built_at}\n", encoding="utf-8")
    return info


def read_build_info() -> BuildInfo:
    """The running build's identity.

    Prefers the stamp baked into the image. Falls back to fingerprinting the
    source tree, which is what happens during local development -- and is
    correct there, because local source *is* what is running.
    """
    override = os.getenv("P2M_BUILD_FINGERPRINT")
    if override:
        return BuildInfo(override, os.getenv("P2M_BUILD_TIME", UNKNOWN), "env")

    stamp = pathlib.Path(__file__).with_name(STAMP_FILENAME)
    if stamp.is_file():
        lines = stamp.read_text(encoding="utf-8").splitlines()
        if lines and lines[0].strip():
            built = lines[1].strip() if len(lines) > 1 else UNKNOWN
            return BuildInfo(lines[0].strip(), built, "stamped")

    return BuildInfo(source_fingerprint(), UNKNOWN, "live")


if __name__ == "__main__":  # pragma: no cover - build tooling
    import json
    import sys

    if "--check" in sys.argv:
        # Compare the local tree against a deployed service.
        #
        # The fingerprint used to live on /readyz, which was unauthenticated
        # and also disclosed the project id and every region setting. It moved
        # to /v1/buildinfo behind the same auth as everything else, so this has
        # to present an identity token -- both to satisfy Cloud Run's
        # roles/run.invoker check and the app's own principal allowlist.
        import subprocess
        import urllib.error
        import urllib.request

        url = sys.argv[sys.argv.index("--check") + 1].rstrip("/")

        token = os.getenv("P2M_ID_TOKEN")
        if not token:
            # No --audiences: gcloud rejects it for user accounts ("Invalid
            # account type for `--audiences`. Requires valid service account."),
            # and the control plane accepts gcloud's own client-ID audience for
            # exactly that reason.
            try:
                token = subprocess.run(  # noqa: S603 - fixed argv, no shell
                    ["gcloud", "auth", "print-identity-token"],  # noqa: S607
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=60,
                ).stdout.strip()
            except (OSError, subprocess.SubprocessError) as exc:
                print(
                    "could not mint an identity token. Install gcloud and run "
                    "`gcloud auth login`, or set P2M_ID_TOKEN.\n"
                    f"  {type(exc).__name__}: {exc}"
                )
                sys.exit(2)

        # One header. Cloud Run satisfies its IAM check from Authorization and
        # forwards it to the container intact, so the same token serves both
        # layers. (X-Serverless-Authorization would not: Cloud Run strips the
        # signature off that one before the container sees it.)
        request = urllib.request.Request(  # noqa: S310 - https URL supplied by the operator
            f"{url}/v1/buildinfo",
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:  # noqa: S310
                deployed = json.load(resp)["build"]
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                print(
                    f"{exc.code} from {url}/v1/buildinfo. The control plane requires an "
                    "allowlisted principal: check roles/run.invoker and "
                    "P2M_ALLOWED_PRINCIPALS."
                )
                sys.exit(2)
            raise

        local = source_fingerprint()
        same = deployed.get("fingerprint") == local
        print(f"local    : {local}")
        print(f"deployed : {deployed.get('fingerprint')} (built {deployed.get('built_at')})")
        print("MATCH" if same else "STALE -- the deployed service predates this working tree")
        sys.exit(0 if same else 1)

    info = write_stamp()
    print(f"{info.fingerprint} {info.built_at}")
