# One image, two services.
#
# The default CMD starts the control plane (provisioning API + UI). The OAuth
# proxy runs from the same image with a different entrypoint --
# `python3 -m prompt_to_mcp.oauth_app`, set by deploy.sh via --command/--args.
# They are separate Cloud Run services because their exposure requirements are
# opposites (see src/prompt_to_mcp/oauth_app.py), but they share a codebase and
# a dependency set, so two images would be two things to keep in step for no
# benefit.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml ./
# Required by the build, not just good manners: pyproject sets
# `license-files = ["LICENSE"]`, and setuptools fails the build if the pattern
# matches nothing.
COPY LICENSE ./
COPY src ./src
# The generic MCP runtime's source is staged *into* the package so the control
# plane can hand a user the exact code their MCP runs. Nothing here imports it
# -- it is inert data that /v1/mcps/{id}/bundle.zip copies verbatim. Staged at
# build time rather than committed so there is one canonical copy (runtime/)
# and no chance of the shipped copy drifting from the deployed image.
COPY runtime ./src/prompt_to_mcp/runtime_src
# BUILD_STAMP is written into src/prompt_to_mcp by deploy.sh just before
# submitting, so the image carries the fingerprint of the tree it was built
# from. Shipped as package data (see pyproject.toml).
RUN pip install --no-cache-dir .

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001

ENV PORT=8080
EXPOSE 8080

# Single worker: provisioning runs as an in-process BackgroundTask, so state is
# per-process, and the workload is I/O-bound -- concurrency comes from the event
# loop rather than from forked workers.
CMD ["sh", "-c", "exec uvicorn --factory prompt_to_mcp.main:create_app --host 0.0.0.0 --port ${PORT}"]
