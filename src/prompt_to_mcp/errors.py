"""Exceptions shared across layers that would otherwise import each other.

:mod:`prompt_to_mcp.sdk_agent` needs the OpenAPI parser and the hardened
fetcher, both of which live under :mod:`prompt_to_mcp.ingest`; ingest in turn
has to catch the agent's failures and map them to a 400. Declaring the shared
exception here keeps that a one-way dependency. Importing it from either side
is safe in any order, which the alternative was not: with the error defined in
``sdk_agent``, importing that module *first* raised
``cannot import name ... from partially initialized module``.
"""

from __future__ import annotations


class SdkResolutionError(ValueError):
    """An SDK reference could not be turned into a usable API description.

    Caller-input class: the reference was unusable, or nothing behind it
    described an HTTP API. Belongs in ``INGEST_INPUT_ERRORS``.
    """
