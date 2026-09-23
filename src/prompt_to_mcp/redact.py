"""Secret-safe rendering of configuration for the record store and the UI.

Everything captured on an :class:`~prompt_to_mcp.models.McpRecord` is persisted
to Firestore and rendered in a browser, so raw client secrets and access tokens
must never appear there. Dropping them entirely, though, makes the config view
useless for the one question it most often has to answer: *is this the same
secret the other run used?*

The compromise is a **fingerprint**: a truncated SHA-256 of the value plus its
length. Two identical secrets fingerprint identically, a typo changes the
fingerprint completely, and nothing about the value itself is recoverable.

Two layers, because key names are not enough
--------------------------------------------
Matching on the *key* covers structured fields (``client_secret``, ``token``)
and nothing else. It missed the case that actually happened: a user pasted a
live Google API key into the free-text ``description`` field --

    "create an mcp server from the google genai sdk
     here us the api key AQ.<forty-odd more characters>"

-- and ``description`` is not a secret-sounding name, so the key was written to
Firestore in the clear, echoed back to the browser, and later shipped inside a
downloadable package. Nothing was wrong with the key-name rule; the value simply
never passed through a field it governs.

So string *values* are scrubbed too, against the shapes real credentials take.
This is a backstop, not the primary control -- :mod:`prompt_to_mcp.resolve`
lifts a pasted key into the ``api_key`` field where the key-name rule owns it --
but a backstop is what was missing, and the cost of a false positive here (a
fingerprint where a token-shaped string used to be) is far below the cost of a
false negative.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

#: Exact key names whose values are secrets. Matching is case-insensitive and
#: also matches any key *ending* in one of these (e.g. ``upstream_client_secret``,
#: ``clientSecret``), so new call sites are covered by default rather than by
#: remembering to add them here.
SECRET_KEYS: frozenset[str] = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "clientsecret",
        "code_verifier",
        "id_token",
        "oauth_access_token",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "setup_access_token",
        "token",
    }
)

#: Keys that look secret by the rule above but are not. ``authorization`` is the
#: worst offender: on an McpRecord it is a Discovery Engine *resource name*
#: (``projects/*/locations/*/authorizations/*``), which is exactly the value an
#: operator needs to read.
NOT_SECRET_KEYS: frozenset[str] = frozenset(
    {
        "authorization",
        "authorization_endpoint",
        "authorization_uri",
        "token_endpoint",
        "token_uri",
        "upstream_client_secret_ref",
        "client_secret_ref",
        "client_secret_salt",
    }
)

REDACTED = "\u2014"  # shown when there is nothing to fingerprint

#: Credential shapes recognised inside free text, as ``(label, pattern)``.
#:
#: Deliberately prefix-anchored rather than entropy-based. A generic "long
#: random-looking string" rule fires on git SHAs, base64 payloads, resource ids
#: and URL path segments, all of which are common in the documentation users
#: paste and all of which an operator needs to be able to read. Issuer prefixes
#: are unambiguous, so these match a credential or they match nothing.
CREDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Google: classic browser/API keys, and the newer `AQ.`-prefixed keys.
    # Standard Google keys are AIza + 35 chars, but an exact length with a
    # trailing \b silently misses anything longer, so accept 35 or more.
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35,}")),
    ("google_api_key", re.compile(r"\bAQ\.[A-Za-z0-9_\-]{20,}")),
    ("google_oauth_token", re.compile(r"\bya29\.[A-Za-z0-9_\-]{20,}")),
    ("gcp_service_account_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("notion_token", re.compile(r"\b(?:ntn|secret)_[A-Za-z0-9]{40,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._\-]{20,})")),
)

#: A credential the user *labelled* but whose issuer we do not recognise, e.g.
#: ``here us the api key AQ.Ab8...`` or ``token = 8f3c...``. The label is the
#: evidence, so the value only has to look like a token rather than like a
#: specific vendor's token.
LABELLED_SECRET_RE = re.compile(
    r"(?i)\b(api[\s_\-]?key|apikey|access[\s_\-]?token|auth[\s_\-]?token|token|secret|password)"
    r"\b(?:\s+(?:is|are|=|:))?[\s:=]+[\"'`]?([A-Za-z0-9._\-]{16,})[\"'`]?"
)

#: Values that satisfy :data:`LABELLED_SECRET_RE` but are prose, not secrets.
#: Without this, "the api key is required" fingerprints the word "required".
_LABEL_FALSE_POSITIVES = frozenset(
    {
        "required",
        "optional",
        "necessary",
        "available",
        "generated",
        "configured",
        "authentication",
        "authorization",
        "credentials",
        "environment",
        "documentation",
        "placeholder",
        "your_api_key",
        "your-api-key",
    }
)


def _looks_like_a_token(value: str) -> bool:
    """Reject prose that happens to follow a secret-ish label.

    A real credential is long and mixes character classes. An English word is
    neither, so requiring both a digit and a letter -- or an unusual length --
    separates them without needing a dictionary.
    """
    if value.lower() in _LABEL_FALSE_POSITIVES:
        return False
    if value.startswith(("http://", "https://")):
        return False
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    mixed_case = value != value.lower() and value != value.upper()
    return (has_digit and has_alpha) or mixed_case or len(value) >= 32


def find_credentials(text: str) -> list[str]:
    """Credential-shaped substrings in ``text``, in the order they appear.

    The detection half of :func:`scrub_text`. Resolution uses it to *lift* a
    pasted key into the field that knows what to do with one, which is strictly
    better than scrubbing it: the user gets the server they asked for, and the
    key ends up in Secret Manager instead of in a description.
    """
    if not text:
        return []

    found: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            found.append(value)

    for _label, pattern in CREDENTIAL_PATTERNS:
        for match in pattern.finditer(text):
            _add(match.group(1) if match.groups() else match.group(0))

    for match in LABELLED_SECRET_RE.finditer(text):
        value = match.group(2)
        if _looks_like_a_token(value):
            _add(value)

    return found


def scrub_text(text: str) -> str:
    """Replace credential-shaped substrings in free text with fingerprints.

    The surrounding prose is preserved, so a record still reads as what the user
    wrote -- ``"here us the api key ***a1b2c3d4 (52 chars)"`` -- which is what
    makes it possible to see that a credential *was* supplied, and whether it
    was the same one as last time, without exposing it.
    """
    if not text or len(text) < 16:
        return text

    def _sub_issuer(match: re.Match[str]) -> str:
        # Patterns with a group keep their surrounding context (the word
        # "Bearer" is worth reading; the token after it is not).
        value = match.group(1) if match.groups() else match.group(0)
        return match.group(0).replace(value, fingerprint(value))

    for _label, pattern in CREDENTIAL_PATTERNS:
        text = pattern.sub(_sub_issuer, text)

    def _sub_labelled(match: re.Match[str]) -> str:
        value = match.group(2)
        if not _looks_like_a_token(value):
            return match.group(0)
        return match.group(0).replace(value, fingerprint(value))

    return LABELLED_SECRET_RE.sub(_sub_labelled, text)


def fingerprint(value: str) -> str:
    """A stable, non-reversible label for a secret.

    ``"***a1b2c3d4 (40 chars)"`` -- comparable across runs and across records,
    but useless to anyone who reads it.
    """
    if not value:
        return REDACTED
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"***{digest} ({len(value)} chars)"


def is_secret_key(key: str) -> bool:
    k = key.strip().lower()
    if k in NOT_SECRET_KEYS:
        return False
    if k in SECRET_KEYS:
        return True
    # `upstream_client_secret`, `oauth.clientSecret`, `x-api-key`, ...
    return any(k.endswith(suffix) for suffix in ("_secret", "_token", "_password", "_key"))


def redact(value: Any, *, _key: str = "") -> Any:
    """Deep-copy ``value``, replacing secret-valued leaves with fingerprints.

    Structure is preserved exactly: a caller can diff two redacted configs and
    see every difference except the secret plaintext.

    A leaf under a secret-sounding key is fingerprinted whole. Every *other*
    string is passed through :func:`scrub_text`, which fingerprints only the
    credential-shaped substrings inside it and leaves the surrounding prose
    alone. That second pass is what covers free-text fields nobody thought to
    name like a secret.
    """
    if isinstance(value, dict):
        return {k: redact(v, _key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, _key=_key) for v in value]
    if _key and is_secret_key(_key):
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        return fingerprint(str(value))
    if isinstance(value, str):
        return scrub_text(value)
    return value
