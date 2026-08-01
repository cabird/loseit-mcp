"""Canonical handling of the ``/u/<sealed>/...`` URL shape.

The sealed segment shows up in three jobs — routing, throttle classification,
and log redaction — and each needs a slightly different match. Keeping the
shared vocabulary in one module is what stops them drifting apart.

They did drift once. Routing and throttling each defined their own pattern,
and because the throttle ran *ahead* of routing it classified requests by the
pre-rewrite path: it charged ``/u/<junk>/enroll`` to the tool budget while the
rewrite still delivered it to the enrollment handler. That turned a 5/hour
limit into 7200/hour. Hence the rule below.
"""

from __future__ import annotations

import re

# Sealed segments are base64url and a few hundred characters long. The upper
# bound is a DoS guard: anything longer is not routable, and so must not be
# treated as a credential-carrying URL by any layer.
_SEGMENT = r"[A-Za-z0-9_-]{32,2048}"

# The routable shape. Prefer `split_token_path` over matching this directly.
TOKEN_PATH_RE = re.compile(rf"^/u/({_SEGMENT})(/.*)?$")

# Deliberately open-ended, and deliberately NOT sharing the cap above: a
# bounded pattern would match only the first 2048 characters of an oversized
# segment and leave the tail in the log line. Redaction must never partially
# match.
TOKEN_REDACT_RE = re.compile(r"(/u/)[A-Za-z0-9_-]{32,}")

# A second net for credentials that arrive without their path prefix — a bare
# sealed segment, or a JWT. Anchoring only on "/u/" means anything logging the
# segment on its own would slip through.
#
# The 64-character floor is what keeps this from being destructive: food IDs
# and MCP session IDs are exactly 32 hex characters, so they stay legible,
# while sealed URLs (~136 chars) and JWTs are comfortably above it. A blanket
# rule at 32 would redact the identifiers an operator most needs to follow.
LONG_SECRET_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{64,}(?![A-Za-z0-9_-])")

# JWTs need their own pattern: the dots between segments break them into runs
# shorter than the floor above, so a `liauth` token would otherwise survive.
# They always begin `eyJ` — base64url of `{"` — which makes this specific
# enough not to catch anything else.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")

# Validation errors echo the value that failed, and a caller can put anything
# in an argument — an address, a password, a whole credential pair. Anything
# email-shaped is therefore removed from text destined for a log.
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def scrub(text: str) -> str:
    """Remove anything credential-shaped from text bound for a log.

    Ordered widest-anchor first so a sealed URL is replaced as a unit rather
    than being partly consumed by a later pattern.
    """
    scrubbed = TOKEN_REDACT_RE.sub(r"\1<redacted>", text)
    scrubbed = JWT_RE.sub("<redacted-jwt>", scrubbed)
    scrubbed = LONG_SECRET_RE.sub("<redacted>", scrubbed)
    return EMAIL_RE.sub("<redacted-email>", scrubbed)

DEFAULT_MOUNT_PATH = "/mcp"


def split_token_path(path: str, mount_path: str = DEFAULT_MOUNT_PATH) -> tuple[str | None, str]:
    """Split ``/u/<sealed>/rest`` into its sealed segment and effective path.

    Returns ``(None, path)`` unchanged when the path carries no sealed segment,
    so callers can handle both shapes without branching.

    **Every layer that inspects a path must agree on this split.** Routing
    rewrites the path, so any component deciding policy *before* routing has to
    classify on the returned effective path rather than the raw one — otherwise
    it is reasoning about a URL the application will never see.

    A segment that is present but unroutable (too long, wrong alphabet) yields
    ``(None, path)``: the request will 404, and until then it is treated as the
    anonymous traffic it effectively is.
    """
    match = TOKEN_PATH_RE.match(path)
    if match is None:
        return None, path
    return match.group(1), match.group(2) or mount_path
