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
