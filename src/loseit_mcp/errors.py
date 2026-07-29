"""User-facing error translation.

This server depends on a private, reverse-engineered API. When Lose It changes
it, the failure surfaces deep inside a wire-format decoder as something like a
``//EX`` envelope or an unexpected token — accurate, but useless to whoever is
holding the chat window.

These helpers turn those failures into messages that say what happened, whether
the user can do anything about it, and what the operator should check.
"""

from __future__ import annotations

from lose_it.core._http import LoseItAuthError, LoseItError

from .config import ConfigError
from .sealed import SealError
from .weight import WeightHistoryError


class LoseItMcpError(RuntimeError):
    """An error already phrased for the end user."""


_UPSTREAM_CHANGED = (
    "Lose It's private API did not respond as expected. This usually means they "
    "deployed a new version of their web app, which changes the protocol this "
    "server speaks.\n\n"
    "Nothing is wrong with your account or your food log. Tell the user this is "
    "a server-side compatibility problem that needs the operator to refresh the "
    "GWT build identifiers (LOSEIT_STRONG_NAME / LOSEIT_POLICY_HASH), and that "
    "retrying now will not help.\n\n"
    "Technical detail: {detail}"
)

_AUTH_FAILED = (
    "Lose It rejected the credentials for this request.\n\n"
    "Tell the user to check the email and password configured for this server. "
    "If they recently changed their Lose It password, the stored credentials "
    "need updating (re-enroll, or update the configured headers).\n\n"
    "Technical detail: {detail}"
)

_UNREACHABLE = (
    "Could not reach Lose It. The service may be down or the network path from "
    "this server may be blocked.\n\n"
    "Tell the user this is likely temporary and worth retrying in a few "
    "minutes.\n\n"
    "Technical detail: {detail}"
)

# Substrings that indicate the wire format no longer matches our expectations,
# as opposed to an ordinary server-side error.
_PROTOCOL_MARKERS = (
    "Unexpected response",
    "unexpected response",
    "Could not decode",
    "too large to decode",
    "IncompatibleRemoteServiceException",
    "SerializationException",
    "policy",
)


def translate(exc: Exception) -> Exception:
    """Return an exception whose message is fit to show a user.

    Anything already user-facing (``ValueError`` from argument validation,
    configuration problems, enrollment failures) is passed through unchanged;
    those messages are actionable as they stand.
    """
    if isinstance(exc, LoseItMcpError | ValueError | ConfigError | SealError):
        return exc

    if isinstance(exc, LoseItAuthError):
        return LoseItMcpError(_AUTH_FAILED.format(detail=exc))

    if isinstance(exc, WeightHistoryError):
        return LoseItMcpError(_UPSTREAM_CHANGED.format(detail=exc))

    if isinstance(exc, LoseItError):
        detail = str(exc)
        if any(marker in detail for marker in _PROTOCOL_MARKERS):
            return LoseItMcpError(_UPSTREAM_CHANGED.format(detail=detail))
        if "Authentication" in detail or "authentication" in detail:
            return LoseItMcpError(_AUTH_FAILED.format(detail=detail))
        return LoseItMcpError(
            f"Lose It returned an error for this request.\n\n"
            f"Tell the user what was attempted and that Lose It refused it.\n\n"
            f"Technical detail: {detail}"
        )

    # httpx raises a family of transport errors; match by module rather than
    # importing every subclass.
    if type(exc).__module__.startswith("httpx"):
        return LoseItMcpError(_UNREACHABLE.format(detail=exc))

    # Decoding failures from the GWT parser arrive as plain structural errors.
    if isinstance(exc, KeyError | IndexError | TypeError | AttributeError):
        return LoseItMcpError(
            _UPSTREAM_CHANGED.format(detail=f"{type(exc).__name__}: {exc}")
        )

    return exc
