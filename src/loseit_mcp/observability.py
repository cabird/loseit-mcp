"""Making a production incident diagnosable.

Before this, the entire package emitted one log record. A failing tool was
silent server-side, because MCP catches tool exceptions and returns them as a
successful JSON-RPC response — so the access log recorded ``200`` for a request
the user experienced as broken. Diagnosing an outage meant reproducing it by
hand against the live API.

What is logged is deliberately narrow. Diary contents, food names, weights,
email addresses and sealed URLs are all absent: the point is to answer "which
tool, for whom, how long, and did it work", not to reconstruct what someone
ate.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from typing import Any

from .paths import scrub

logger = logging.getLogger("loseit_mcp.tools")

# Correlates the lines belonging to one tool call.
_request_id: ContextVar[str | None] = ContextVar("loseit_request_id", default=None)

# Salts the account tag. Regenerated per process on purpose: correlation within
# a process is what incident diagnosis needs, and a stable salt would turn the
# log into something that can confirm whether a *guessed* email uses the
# service. A restart costs nothing here and closes that.
_TAG_SALT = os.urandom(16)


def account_tag(identity: str | None) -> str:
    """A short, non-reversible handle for one account.

    Not the email, and not the sealed URL. Enough to tell two users apart in a
    log, useless for finding out who they are.

    Sixteen hex characters, not eight: at eight the tag is 32 bits, which
    collides with about 1% probability across ten thousand accounts — enough to
    silently attribute one user's failure to another during an incident.
    """
    if not identity:
        return "anon"
    return hmac.new(_TAG_SALT, identity.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


# Failures we already understand and report deliberately. These get a one-line
# summary; anything else keeps its stack, because an unanticipated fault is
# exactly when the stack is worth its volume.
_EXPECTED_ERRORS = frozenset(
    {
        "LoseItMcpError",
        "LoseItError",
        "LoseItAuthError",
        "ValueError",
        "CredentialsError",
        "SealError",
        "PortionError",
        "WeightHistoryError",
    }
)


def current_request_id() -> str | None:
    return _request_id.get()


def _root_cause(exc: BaseException) -> BaseException:
    """The deepest exception in the chain.

    ``acquire`` re-raises a translated, user-facing error, and MCP wraps that
    again, so the immediate cause is prose written for the model: every
    distinct protocol break produces the same opening sentence. The useful
    class and message are at the bottom of the chain.
    """
    seen: set[int] = set()
    while exc.__cause__ is not None and id(exc) not in seen:
        seen.add(id(exc))
        exc = exc.__cause__
    return exc


def _is_expected(exc: BaseException) -> bool:
    """True for failures we raise on purpose.

    Matched by class rather than by name. Name matching collided with
    same-named third-party classes, and — worse — ``errors.translate`` converts
    ``TypeError``/``AttributeError``/``KeyError`` into a user-facing error, so
    ordinary programming bugs were being filed as anticipated and losing their
    stack, which is the exact inverse of the intent.
    """
    from lose_it.core._http import LoseItAuthError, LoseItError

    from .errors import LoseItMcpError
    from .sealed import SealError
    from .tenancy import CredentialsError

    return isinstance(
        exc,
        LoseItMcpError | LoseItError | LoseItAuthError | SealError | CredentialsError | ValueError,
    )


def install_tool_logging(mcp: Any) -> None:
    """Wrap the tool manager so every call is recorded exactly once.

    Hooking the manager rather than each tool means a tool added later is
    covered automatically, and it sits inside MCP's own exception handling, so
    failures are observed before they are converted into a polite message for
    the model.
    """
    manager = mcp._tool_manager
    original: Callable[..., Awaitable[Any]] = manager.call_tool

    async def call_tool(name: str, arguments: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
        request_id = uuid.uuid4().hex[:8]
        token = _request_id.set(request_id)
        started = time.monotonic()
        try:
            result = await original(name, arguments, *args, **kwargs)
        except Exception as exc:
            root = _root_cause(exc)
            # A traceback for every rejected food id would bury the signal, so
            # the stack is kept for faults we did not anticipate. Anything
            # raised deliberately is a known outcome and its message says
            # everything the stack would.
            logger.warning(
                "tool=%s id=%s outcome=error dur_ms=%d error=%s detail=%s",
                name,
                request_id,
                int((time.monotonic() - started) * 1000),
                type(root).__name__,
                scrub(_detail(root)),
                exc_info=not _is_expected(root),
            )
            raise
        except BaseException:
            # A client that disconnects or times out cancels the task, and
            # CancelledError is not an Exception. Without this the literal
            # "it stopped working" symptom produces no record at all.
            logger.warning(
                "tool=%s id=%s outcome=abandoned dur_ms=%d",
                name,
                request_id,
                int((time.monotonic() - started) * 1000),
            )
            raise
        else:
            logger.info(
                "tool=%s id=%s outcome=ok dur_ms=%d args=%s",
                name,
                request_id,
                int((time.monotonic() - started) * 1000),
                _safe_args(arguments),
            )
            return result
        finally:
            _request_id.reset(token)

    manager.call_tool = call_tool  # type: ignore[method-assign]


# Argument values that describe *how* a tool was called rather than what the
# user ate. Everything else is reduced to its name, so a log shows the shape of
# a call without carrying diary content.
_LOGGABLE_ARGS = frozenset(
    {"limit", "meal", "dry_run", "date", "days", "start", "end", "servings", "serving_unit"}
)


def _safe_args(arguments: dict[str, Any]) -> str:
    """Render call arguments without their sensitive values."""
    parts = []
    for key in sorted(arguments):
        value = arguments[key]
        if key in _LOGGABLE_ARGS:
            parts.append(f"{key}={value!r}")
        else:
            parts.append(f"{key}=<{type(value).__name__}>")
    return ",".join(parts) or "none"

def _detail(exc: BaseException) -> str:
    """The informative part of an error message.

    Translated errors lead with prose for the model and put the actual fault
    after "Technical detail:", so taking the first line logged an identical
    sentence for every distinct protocol break.
    """
    text = str(exc)
    marker = "Technical detail:"
    if marker in text:
        text = text.split(marker, 1)[1]
    return " ".join(text.split())[:200]
