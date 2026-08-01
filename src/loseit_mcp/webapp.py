"""HTTP wiring for the hosted deployment.

Routes ``/u/<sealed>/mcp`` to the MCP mount point, stashing the sealed segment
for the request, and keeps that segment out of the logs.

The segment is carried in a ``ContextVar`` rather than a mutated header, so
nothing downstream can mistake it for client-supplied input and it cannot leak
between concurrently-served requests.

Minting those URLs lives in :mod:`loseit_mcp.enroll`.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

from .paths import scrub as _scrub
from .paths import split_token_path

# Set per request by PathTokenMiddleware; read by tenancy when no credential
# headers are present.
_path_token: ContextVar[str | None] = ContextVar("loseit_path_token", default=None)


def current_path_token() -> str | None:
    """The sealed segment for the request being served, if any."""
    return _path_token.get()


def _redact_record(record: logging.LogRecord) -> None:
    """Strip credentials from every part of a record that can carry text.

    Applied in one place so the handler filter and the record factory cannot
    drift apart — an earlier version scrubbed the message in both but the
    traceback in only one, so a handler attached after startup still received
    an unredacted stack.
    """
    try:
        rendered = record.getMessage()
    except Exception:  # noqa: BLE001 - a broken record is not ours to fix
        # Fail closed. A record whose formatting raised still holds its raw
        # message and arguments, and those are exactly what would leak.
        record.msg = _scrub(str(record.msg))
        record.args = ()
    else:
        redacted = _scrub(rendered)
        if redacted != rendered:
            record.msg = redacted
            record.args = ()

    # A traceback can embed a sealed URL — a request path appears in plenty of
    # frames — and it never passes through getMessage(), so redacting only the
    # message lets the credential out by the route carrying the most text.
    #
    # `exc_info` is left in place: an exporter such as Azure Monitor or Sentry
    # builds its exception telemetry from it, and clearing it would trade a
    # leak for a blind spot. Pre-setting a redacted `exc_text` means any
    # handler that re-renders the stack gets the safe version, because
    # `Formatter.format` reuses `exc_text` when it is already set.
    if record.exc_info and not record.exc_text:
        record.exc_text = _scrub(logging.Formatter().formatException(record.exc_info))
    elif record.exc_text:
        record.exc_text = _scrub(record.exc_text)


class _RedactTokenFilter(logging.Filter):
    """Rewrites ``/u/<sealed>`` to ``/u/<redacted>`` in log records.

    A sealed URL is a bearer credential and it rides in the path — exactly what
    access logs record. Redaction runs on the *formatted* message because the
    segment can be split across ``msg`` and ``args``, where neither part matches
    on its own.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        _redact_record(record)
        return True


def install_log_redaction() -> None:
    """Attach redaction to every active log handler, and to future ones.

    Filters must go on handlers, not loggers: a logger's filters only run for
    records logged directly on it, so records propagating up from third-party
    loggers would otherwise bypass them.

    Handlers added *later* — an Azure Monitor or OpenTelemetry exporter, a
    lazily-imported library — would also miss a one-shot pass, so the record
    factory is wrapped as a backstop. That runs for every record regardless of
    where it ends up.
    """
    log_filter = _RedactTokenFilter()
    seen: set[int] = set()

    def attach(handlers: Any) -> None:
        for handler in handlers:
            if id(handler) in seen:
                continue
            seen.add(id(handler))
            if not any(isinstance(f, _RedactTokenFilter) for f in handler.filters):
                handler.addFilter(log_filter)

    attach(logging.getLogger().handlers)
    for name in logging.root.manager.loggerDict:
        attach(getattr(logging.getLogger(name), "handlers", []))

    _install_record_factory()


_FACTORY_INSTALLED = False


def _install_record_factory() -> None:
    """Redact at record creation, so no handler can be missed."""
    global _FACTORY_INSTALLED
    if _FACTORY_INSTALLED:
        return
    previous = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        # The same treatment the handler filter applies, including the
        # traceback. A handler registered after startup never sees the filter,
        # so this has to be complete rather than a partial safety net.
        _redact_record(record)
        return record

    logging.setLogRecordFactory(factory)
    _FACTORY_INSTALLED = True


class PathTokenMiddleware:
    """Rewrites ``/u/<sealed>/rest`` to ``/rest`` and exposes the segment.

    Pure ASGI rather than Starlette's ``BaseHTTPMiddleware`` so it can rewrite
    the scope before routing, and so it doesn't interfere with the streaming
    responses the MCP transport relies on.
    """

    def __init__(self, app: ASGIApp, mount_path: str = "/mcp"):
        self._app = app
        self._mount_path = mount_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        token, remainder = split_token_path(scope.get("path", ""), self._mount_path)
        if token is None:
            await self._app(scope, receive, send)
            return

        scope = dict(scope)
        scope["path"] = remainder
        # ASGI delivers `path` already percent-decoded, so it can hold any
        # character; raw_path is its UTF-8 encoding. Encoding as ASCII would
        # raise on a non-ASCII path and 500 before any credential check.
        scope["raw_path"] = remainder.encode("utf-8")

        reset = _path_token.set(token)
        try:
            await self._app(scope, receive, send)
        finally:
            _path_token.reset(reset)

