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

from .paths import TOKEN_REDACT_RE, split_token_path

# Set per request by PathTokenMiddleware; read by tenancy when no credential
# headers are present.
_path_token: ContextVar[str | None] = ContextVar("loseit_path_token", default=None)


def current_path_token() -> str | None:
    """The sealed segment for the request being served, if any."""
    return _path_token.get()


class _RedactTokenFilter(logging.Filter):
    """Rewrites ``/u/<sealed>`` to ``/u/<redacted>`` in log records.

    A sealed URL is a bearer credential and it rides in the path — exactly what
    access logs record. Redaction runs on the *formatted* message because the
    segment can be split across ``msg`` and ``args``, where neither part matches
    on its own.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:  # noqa: BLE001 - a broken record is not ours to fix
            return True

        redacted = TOKEN_REDACT_RE.sub(r"\1<redacted>", rendered)
        if redacted != rendered:
            record.msg = redacted
            record.args = ()
        return True


def install_log_redaction() -> None:
    """Attach redaction to every active log handler.

    Filters must go on handlers, not loggers: a logger's filters only run for
    records logged directly on it, so records propagating up from third-party
    loggers would otherwise bypass them.
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

