"""HTTP wiring for the hosted deployment.

Adds two things around the MCP app:

- ``/u/<sealed>/mcp`` — routes a sealed-credential URL to the MCP mount point,
  stashing the sealed segment for the request.
- ``/enroll`` — mints those URLs.

The sealed segment is carried in a ``ContextVar`` rather than a mutated header,
so nothing downstream can mistake it for client-supplied input and it cannot
leak between concurrently-served requests.
"""

from __future__ import annotations

import hmac
import logging
import re
from contextvars import ContextVar
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .sealed import DEFAULT_TTL_DAYS, SealError, UrlSealer

# Set per request by PathTokenMiddleware; read by tenancy when no credential
# headers are present.
_path_token: ContextVar[str | None] = ContextVar("loseit_path_token", default=None)

# Sealed segments are base64url and a few hundred characters long.
# Cap the routable length as a DoS guard.
_TOKEN_RE = re.compile(r"^/u/([A-Za-z0-9_-]{32,2048})(/.*)?$")

# Deliberately open-ended, and NOT sharing the cap above: a bounded pattern
# would match only the first 2048 characters of an oversized segment and leave
# the tail in the log line. Redaction must never partially match.
_TOKEN_SUB_RE = re.compile(r"(/u/)[A-Za-z0-9_-]{32,}")

# Bound what can be sealed, so a mintable URL is always a routable one.
MAX_EMAIL_LENGTH = 256
MAX_PASSWORD_LENGTH = 512
MAX_TTL_DAYS = 3650


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

        redacted = _TOKEN_SUB_RE.sub(r"\1<redacted>", rendered)
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

        match = _TOKEN_RE.match(scope.get("path", ""))
        if match is None:
            await self._app(scope, receive, send)
            return

        remainder = match.group(2) or self._mount_path
        scope = dict(scope)
        scope["path"] = remainder
        # ASGI delivers `path` already percent-decoded, so it can hold any
        # character; raw_path is its UTF-8 encoding. Encoding as ASCII would
        # raise on a non-ASCII path and 500 before any credential check.
        scope["raw_path"] = remainder.encode("utf-8")

        reset = _path_token.set(match.group(1))
        try:
            await self._app(scope, receive, send)
        finally:
            _path_token.reset(reset)


def _public_base_url(request: Request) -> str:
    """Best-effort external base URL, honouring the proxy Azure puts in front."""
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    if not host:
        return str(request.base_url).rstrip("/")
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    return f"{scheme}://{host}"


def _optional_int(
    body: dict[str, Any],
    key: str,
    default: int | None,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    null_means_default: bool = False,
) -> int | None:
    """Read an optional integer field, or raise ``ValueError`` with a message.

    ``null_means_default`` matters for bounded fields: letting an explicit JSON
    ``null`` through as "no limit" would walk straight past ``minimum`` and
    ``maximum``.
    """
    if key not in body:
        return default
    raw = body[key]
    if raw is None:
        return default if null_means_default else None
    try:
        value = int(raw)
    except (TypeError, ValueError, OverflowError) as exc:
        # OverflowError: JSON `1e400` decodes to float('inf').
        raise ValueError(f"'{key}' must be a whole number.") from exc
    if minimum is not None and value < minimum:
        raise ValueError(f"'{key}' must be at least {minimum}.")
    if maximum is not None and value > maximum:
        raise ValueError(f"'{key}' must be at most {maximum}.")
    return value


def add_enrollment_route(
    mcp: Any,
    sealer: UrlSealer,
    *,
    mount_path: str = "/mcp",
    enroll_secret: str | None = None,
) -> None:
    """Attach ``POST /enroll``, which seals credentials into a URL.

    ``enroll_secret`` gates the endpoint. It is required in practice — an open
    endpoint on a public host lets anyone mint URLs, and each one is a working
    credential for whatever account they supplied.
    """

    @mcp.custom_route("/enroll", methods=["POST"])
    async def enroll(request: Request) -> JSONResponse:
        if enroll_secret and not hmac.compare_digest(
            request.headers.get("x-enroll-secret") or "", enroll_secret
        ):
            return JSONResponse({"error": "Enrollment is not open."}, status_code=403)

        try:
            body = await request.json()
        except (ValueError, TypeError):
            return JSONResponse({"error": "Expected a JSON body."}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "Expected a JSON object."}, status_code=400)

        email, password = body.get("email"), body.get("password")
        if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
            return JSONResponse(
                {"error": "Both 'email' and 'password' are required."}, status_code=400
            )
        # An unbounded credential yields a sealed segment too long to route,
        # so the URL we hand back would 404 on every request.
        if len(email) > MAX_EMAIL_LENGTH:
            return JSONResponse(
                {"error": f"'email' must be at most {MAX_EMAIL_LENGTH} characters."},
                status_code=400,
            )
        if len(password) > MAX_PASSWORD_LENGTH:
            return JSONResponse(
                {"error": f"'password' must be at most {MAX_PASSWORD_LENGTH} characters."},
                status_code=400,
            )

        try:
            # Expiry is the only remaining control on a leaked URL, so `null`
            # means "use the default" rather than "never expires".
            ttl_days = _optional_int(
                body,
                "ttl_days",
                DEFAULT_TTL_DAYS,
                minimum=1,
                maximum=MAX_TTL_DAYS,
                null_means_default=True,
            )
            hours_from_gmt = _optional_int(body, "hours_from_gmt", None, minimum=-12, maximum=14)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        try:
            sealed = sealer.seal(email, password, hours_from_gmt=hours_from_gmt, ttl_days=ttl_days)
        except SealError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        return JSONResponse(
            {
                "url": f"{_public_base_url(request)}/u/{sealed}{mount_path}",
                "expires_in_days": ttl_days,
                "note": (
                    "This URL is a credential. It cannot be revoked individually "
                    "— rotate LOSEIT_URL_SECRET to invalidate all issued URLs."
                ),
            },
            status_code=201,
        )
