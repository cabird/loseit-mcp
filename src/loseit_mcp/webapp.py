"""HTTP wiring for the hosted deployment.

Adds two things around the MCP app:

- ``/u/<token>/mcp`` — path-token routing, for clients that can only be given
  a URL. The middleware strips the token, stashes it for the request, and
  rewrites the path so the MCP app sees its usual mount point.
- ``/enroll`` and ``/revoke`` — issuing and destroying those tokens.

The token is carried through the request in a ``ContextVar`` rather than a
mutated header, so nothing downstream can mistake it for client-supplied input
and it cannot leak between concurrently-served requests.
"""

from __future__ import annotations

import logging
import re
from contextvars import ContextVar
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .enrollment import DEFAULT_TTL_DAYS, EnrollmentError, EnrollmentRegistry

# Set per request by PathTokenMiddleware; read by tenancy when no credential
# headers are present.
_path_token: ContextVar[str | None] = ContextVar("loseit_path_token", default=None)

# URL-safe base64 alphabet, and long enough that a short path can't be mistaken
# for a token.
_TOKEN_RE = re.compile(r"^/u/([A-Za-z0-9_-]{16,128})(/.*)?$")

# Same shape, unanchored and with no trailing slash required, for scrubbing
# tokens out of log lines. `/u/<token>` with no remainder is a valid
# authenticated request, so a pattern anchored on a trailing `/` would let the
# bare form through unredacted.
_TOKEN_SUB_RE = re.compile(r"(/u/)[A-Za-z0-9_-]{16,128}")


def current_path_token() -> str | None:
    """The enrollment token for the request being served, if any."""
    return _path_token.get()


class _RedactTokenFilter(logging.Filter):
    """Rewrites ``/u/<token>`` to ``/u/<redacted>`` in log records.

    Enrollment tokens are bearer credentials *and* decryption keys, and they
    travel in the URL path — which is exactly what access logs record. Without
    this, running the server would quietly write every user's credential into
    the log pipeline, and a log + database compromise would defeat the
    encrypted-at-rest design entirely.

    Redaction is applied to the *formatted* message, because a token can be
    split across ``msg`` and ``args`` (``"fetched /u/%s/mcp", token``) where
    neither part matches on its own. When a token is found the record collapses
    to a pre-formatted message; records without one keep their original
    structure so structured-logging handlers are unaffected.
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
    """Attach token redaction to every active log handler.

    Filters must go on *handlers*, not loggers: a logger's filters only run for
    records logged directly on it, and records propagating up from child
    loggers bypass every ancestor logger's filters. Attaching to handlers is
    what actually catches output from arbitrary libraries.

    Call after the logging config is in place — uvicorn replaces handlers
    during startup.
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
        logger = logging.getLogger(name)
        attach(getattr(logger, "handlers", []))


class PathTokenMiddleware:
    """Rewrites ``/u/<token>/rest`` to ``/rest`` and exposes the token.

    Pure ASGI rather than Starlette ``BaseHTTPMiddleware`` so it can rewrite the
    scope before routing, and so it doesn't interfere with the streaming
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

        token, remainder = match.group(1), match.group(2) or self._mount_path
        scope = dict(scope)
        scope["path"] = remainder
        scope["raw_path"] = remainder.encode("ascii")

        reset = _path_token.set(token)
        try:
            await self._app(scope, receive, send)
        finally:
            _path_token.reset(reset)


def _public_base_url(request: Request) -> str:
    """Best-effort external base URL, honouring the proxy Azure puts in front."""
    forwarded_proto = request.headers.get("x-forwarded-proto")
    forwarded_host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    if forwarded_host:
        scheme = forwarded_proto or request.url.scheme
        return f"{scheme}://{forwarded_host}"
    return str(request.base_url).rstrip("/")


def add_enrollment_routes(
    mcp: Any,
    registry: EnrollmentRegistry,
    *,
    mount_path: str = "/mcp",
    enroll_secret: str | None = None,
) -> None:
    """Attach ``/enroll`` and ``/revoke`` to the MCP app.

    ``enroll_secret`` gates enrollment behind a shared secret. Without it the
    endpoint is open, which on a public deployment lets anyone mint tokens
    against credentials they already hold — noisy rather than dangerous, but
    still worth closing off.
    """

    def _authorized(request: Request) -> bool:
        if not enroll_secret:
            return True
        return request.headers.get("x-enroll-secret") == enroll_secret

    @mcp.custom_route("/enroll", methods=["POST"])
    async def enroll(request: Request) -> JSONResponse:
        if not _authorized(request):
            return JSONResponse({"error": "Enrollment is not open."}, status_code=403)
        try:
            body = await request.json()
        except (ValueError, TypeError):
            return JSONResponse({"error": "Expected a JSON body."}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "Expected a JSON object."}, status_code=400)

        email = body.get("email")
        password = body.get("password")
        if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
            return JSONResponse(
                {"error": "Both 'email' and 'password' are required."}, status_code=400
            )

        ttl_raw = body.get("ttl_days", DEFAULT_TTL_DAYS)
        ttl_days: int | None
        if ttl_raw is None:
            ttl_days = None
        else:
            try:
                ttl_days = int(ttl_raw)
            except (TypeError, ValueError):
                return JSONResponse({"error": "'ttl_days' must be a number."}, status_code=400)
            if ttl_days <= 0:
                return JSONResponse({"error": "'ttl_days' must be positive."}, status_code=400)

        tz_raw = body.get("hours_from_gmt")
        hours_from_gmt: int | None = None
        if tz_raw is not None:
            try:
                hours_from_gmt = int(tz_raw)
            except (TypeError, ValueError):
                return JSONResponse(
                    {"error": "'hours_from_gmt' must be a whole number."}, status_code=400
                )
            if not -12 <= hours_from_gmt <= 14:
                return JSONResponse(
                    {"error": "'hours_from_gmt' must be between -12 and 14."}, status_code=400
                )

        try:
            token = registry.enroll(
                email,
                password,
                ttl_days=ttl_days,
                label=str(body.get("label") or ""),
                hours_from_gmt=hours_from_gmt,
            )
        except EnrollmentError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        base = _public_base_url(request)
        return JSONResponse(
            {
                "url": f"{base}/u/{token}{mount_path}",
                "expires_in_days": ttl_days,
                "note": (
                    "This URL is a credential and is shown only once. Store it "
                    "securely; POST /revoke to invalidate it."
                ),
            },
            status_code=201,
        )

    @mcp.custom_route("/revoke", methods=["POST"])
    async def revoke(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except (ValueError, TypeError):
            return JSONResponse({"error": "Expected a JSON body."}, status_code=400)
        token = body.get("token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            return JSONResponse({"error": "'token' is required."}, status_code=400)
        # Holding the token is the authorization to revoke it.
        return JSONResponse({"revoked": registry.revoke(token)})
