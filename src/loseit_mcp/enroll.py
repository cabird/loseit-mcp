"""Self-service enrollment: the page people visit, and the endpoint behind it.

Enrollment turns an email and password into a sealed URL that acts as the
caller's whole credential. Two things make that safe enough to leave open:

- Sealing grants no access the caller didn't already have. A URL minted from a
  password someone doesn't own is useless, because every request it carries
  still has to log into Lose It!
- Credentials are checked here before a URL is issued, so nobody walks away
  with a link that fails on first use. That does make this endpoint report
  whether a password is valid, which is why attempts are throttled per email
  address as well as per client address — see :func:`add_enrollment_route`.

The HTML lives in :mod:`loseit_mcp.enrollpage`; this module is the wiring.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from collections.abc import Callable
from typing import Any

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import enrollpage
from .auth import InvalidCredentialsError, UpstreamUnavailableError, login
from .enrollpage import CONTENT_SECURITY_POLICY
from .sealed import DEFAULT_TTL_DAYS, SealError, UrlSealer
from .throttle import Limit, Throttle

logger = logging.getLogger(__name__)

# Bound what can be sealed, so a mintable URL is always a routable one.
MAX_EMAIL_LENGTH = 256
MAX_PASSWORD_LENGTH = 512
MAX_TTL_DAYS = 3650

# Generous for a JSON object holding two short strings, and small enough that a
# hostile body is refused rather than buffered.
MAX_BODY_BYTES = 64 * 1024

# Sign-in attempts per email address. Deliberately tight: this is the control
# that keeps credential verification from being useful for guessing passwords.
VERIFY_LIMIT = Limit(capacity=8, per_seconds=900)


def verify_credentials(email: str, password: str) -> None:
    """Confirm Lose It! accepts these credentials, then discard them.

    Raises :class:`InvalidCredentialsError` if they are rejected, or
    :class:`UpstreamUnavailableError` if Lose It! could not be asked.

    The session this produces is deliberately thrown away rather than cached.
    Caching it would key a live token on credentials supplied by an
    unauthenticated caller, which is a far larger commitment than answering
    "yes, that login works" — and the first real tool call will mint one
    anyway.
    """
    login(email, password)


def add_enrollment_route(
    mcp: Any,
    sealer: UrlSealer,
    *,
    mount_path: str = "/mcp",
    enroll_secret: str | None = None,
    verify: Callable[[str, str], None] | None = None,
    verify_limit: Limit | None = None,
    serve_page: bool = False,
) -> None:
    """Attach ``POST /enroll``, and optionally the enrollment page at ``/``.

    ``enroll_secret`` gates the endpoint. Leaving it unset opens enrollment to
    anyone, which is safe for the reason given in the module docstring.

    ``verify`` is called with the credentials before sealing and should raise
    :class:`InvalidCredentialsError` if Lose It! rejects them. It is injected
    rather than called directly so tests can exercise this route without
    touching the network.

    Verifying means this endpoint reports whether a password is valid, so
    ``verify_limit`` throttles attempts *per email address*. The address
    throttle in front cannot do that job: a targeted attacker rotates source
    addresses far more easily than the one account they care about. With both
    in place, guessing here is slower than guessing against Lose It's own login
    form, so this adds no capability an attacker did not already have.
    """
    verify_throttle = Throttle(verify_limit or VERIFY_LIMIT) if verify is not None else None

    if serve_page:

        @mcp.custom_route("/", methods=["GET"])
        async def enrollment_page(request: Request) -> Response:
            nonce = secrets.token_urlsafe(16)
            return Response(
                enrollpage.render(nonce),
                media_type="text/html; charset=utf-8",
                headers={
                    "content-security-policy": CONTENT_SECURITY_POLICY.format(nonce=nonce),
                    "referrer-policy": "no-referrer",
                    "x-content-type-options": "nosniff",
                    # The page is per-request only because of the nonce; a
                    # cached copy would pair a stale nonce with a fresh policy
                    # and silently break every script on the page.
                    "cache-control": "no-store",
                },
            )

    @mcp.custom_route("/enroll", methods=["POST"])
    async def enroll(request: Request) -> JSONResponse:
        if enroll_secret and not _secret_matches(
            request.headers.get("x-enroll-secret"), enroll_secret
        ):
            return JSONResponse({"error": "Enrollment is not open."}, status_code=403)

        body_bytes = await _read_bounded_body(request)
        if body_bytes is None:
            return JSONResponse(
                {"error": f"Request body must be under {MAX_BODY_BYTES // 1024} KB."},
                status_code=413,
            )

        try:
            body = json.loads(body_bytes)
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

        if verify is not None:
            if verify_throttle is not None:
                retry_after = verify_throttle.check(_email_key(email))
                if retry_after is not None:
                    seconds = max(1, int(retry_after + 0.999))
                    return JSONResponse(
                        {
                            "error": (
                                "Too many sign-in attempts for that email address. "
                                "Wait a few minutes and try again."
                            ),
                            "retry_after_seconds": seconds,
                        },
                        status_code=429,
                        headers={"retry-after": str(seconds)},
                    )
            try:
                # Blocking HTTP call, so it goes off the event loop: one slow
                # login must not stall every other request in the process.
                await anyio.to_thread.run_sync(verify, email, password)
            except InvalidCredentialsError:
                return JSONResponse(
                    {
                        "error": (
                            "Lose It! didn't accept that email and password. "
                            "Check them and try again."
                        )
                    },
                    status_code=401,
                )
            except UpstreamUnavailableError:
                # Deliberately not 401: nothing was learned about the
                # credentials here, and telling someone their password is wrong
                # when Lose It is merely down sends them to reset a good one.
                logger.warning("Enrollment verification failed: Lose It! unreachable")
                return JSONResponse(
                    {
                        "error": (
                            "Couldn't reach Lose It! to check your login. That's a "
                            "problem on our side or theirs, not with your password. "
                            "Please try again shortly."
                        )
                    },
                    status_code=502,
                )

        try:
            sealed = sealer.seal(email, password, hours_from_gmt=hours_from_gmt, ttl_days=ttl_days)
        except SealError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        return JSONResponse(
            {
                "url": f"{_public_base_url(request)}/u/{sealed}{mount_path}",
                "expires_in_days": ttl_days,
                "verified": verify is not None,
                "note": (
                    "This URL is a credential. It cannot be revoked individually "
                    "— rotate LOSEIT_URL_SECRET to invalidate all issued URLs."
                ),
            },
            status_code=201,
        )


def _secret_matches(supplied: str | None, expected: str) -> bool:
    """Constant-time comparison that tolerates any input.

    ``hmac.compare_digest`` raises on non-ASCII ``str``, so a header with an
    accented character would otherwise 500 instead of being refused.
    """
    try:
        return hmac.compare_digest(supplied or "", expected)
    except TypeError:
        return False


def _email_key(email: str) -> str:
    """Throttle bucket for an email address.

    Case- and whitespace-insensitive, so trivial variations of one address
    don't each get their own budget, and hashed so the bucket store never
    holds addresses.
    """
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:32]


async def _read_bounded_body(request: Request) -> bytes | None:
    """Read the request body, or ``None`` if it exceeds :data:`MAX_BODY_BYTES`.

    Streamed rather than taken from ``request.body()`` so an oversized upload
    is abandoned partway instead of being buffered in full first.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


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
