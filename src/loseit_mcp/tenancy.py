"""Multi-tenant credential resolution for the hosted HTTP deployment.

Local stdio use has one account, configured from the environment. A hosted
server has many, so credentials arrive per request and the resulting sessions
are cached (see :mod:`loseit_mcp.tokencache`).

Credentials are read from either:

- ``Authorization: Basic base64(email:password)``, or
- ``X-LoseIt-Email`` / ``X-LoseIt-Password`` headers.

Always terminate TLS in front of this service; the credentials are only as
protected as the transport carrying them.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, replace
from typing import Any

from .auth import AuthError, login
from .config import Settings
from .service import LoseItService
from .tokencache import TokenCache

EMAIL_HEADER = "x-loseit-email"
PASSWORD_HEADER = "x-loseit-password"
TZ_OFFSET_HEADER = "x-loseit-hours-from-gmt"


class CredentialsError(RuntimeError):
    """No usable credentials were supplied with the request."""


@dataclass(frozen=True)
class Credentials:
    email: str
    password: str
    # Whole-hour UTC offset for the caller. A container runs in UTC, so without
    # this every user's "today" would be the container's, which can log food to
    # the wrong day near midnight.
    hours_from_gmt: int | None = None


def _decode_basic(value: str) -> Credentials | None:
    if not value.lower().startswith("basic "):
        return None
    encoded = value[6:].strip()
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    email, sep, password = decoded.partition(":")
    if not sep or not email or not password:
        return None
    return Credentials(email=email, password=password)


def credentials_from_headers(headers: Any) -> Credentials:
    """Extract credentials from a request's headers.

    Accepts any mapping-like header bag with case-insensitive lookup, which is
    what both Starlette and the MCP ``Context`` provide.
    """

    def get(name: str) -> str | None:
        try:
            value = headers.get(name)
        except AttributeError:
            return None
        return value if isinstance(value, str) and value else None

    raw_offset = get(TZ_OFFSET_HEADER)
    offset: int | None = None
    if raw_offset is not None:
        try:
            parsed = int(raw_offset)
        except ValueError as exc:
            raise CredentialsError(
                f"'{TZ_OFFSET_HEADER}' must be a whole number of hours, got {raw_offset!r}."
            ) from exc
        if not -12 <= parsed <= 14:
            raise CredentialsError(
                f"'{TZ_OFFSET_HEADER}' must be between -12 and 14, got {parsed}."
            )
        offset = parsed

    authorization = get("authorization")
    if authorization:
        creds = _decode_basic(authorization)
        if creds is not None:
            return replace(creds, hours_from_gmt=offset)

    email = get(EMAIL_HEADER)
    password = get(PASSWORD_HEADER)
    if email and password:
        return Credentials(email=email.strip(), password=password, hours_from_gmt=offset)

    raise CredentialsError(
        "No Lose It! credentials on the request. Send either "
        "'Authorization: Basic <base64 email:password>' or the "
        f"'{EMAIL_HEADER}' and '{PASSWORD_HEADER}' headers."
    )


class SessionResolver:
    """Turns per-request credentials into a ready :class:`LoseItService`.

    Sessions are cached so a burst of tool calls from one client costs a single
    login. Each call still gets its own :class:`LoseItService` (and therefore
    its own HTTP client), so concurrent requests never share mutable state.
    """

    def __init__(self, base_settings: Settings, cache: TokenCache | None = None) -> None:
        self._base = base_settings
        self._cache = cache or TokenCache()

    @property
    def cache(self) -> TokenCache:
        return self._cache

    def resolve(self, creds: Credentials) -> LoseItService:
        session = self._cache.get(creds.email, creds.password)
        if session is None:
            session = login(creds.email, creds.password)
            self._cache.put(creds.email, creds.password, session)

        settings = self._base.with_overrides(
            email=creds.email,
            password=creds.password,
            token=session.token,
            user_id=session.user_id,
            user_name=session.user_name,
            hours_from_gmt=creds.hours_from_gmt,
        )
        return LoseItService(settings)

    def invalidate(self, creds: Credentials) -> None:
        self._cache.invalidate(creds.email, creds.password)


def resolve_or_raise(resolver: SessionResolver, headers: Any) -> tuple[LoseItService, Credentials]:
    """Resolve a service for a request, mapping auth failures to clear errors."""
    creds = credentials_from_headers(headers)
    try:
        return resolver.resolve(creds), creds
    except AuthError as exc:
        raise CredentialsError(f"Lose It! rejected those credentials: {exc}") from exc
