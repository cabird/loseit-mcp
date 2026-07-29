"""Authentication against Lose It!.

The GWT-RPC endpoint at ``www.loseit.com/web/service`` authenticates with a
``liauth`` JWT sent as a cookie. The upstream ``lose_it`` SDK expects you to
supply that JWT yourself; this module obtains it programmatically by posting
your credentials to the mobile API's login endpoint:

``POST https://api.loseit.com/account/login`` with a form body of
``username`` / ``password`` / ``grant_type=password``. The response sets the
session cookies and returns the numeric ``user_id``.

Tokens are cached on disk (mode ``0600``) so we don't re-authenticate on every
start, and are refreshed automatically once the JWT's ``exp`` claim passes.
"""

from __future__ import annotations

import base64
import getpass
import json
import os
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .config import LOGIN_URL, ConfigError, Settings


class AuthError(RuntimeError):
    """Login failed or no usable credential is available."""


@dataclass(frozen=True)
class Session:
    """A resolved, usable Lose It! session."""

    token: str
    user_id: str
    user_name: str
    email: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "user_id": self.user_id,
            "user_name": self.user_name,
            "email": self.email,
            "cached_at": int(time.time()),
        }


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """Return a JWT's payload claims without verifying its signature."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def is_expired(token: str, *, leeway_seconds: int = 300) -> bool:
    """True if the token's ``exp`` claim has passed (or is about to).

    Tokens with no readable ``exp`` are treated as still valid; a failing RPC
    will trigger a re-login anyway.
    """
    payload = decode_jwt_payload(token)
    if not payload:
        return False
    exp = payload.get("exp")
    if not isinstance(exp, int | float):
        return False
    return exp - leeway_seconds <= time.time()


def _write_private(path: Path, text: str) -> None:
    """Write a file that only the current user can read.

    The file is created with mode 0600 *before* any content is written, so the
    token is never briefly visible under a permissive umask. Each write uses a
    unique temporary name so concurrent writers can't clobber each other's
    partial files.

    On Windows POSIX modes are not enforced, so we additionally reset the DACL
    to the current user only.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    if sys.platform == "win32":
        _restrict_windows_acl(tmp)

    os.replace(tmp, path)


def _restrict_windows_acl(path: Path) -> None:
    """Reset a file's ACL to the current user only (best effort).

    ``os.chmod`` does not change Windows ACLs, so a token file could otherwise
    inherit directory permissions that are wider than intended.
    """
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{getpass.getuser()}:F"],
            check=True,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        # Non-fatal: the file still exists and the caller may not be able to do
        # anything about a locked-down environment.
        pass


def load_cached_session(path: Path) -> Session | None:
    """Return a cached session, or ``None`` if absent/stale/unreadable."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    token = data.get("token")
    if not token or is_expired(token):
        return None
    return Session(
        token=token,
        user_id=str(data.get("user_id", "")),
        user_name=str(data.get("user_name", "")),
        email=data.get("email"),
    )


def save_session(session: Session, path: Path) -> None:
    _write_private(path, json.dumps(session.to_dict(), indent=2))


def login(email: str, password: str, *, timeout: float = 30.0) -> Session:
    """Exchange credentials for a ``liauth`` JWT.

    Raises :class:`AuthError` if the credentials are rejected or the response
    doesn't carry the expected cookie.
    """
    body = {"username": email, "password": password, "grant_type": "password"}
    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "accept": "application/json",
    }
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.post(LOGIN_URL, data=body, headers=headers)
    except httpx.HTTPError as exc:
        raise AuthError(f"Could not reach the Lose It! login endpoint: {exc}") from exc

    if resp.status_code in (400, 401, 403):
        raise AuthError(
            f"Lose It! rejected the credentials (HTTP {resp.status_code}). "
            "Check LOSEIT_EMAIL / LOSEIT_PASSWORD."
        )
    if resp.status_code != 200:
        raise AuthError(f"Login failed: HTTP {resp.status_code}: {resp.text[:300]}")

    token = resp.cookies.get("liauth") or resp.cookies.get("fn_auth")
    payload: dict[str, Any] = {}
    try:
        parsed = resp.json()
        if isinstance(parsed, dict):
            payload = parsed
    except ValueError:
        payload = {}

    # Some builds return the JWT in the body rather than as a cookie.
    if not token:
        for key in ("access_token", "token", "liauth", "jwt"):
            candidate = payload.get(key)
            if isinstance(candidate, str) and candidate:
                token = candidate
                break

    if not token:
        raise AuthError(
            "Login succeeded but no 'liauth' token was returned. "
            f"Cookies: {sorted(resp.cookies.keys())}; body keys: {sorted(payload)}"
        )

    claims = decode_jwt_payload(token) or {}
    user_id = str(payload.get("user_id") or claims.get("sub") or "")
    account_email = payload.get("username") or payload.get("email") or email
    user_name = str(
        payload.get("first_name")
        or payload.get("firstName")
        or claims.get("name")
        or _name_from_email(str(account_email))
    )

    return Session(
        token=token,
        user_id=user_id,
        user_name=user_name,
        email=str(account_email),
    )


def _name_from_email(email: str) -> str:
    """Fallback display name derived from an email local-part."""
    local = email.split("@")[0] or "User"
    return local[:1].upper() + local[1:]


def resolve_session(settings: Settings, *, force_login: bool = False) -> Session:
    """Return a usable session, logging in only when necessary.

    Resolution order:

    1. An explicitly supplied ``token`` (``--token`` / ``LOSEIT_TOKEN``), unless
       it has expired and we hold credentials that can mint a fresh one.
    2. A cached session on disk that hasn't expired **and belongs to the
       configured account**.
    3. A fresh login with ``email`` + ``password``.
    """
    settings.require_credentials()
    can_login = bool(settings.email and settings.password)

    # Only fall through to a login when we can actually perform one; otherwise
    # an expired token is still the caller's best option and the resulting API
    # error is clearer than a config error raised here.
    if settings.token and not force_login and not (is_expired(settings.token) and can_login):
        claims = decode_jwt_payload(settings.token) or {}
        return Session(
            token=settings.token,
            user_id=settings.user_id or str(claims.get("sub") or ""),
            user_name=settings.user_name or _name_from_email(settings.email or "user"),
            email=settings.email,
        )

    if not force_login:
        cached = load_cached_session(settings.session_file) if settings.persist_session else None
        if cached and _matches_configured_account(cached, settings):
            return _apply_overrides(cached, settings)

    if not can_login:
        raise ConfigError(
            "A fresh login is required but no email/password is configured."
        )

    session = login(settings.email, settings.password)  # type: ignore[arg-type]
    session = _apply_overrides(session, settings)
    if settings.persist_session:
        save_session(session, settings.session_file)
    return session


def _apply_overrides(session: Session, settings: Settings) -> Session:
    """Let explicit config win over whatever login/cache produced."""
    return Session(
        token=session.token,
        user_id=settings.user_id or session.user_id,
        user_name=settings.user_name or session.user_name,
        email=session.email or settings.email,
    )


def _matches_configured_account(session: Session, settings: Settings) -> bool:
    """True if a cached session belongs to the account we're configured for.

    Without this check, changing ``LOSEIT_EMAIL`` would silently keep using the
    previous account's cached token — so reads and, worse, writes would land on
    the wrong diary.
    """
    if not settings.email:
        return True
    if not session.email:
        return False
    return session.email.strip().lower() == settings.email.strip().lower()
