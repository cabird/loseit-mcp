"""Client-side helper for obtaining a credential URL from a hosted server.

Kept separate from the serving code because it is the one place the CLI acts as
a *client* of a deployment rather than as the deployment itself.

Secrets are read from the environment or prompted for interactively. They are
deliberately not accepted as command-line arguments: argv is visible in shell
history and in process listings on a shared machine.
"""

from __future__ import annotations

import getpass
import json
import os
import sys
from typing import Any
from urllib.parse import urlparse

import httpx


class EnrollClientError(RuntimeError):
    """Enrollment could not be completed."""


def _prompt(label: str, *, secret: bool) -> str:
    if not sys.stdin.isatty():
        raise EnrollClientError(
            f"{label} is required. Set it in the environment, or run this "
            "interactively so it can be prompted for."
        )
    value = (getpass.getpass(f"{label}: ") if secret else input(f"{label}: ")).strip()
    if not value:
        raise EnrollClientError(f"{label} cannot be empty.")
    return value


def _detect_offset() -> int:
    from datetime import datetime

    offset = datetime.now().astimezone().utcoffset()
    return 0 if offset is None else round(offset.total_seconds() / 3600)


def enroll(
    server: str,
    *,
    email: str | None = None,
    ttl_days: int | None = None,
    tz_offset: int | None = None,
    allow_insecure: bool = False,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Request a credential URL and return the server's response.

    ``email`` is prompted for if omitted. The password comes from
    ``LOSEIT_PASSWORD`` or a hidden prompt; the enrollment secret from
    ``LOSEIT_ENROLL_SECRET`` or a hidden prompt.
    """
    base = server.rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme not in ("http", "https"):
        raise EnrollClientError(f"Server must be an http(s) URL, got {server!r}.")
    if parsed.scheme == "http" and not allow_insecure:
        raise EnrollClientError(
            "Refusing to send credentials over plain http. Use https, or pass "
            "--insecure if this is a local test server."
        )

    email = email or os.environ.get("LOSEIT_EMAIL") or _prompt("Lose It! email", secret=False)
    password = os.environ.get("LOSEIT_PASSWORD") or _prompt("Lose It! password", secret=True)
    enroll_secret = os.environ.get("LOSEIT_ENROLL_SECRET") or _prompt(
        "Server enrollment secret", secret=True
    )

    payload: dict[str, Any] = {
        "email": email,
        "password": password,
        "hours_from_gmt": _detect_offset() if tz_offset is None else tz_offset,
    }
    if ttl_days is not None:
        payload["ttl_days"] = ttl_days

    try:
        response = httpx.post(
            f"{base}/enroll",
            json=payload,
            headers={"x-enroll-secret": enroll_secret},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise EnrollClientError(f"Could not reach {base}: {exc}") from exc

    if response.status_code == 403:
        raise EnrollClientError(
            "The server rejected the enrollment secret. Check "
            "LOSEIT_ENROLL_SECRET matches the server's setting."
        )
    if response.status_code == 404:
        raise EnrollClientError(
            f"{base}/enroll was not found. The server may not have credential "
            "URLs enabled (LOSEIT_ENROLLMENT=1)."
        )
    if response.status_code != 201:
        detail = _error_detail(response)
        raise EnrollClientError(f"Enrollment failed (HTTP {response.status_code}): {detail}")

    try:
        body = response.json()
    except json.JSONDecodeError as exc:
        raise EnrollClientError("The server returned a response that wasn't JSON.") from exc
    if not isinstance(body, dict) or "url" not in body:
        raise EnrollClientError("The server's response did not contain a URL.")
    return body


def _error_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except json.JSONDecodeError:
        return response.text[:200]
    return str(body.get("error", body)) if isinstance(body, dict) else str(body)
