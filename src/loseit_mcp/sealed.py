"""Sealed enrollment URLs — credentials encrypted into the URL itself.

Some MCP clients can only be pointed at a URL and cannot attach auth headers.
Rather than keeping a server-side table of who owns which token, the URL *is*
the credential: it carries the account's details encrypted under a key derived
from a single server secret.

    https://host/u/<sealed>/mcp

That means no database, no file, and nothing to persist — the server can
decrypt a URL it has never seen before, so enrollments survive restarts and
redeploys for free. The only durable secret is ``LOSEIT_URL_SECRET``.

**Revocation is all-or-nothing.** Because there is no per-URL record, an
individual URL cannot be invalidated; rotating the secret invalidates every URL
at once. Sealed URLs therefore carry an expiry inside the encrypted payload
(tamper-proof by construction), so a leaked URL stops working on its own.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Bumped if the payload format ever changes, so old URLs fail cleanly rather
# than being misparsed.
_VERSION = b"\x01"
_KEY_INFO = b"loseit-mcp/sealed-url/v1"
_NONCE_BYTES = 12

DEFAULT_TTL_DAYS = 365

# The secret is the AES key material for every issued URL, and a single sealed
# URL is a self-verifying offline oracle — a guess costs one HMAC plus one
# GCM decrypt (~7µs measured). It must therefore be a random value.
#
# No length or character check can actually prove randomness, so rather than
# pretend otherwise this simply sets the bar above what anyone will type by
# hand: 43 characters is what `secrets.token_urlsafe(32)` produces, and
# `loseit-mcp gen-secret` generates one.
MIN_SECRET_LENGTH = 40
MIN_SECRET_DISTINCT_CHARS = 12

# Every failure mode answers with this one message, so the endpoint cannot be
# used to distinguish "wrong secret" from "expired" from "tampered". Rotation
# and expiry are by far the likeliest causes in practice, and the remedy is the
# same for all of them, so the message says what to do rather than what broke.
_INVALID_MESSAGE = (
    "This credential URL is no longer valid. The most likely reasons are that "
    "the server's URL secret was rotated or that the link expired.\n\n"
    "Tell the user their saved Lose It! URL has stopped working and they need a "
    "new one: run `loseit-mcp enroll <server-url>` and enter their Lose It! "
    "email and password, then replace the URL in their MCP client "
    "configuration. Nothing is wrong with their Lose It! account, and retrying "
    "the current URL will not help."
)


class SealError(RuntimeError):
    """A URL could not be sealed or opened."""


@dataclass(frozen=True)
class SealedCredentials:
    """What a sealed URL carries."""

    email: str
    password: str
    hours_from_gmt: int | None = None
    expires_at: float | None = None


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


_GENERATE_HINT = (
    'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
)


def _check_secret_strength(secret: bytes) -> None:
    """Reject secrets weak enough to brute-force offline.

    Length alone isn't enough: a typed passphrase can clear a length bar while
    carrying far less entropy than the 256-bit key it derives. The character
    variety check is a coarse proxy, but it reliably separates a random token
    from ``correcthorsebatterystaple``.
    """
    if len(secret) < MIN_SECRET_LENGTH:
        raise SealError(
            f"The URL secret must be at least {MIN_SECRET_LENGTH} characters. {_GENERATE_HINT}"
        )
    if len(set(secret)) < MIN_SECRET_DISTINCT_CHARS:
        raise SealError(
            "The URL secret looks like a passphrase rather than a random value. "
            "It is the key protecting every enrolled user's password and can be "
            f"attacked offline, so it must be random. {_GENERATE_HINT}"
        )


class UrlSealer:
    """Seals credentials into a URL segment and opens them again.

    Stateless: two processes sharing the same secret produce and accept the
    same URLs, so this also works unchanged if the app is ever scaled out.
    """

    def __init__(self, secret: bytes):
        _check_secret_strength(secret)
        # A fixed salt is correct here *given the strength check above*: the
        # secret is high-entropy, and a random salt would have to be stored
        # somewhere, which is the very thing this design avoids.
        self._key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=_KEY_INFO
        ).derive(secret)

    def seal(
        self,
        email: str,
        password: str,
        *,
        hours_from_gmt: int | None = None,
        ttl_days: int | None = DEFAULT_TTL_DAYS,
    ) -> str:
        """Return the URL segment encoding these credentials."""
        if not email or not password:
            raise SealError("Both email and password are required.")

        payload = {
            "e": email,
            "p": password,
            "tz": hours_from_gmt,
            "x": None if ttl_days is None else time.time() + ttl_days * 86400,
        }
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(self._key).encrypt(
            nonce, json.dumps(payload, separators=(",", ":")).encode("utf-8"), _VERSION
        )
        return _b64e(_VERSION + nonce + ciphertext)

    def open(self, sealed: str) -> SealedCredentials:
        """Decrypt a URL segment.

        Every failure — wrong secret, tampering, truncation, expiry — raises the
        same message, so the endpoint cannot be used as an oracle.
        """
        try:
            raw = _b64d(sealed)
            # Reject non-canonical encodings. Base64 discards the unused bits of
            # a final character, so several distinct strings can decode to the
            # same bytes; requiring the canonical form keeps one URL per
            # credential rather than a family of equivalent ones.
            if _b64e(raw) != sealed:
                raise ValueError("non-canonical encoding")
            if len(raw) < 1 + _NONCE_BYTES + 16 or raw[:1] != _VERSION:
                raise ValueError("bad envelope")
            nonce = raw[1 : 1 + _NONCE_BYTES]
            plaintext = AESGCM(self._key).decrypt(nonce, raw[1 + _NONCE_BYTES :], _VERSION)
            data = json.loads(plaintext)
            email, password = data["e"], data["p"]
            if not isinstance(email, str) or not isinstance(password, str):
                raise TypeError("bad payload")
        except Exception as exc:
            raise SealError(_INVALID_MESSAGE) from exc

        expires_at = data.get("x")
        if isinstance(expires_at, int | float) and time.time() >= expires_at:
            raise SealError(_INVALID_MESSAGE)

        tz = data.get("tz")
        return SealedCredentials(
            email=email,
            password=password,
            hours_from_gmt=tz if isinstance(tz, int) else None,
            expires_at=expires_at if isinstance(expires_at, int | float) else None,
        )
