"""Multi-tenant token cache for the hosted (HTTP) deployment.

In the hosted model each request carries the caller's Lose It! credentials, and
we hold the resulting ``liauth`` JWT so we don't re-authenticate on every call.

**The cache key must depend on the password, not just the email.** Keying on
email alone would let anyone who knows an address reuse the real user's cached
token by sending any password at all — a complete authentication bypass. So the
key is an HMAC over both, which means a wrong password simply misses the cache
and falls through to a real login (which then fails, as it should).

Passwords are never stored: only the HMAC and the resulting JWT are kept.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass

from .auth import Session, decode_jwt_payload

# Refresh a little before actual expiry so a token can't die mid-request.
DEFAULT_LEEWAY_SECONDS = 300

# Bound the cache so a hostile caller can't grow it without limit by sending
# endless distinct credentials.
DEFAULT_MAX_ENTRIES = 1000


@dataclass(frozen=True)
class CachedSession:
    session: Session
    expires_at: float

    def is_valid(self, leeway: int = DEFAULT_LEEWAY_SECONDS) -> bool:
        return time.time() < self.expires_at - leeway


def _load_or_create_secret() -> bytes:
    """Return the HMAC secret for cache keys.

    ``LOSEIT_CACHE_SECRET`` pins it across restarts and across instances (which
    matters if a shared cache backend is ever added). Otherwise we generate a
    random per-process secret, which is safe but means the cache is cold after
    every restart.
    """
    configured = os.environ.get("LOSEIT_CACHE_SECRET")
    if configured:
        return configured.encode("utf-8")
    return os.urandom(32)


def session_expiry(session: Session) -> float:
    """Absolute expiry for a session, from the JWT's ``exp`` claim.

    Falls back to one hour when the claim is unreadable — short enough to stay
    safe, long enough to avoid hammering the login endpoint.
    """
    claims = decode_jwt_payload(session.token) or {}
    exp = claims.get("exp")
    if isinstance(exp, int | float) and exp > 0:
        return float(exp)
    return time.time() + 3600


class TokenCache:
    """Thread-safe, size-bounded credential-to-session cache."""

    def __init__(
        self,
        *,
        secret: bytes | None = None,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        leeway_seconds: int = DEFAULT_LEEWAY_SECONDS,
    ) -> None:
        self._secret = secret or _load_or_create_secret()
        self._max_entries = max_entries
        self._leeway = leeway_seconds
        self._entries: dict[str, CachedSession] = {}
        self._lock = threading.Lock()

    def key_for(self, email: str, password: str) -> str:
        """Derive the cache key. Depends on BOTH email and password by design."""
        material = f"{email.strip().lower()}\0{password}".encode()
        return hmac.new(self._secret, material, hashlib.sha256).hexdigest()

    def get(self, email: str, password: str) -> Session | None:
        """Return a still-valid cached session, or ``None``."""
        key = self.key_for(email, password)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if not entry.is_valid(self._leeway):
                del self._entries[key]
                return None
            return entry.session

    def put(self, email: str, password: str, session: Session) -> None:
        key = self.key_for(email, password)
        entry = CachedSession(session=session, expires_at=session_expiry(session))
        with self._lock:
            self._evict_locked()
            self._entries[key] = entry

    def invalidate(self, email: str, password: str) -> None:
        """Drop an entry — used when the server rejects a cached token."""
        key = self.key_for(email, password)
        with self._lock:
            self._entries.pop(key, None)

    def _evict_locked(self) -> None:
        """Drop expired entries, then the soonest-to-expire if still over cap."""
        now = time.time()
        for key in [k for k, v in self._entries.items() if v.expires_at <= now]:
            del self._entries[key]
        while len(self._entries) >= self._max_entries:
            oldest = min(self._entries, key=lambda k: self._entries[k].expires_at)
            del self._entries[oldest]

    def stats(self) -> dict[str, int]:
        with self._lock:
            valid = sum(1 for v in self._entries.values() if v.is_valid(self._leeway))
            return {"entries": len(self._entries), "valid": valid}
