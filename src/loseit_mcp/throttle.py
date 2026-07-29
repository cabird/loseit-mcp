"""Per-client request throttling.

The server is a single small instance in front of a third-party API, so it has
two things worth protecting: its own CPU, and Lose It's login endpoint. Those
have very different costs per request —

- ``/enroll`` is a key derivation and one AES-GCM seal. Microseconds, no
  storage, no upstream call.
- ``/mcp`` can trigger a real Lose It login on a session-cache miss (~1s), so a
  client with a valid URL can turn request volume into upstream load.

so they get separate budgets.

Implemented as a token bucket per client: a burst is allowed up to ``capacity``,
then requests are admitted at the refill rate. Bucket state lives in memory,
which suits a single instance; scaling out would want a shared store, and the
:class:`Throttle` interface is small enough to swap.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send


@dataclass(frozen=True)
class Limit:
    """``capacity`` requests, refilling over ``per_seconds``."""

    capacity: int
    per_seconds: float

    @property
    def refill_rate(self) -> float:
        return self.capacity / self.per_seconds


# Enrollment is rare — a handful per person, ever — so a tight budget costs
# legitimate users nothing while making bulk abuse pointless.
ENROLL_LIMIT = Limit(capacity=5, per_seconds=3600)

# Tool calls are the common path and can be chatty during a conversation, but
# each cache miss costs an upstream login, so this is generous rather than open.
MCP_LIMIT = Limit(capacity=120, per_seconds=60)

# Cap tracked clients so the throttle itself can't be used to exhaust memory.
MAX_TRACKED_CLIENTS = 10_000


class _Bucket:
    __slots__ = ("tokens", "updated")

    def __init__(self, capacity: float, now: float):
        self.tokens = capacity
        self.updated = now


class Throttle:
    """Token-bucket limiter keyed by an arbitrary client identifier."""

    def __init__(self, limit: Limit, *, max_clients: int = MAX_TRACKED_CLIENTS):
        self._limit = limit
        self._max_clients = max_clients
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str, now: float | None = None) -> float | None:
        """Consume a token for ``key``.

        Returns ``None`` when the request is allowed, or the number of seconds
        until one token is available when it is not.
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                self._evict_locked(now)
                bucket = _Bucket(self._limit.capacity, now)
                self._buckets[key] = bucket
            else:
                elapsed = now - bucket.updated
                bucket.tokens = min(
                    self._limit.capacity, bucket.tokens + elapsed * self._limit.refill_rate
                )
                bucket.updated = now

            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return None
            return (1 - bucket.tokens) / self._limit.refill_rate

    def _evict_locked(self, now: float) -> None:
        """Drop full (idle) buckets first, then the least recently used."""
        if len(self._buckets) < self._max_clients:
            return
        for key, bucket in list(self._buckets.items()):
            refilled = bucket.tokens + (now - bucket.updated) * self._limit.refill_rate
            if refilled >= self._limit.capacity:
                del self._buckets[key]
        while len(self._buckets) >= self._max_clients:
            oldest = min(self._buckets, key=lambda k: self._buckets[k].updated)
            del self._buckets[oldest]

    def tracked(self) -> int:
        with self._lock:
            return len(self._buckets)


def client_key(scope: Scope, trusted_proxies: int = 1) -> str:
    """Identify the client behind a reverse proxy.

    ``X-Forwarded-For`` accumulates left to right, each hop appending the
    address it received the request from — so the **rightmost** entries are the
    ones added by infrastructure we control, and the leftmost is whatever the
    client claimed. Reading the leftmost would let anyone bypass throttling by
    sending a header, so we count back from the right by the number of proxies
    actually in front of us.
    """
    headers = dict(scope.get("headers") or [])
    forwarded = headers.get(b"x-forwarded-for", b"").decode("latin-1")
    if forwarded:
        hops = [h.strip() for h in forwarded.split(",") if h.strip()]
        if hops:
            index = max(0, len(hops) - trusted_proxies)
            candidate = _strip_port(hops[index])
            if candidate:
                return candidate

    client = scope.get("client")
    return client[0] if client else "unknown"


def _strip_port(value: str) -> str | None:
    """Normalise ``1.2.3.4:5678`` / ``[::1]:443`` to a bare address."""
    text = value.strip()
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            text = text[1:end]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        # Not parseable as an address; still usable as an opaque bucket key,
        # but bound its length so a hostile header can't bloat the store.
        return text[:64] or None


class ThrottleMiddleware:
    """Applies per-path throttles, answering 429 with ``Retry-After``.

    Pure ASGI so it can run ahead of routing and leave streaming responses
    alone.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        enroll_limit: Limit = ENROLL_LIMIT,
        mcp_limit: Limit = MCP_LIMIT,
        trusted_proxies: int = 1,
        exempt_paths: tuple[str, ...] = ("/healthz",),
    ):
        self._app = app
        self._enroll = Throttle(enroll_limit)
        self._mcp = Throttle(mcp_limit)
        self._trusted_proxies = trusted_proxies
        self._exempt = exempt_paths

    def _throttle_for(self, path: str) -> Throttle | None:
        if path in self._exempt:
            return None
        if path == "/enroll":
            return self._enroll
        return self._mcp

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        throttle = self._throttle_for(scope.get("path", ""))
        if throttle is None:
            await self._app(scope, receive, send)
            return

        retry_after = throttle.check(client_key(scope, self._trusted_proxies))
        if retry_after is None:
            await self._app(scope, receive, send)
            return

        await _send_429(send, retry_after)


async def _send_429(send: Send, retry_after: float) -> None:
    seconds = max(1, int(retry_after + 0.999))
    body = json.dumps(
        {
            "error": "Too many requests. Slow down and try again shortly.",
            "retry_after_seconds": seconds,
        }
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 429,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"retry-after", str(seconds).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def limit_from_env(name: str, default: Limit) -> Limit:
    """Read ``<NAME>`` as ``"<capacity>/<seconds>"``, e.g. ``"5/3600"``."""
    import os

    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        capacity, per = raw.split("/", 1)
        parsed = Limit(capacity=int(capacity), per_seconds=float(per))
    except (ValueError, TypeError):
        return default
    if parsed.capacity < 1 or parsed.per_seconds <= 0:
        return default
    return parsed


def describe(limit: Limit) -> str:
    return f"{limit.capacity} per {int(limit.per_seconds)}s"


__all__ = [
    "ENROLL_LIMIT",
    "MCP_LIMIT",
    "Limit",
    "Throttle",
    "ThrottleMiddleware",
    "client_key",
    "describe",
    "limit_from_env",
]
