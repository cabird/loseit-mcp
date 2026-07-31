"""Regressions from the fourth review.

The theme running through most of these is that a check is only as good as the
value it is applied to. The throttle limited the right thing by the wrong path;
the history tool bounded the wrong parameter; the service serialized lifecycle
transitions but not the requests they disrupt.
"""

from __future__ import annotations

import threading
import time
from datetime import date, timedelta
from typing import Any

import pytest

from loseit_mcp.paths import split_token_path
from loseit_mcp.service import MAX_HISTORY_SPAN_DAYS
from loseit_mcp.throttle import Limit, ThrottleMiddleware, client_key
from loseit_mcp.webapp import PathTokenMiddleware

TOKEN = "AAAABBBBCCCCDDDDEEEEFFFFGGGG1111"


def _scope(path: str, *, client: str = "203.0.113.7", **headers: str) -> dict[str, Any]:
    return {
        "type": "http",
        "path": path,
        "client": (client, 12345),
        "headers": [(k.replace("_", "-").encode(), v.encode()) for k, v in headers.items()],
    }


async def _ok_app(scope: dict, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 201, "headers": []})
    await send({"type": "http.response.body", "body": b""})


async def _status_of(app: Any, scope: dict) -> int:
    seen: dict[str, int] = {}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            seen["status"] = message["status"]

    await app(scope, None, send)
    return seen["status"]


class TestEnrollThrottleBypass:
    """The enrollment limit must survive a sealed-URL prefix.

    ``ThrottleMiddleware`` runs ahead of ``PathTokenMiddleware``, so it sees
    ``/u/<sealed>/enroll`` while the handler that eventually runs is the plain
    ``/enroll`` one. Classifying on the raw path put those requests in the
    120/min tool budget instead of the 5/hour enrollment budget — a 1440x
    bypass of a control the deployment docs advertise.
    """

    def _stack(self) -> ThrottleMiddleware:
        return ThrottleMiddleware(
            PathTokenMiddleware(_ok_app),
            enroll_limit=Limit(capacity=5, per_seconds=3600),
            mcp_limit=Limit(capacity=120, per_seconds=60),
        )

    @pytest.mark.anyio
    async def test_direct_enroll_is_limited(self) -> None:
        app = self._stack()
        results = [await _status_of(app, _scope("/enroll")) for _ in range(8)]
        assert results == [201, 201, 201, 201, 201, 429, 429, 429]

    @pytest.mark.anyio
    async def test_prefixed_enroll_is_limited_the_same_way(self) -> None:
        """The regression. A fresh sealed segment each time also dodges the
        per-credential bucket, so only the address bucket can catch this."""
        app = self._stack()
        results = [
            await _status_of(app, _scope(f"/u/{'A' * 28}{i:04d}/enroll")) for i in range(8)
        ]
        assert results == [201, 201, 201, 201, 201, 429, 429, 429]

    @pytest.mark.anyio
    async def test_prefixed_and_direct_enroll_share_one_budget(self) -> None:
        app = self._stack()
        for _ in range(5):
            assert await _status_of(app, _scope("/enroll")) == 201
        assert await _status_of(app, _scope(f"/u/{TOKEN}/enroll")) == 429

    @pytest.mark.anyio
    async def test_tool_traffic_keeps_the_larger_budget(self) -> None:
        """The fix must not overcorrect: /u/<sealed>/mcp is ordinary tool
        traffic and must not be charged to the tiny enrollment bucket."""
        app = self._stack()
        for _ in range(20):
            assert await _status_of(app, _scope(f"/u/{TOKEN}/mcp")) == 201

    @pytest.mark.anyio
    async def test_healthz_stays_exempt_behind_a_prefix(self) -> None:
        app = self._stack()
        for _ in range(50):
            assert await _status_of(app, _scope(f"/u/{TOKEN}/healthz")) == 201


class TestPathClassificationAgrees:
    """The throttle and the router must resolve a path identically.

    This is the invariant whose violation produced the bypass above, asserted
    directly so a future edit to either regex is caught here rather than in
    production.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "/enroll",
            "/mcp",
            "/healthz",
            f"/u/{TOKEN}/enroll",
            f"/u/{TOKEN}/mcp",
            f"/u/{TOKEN}/healthz",
            f"/u/{TOKEN}",
            "/u/short/enroll",
            "/u/" + "A" * 4096 + "/enroll",
        ],
    )
    @pytest.mark.anyio
    async def test_router_receives_the_path_the_throttle_classified(self, path: str) -> None:
        seen: dict[str, str] = {}

        async def record(scope: dict, receive: Any, send: Any) -> None:
            seen["path"] = scope["path"]
            await _ok_app(scope, receive, send)

        _, effective = split_token_path(path)
        await _status_of(PathTokenMiddleware(record), _scope(path))
        assert seen["path"] == effective

    def test_oversized_segment_is_not_treated_as_a_credential(self) -> None:
        """Too long to route, so it must not be mistaken for a sealed URL by
        the layer that decides policy either."""
        token, effective = split_token_path("/u/" + "A" * 4096 + "/enroll")
        assert token is None
        assert effective == "/u/" + "A" * 4096 + "/enroll"


class TestTrustedProxyCount:
    """``LOSEIT_TRUSTED_PROXIES=0`` crashed every request, /healthz included.

    ``hops[len(hops) - 0]`` is an IndexError. Because it also took down the
    health probe, App Service would have restarted the container in a loop.
    """

    def test_zero_proxies_ignores_a_forwarded_header(self) -> None:
        scope = _scope("/mcp", client="10.0.0.5", x_forwarded_for="1.2.3.4")
        assert client_key(scope, trusted_proxies=0) == "10.0.0.5"

    def test_zero_proxies_does_not_raise_on_many_hops(self) -> None:
        scope = _scope("/mcp", client="10.0.0.5", x_forwarded_for="1.2.3.4, 5.6.7.8, 9.9.9.9")
        assert client_key(scope, trusted_proxies=0) == "10.0.0.5"

    def test_more_proxies_than_hops_falls_back_to_the_leftmost(self) -> None:
        scope = _scope("/mcp", x_forwarded_for="1.2.3.4")
        assert client_key(scope, trusted_proxies=5) == "1.2.3.4"

    def test_one_proxy_still_reads_the_rightmost_hop(self) -> None:
        scope = _scope("/mcp", x_forwarded_for="1.2.3.4, 198.51.100.9")
        assert client_key(scope, trusted_proxies=1) == "198.51.100.9"


class TestWeightHistorySpanCap:
    """One tool call must not fan out to tens of thousands of upstream RPCs.

    ``days`` was capped at 365 by the schema, but explicit ``start``/``end``
    were unbounded. ``start=0001-01-01`` expands to ~60,868 sequential
    requests inside a single call, where the throttle never gets another say.
    """

    def _service(self) -> Any:
        from loseit_mcp.service import LoseItService

        svc = LoseItService.__new__(LoseItService)
        svc._settings = type("S", (), {"hours_from_gmt": 0})()
        svc._lock = threading.RLock()
        svc._client = None
        svc._inflight = 0
        svc._retired = []
        svc._generation = 0
        return svc

    def test_rejects_an_unbounded_start(self) -> None:
        svc = self._service()
        with pytest.raises(ValueError, match="maximum"):
            svc.get_weight_history(start="0001-01-01", end="9999-12-31")

    def test_rejects_a_span_one_day_over_the_cap(self) -> None:
        svc = self._service()
        end = date(2026, 7, 29)
        start = end - timedelta(days=MAX_HISTORY_SPAN_DAYS)
        with pytest.raises(ValueError, match="maximum"):
            svc.get_weight_history(start=start.isoformat(), end=end.isoformat())

    def test_rejects_a_reversed_range(self) -> None:
        svc = self._service()
        with pytest.raises(ValueError, match="after end"):
            svc.get_weight_history(start="2026-07-29", end="2026-01-01")

    def test_error_names_the_span_and_the_limit(self) -> None:
        svc = self._service()
        with pytest.raises(ValueError) as excinfo:
            svc.get_weight_history(start="1970-01-01", end="2026-07-29")
        message = str(excinfo.value)
        assert "1970-01-01" in message and "2026-07-29" in message
        assert f"{MAX_HISTORY_SPAN_DAYS:,}" in message

    def test_a_span_at_the_cap_is_accepted(self) -> None:
        """The boundary is inclusive, and the guard must not reject work the
        server is willing to do."""
        svc = self._service()
        end = date(2026, 7, 29)
        start = end - timedelta(days=MAX_HISTORY_SPAN_DAYS - 1)
        calls: list[tuple[date, date]] = []
        svc._client = type("C", (), {"http": None})()
        import loseit_mcp.service as service_module

        original = service_module._get_weight_history
        service_module._get_weight_history = lambda http, s, e: (calls.append((s, e)) or [])
        try:
            result = svc.get_weight_history(start=start.isoformat(), end=end.isoformat())
        finally:
            service_module._get_weight_history = original
        assert calls == [(start, end)]
        assert result["count"] == 0


class TestReauthDoesNotCloseInFlightClients:
    """A re-auth must not close a client another thread is mid-request on.

    The class docstring promised exactly this while ``_reauthenticate`` called
    ``close()`` unconditionally. Concurrent callers sharing a service — the
    normal case for one tenant with two tool calls in flight — could have their
    connection pool closed underneath them.
    """

    def _service(self) -> Any:
        from loseit_mcp.service import LoseItService

        svc = LoseItService.__new__(LoseItService)
        svc._settings = None
        svc._session = None
        svc._client = None
        svc._lock = threading.RLock()
        svc._inflight = 0
        svc._retired = []
        svc._generation = 0
        svc.on_reauthenticated = None
        return svc

    def test_retired_client_survives_until_the_request_finishes(self) -> None:
        svc = self._service()
        closed: list[str] = []
        old = type("C", (), {"close": lambda self: closed.append("old")})()
        svc._client = old

        with svc._in_flight():
            svc._retired.append(svc._client)
            svc._client = type("C", (), {"close": lambda self: closed.append("new")})()
            assert closed == [], "closed a client while a request was in flight"

        assert closed == ["old"], "retired client was never reclaimed"

    def test_concurrent_request_is_not_disturbed_by_a_reauth(self, monkeypatch: Any) -> None:
        """Drives the real ``_reauthenticate`` while a request is in flight."""
        import loseit_mcp.service as service_module

        svc = self._service()
        closed = threading.Event()

        class Client:
            def close(self) -> None:
                closed.set()

        svc._client = Client()
        monkeypatch.setattr(
            service_module, "resolve_session", lambda settings, force_login: object()
        )
        svc._build_client = lambda session: Client()

        started = threading.Event()
        released = threading.Event()

        def worker() -> None:
            with svc._in_flight():
                started.set()
                released.wait(timeout=5)

        thread = threading.Thread(target=worker)
        thread.start()
        assert started.wait(timeout=5)

        svc._reauthenticate()
        assert not closed.is_set(), "re-auth closed a client that a request was still using"

        released.set()
        thread.join(timeout=5)
        assert closed.is_set(), "superseded client was never closed after the request finished"

    def test_close_releases_retired_clients_too(self) -> None:
        svc = self._service()
        closed: list[str] = []
        svc._retired = [type("C", (), {"close": lambda self: closed.append("retired")})()]
        svc._client = type("C", (), {"close": lambda self: closed.append("current")})()
        svc.close()
        assert sorted(closed) == ["current", "retired"]

    def test_many_reauths_do_not_accumulate_clients(self) -> None:
        """Retirement must not become a leak: with nothing in flight, each
        superseded client is closed immediately."""
        svc = self._service()
        closed: list[int] = []
        for i in range(20):
            with svc._lock:
                if svc._client is not None:
                    svc._retired.append(svc._client)
                svc._client = type(
                    "C", (), {"close": lambda self, i=i: closed.append(i)}
                )()
                reclaimed = svc._reclaim_retired()
            for client in reclaimed:
                client.close()
        assert closed == list(range(19))
        assert svc._retired == []


class TestThrottleUnderConcurrency:
    """The previous concurrency test would have passed a limiter that admitted
    everything; this one asserts the limiter actually holds its capacity."""

    def test_capacity_is_never_exceeded_under_threads(self) -> None:
        from loseit_mcp.throttle import Throttle

        throttle = Throttle(Limit(capacity=50, per_seconds=3600))
        admitted: list[int] = []
        lock = threading.Lock()

        def hammer() -> None:
            local = 0
            for _ in range(40):
                if throttle.check("shared", now=time.monotonic()) is None:
                    local += 1
            with lock:
                admitted.append(local)

        threads = [threading.Thread(target=hammer) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert sum(admitted) == 50, f"expected exactly 50 admissions, got {sum(admitted)}"
