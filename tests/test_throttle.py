"""Request throttling.

Two properties matter most: a client cannot raise its own budget by sending a
header, and the store cannot be grown without limit.
"""

from __future__ import annotations

import threading

import pytest

from loseit_mcp.throttle import (
    CREDENTIAL_LIMIT,
    ENROLL_LIMIT,
    MCP_LIMIT,
    Limit,
    Throttle,
    client_key,
    credential_key,
    describe,
    limit_from_env,
)


def _scope(path: str = "/mcp", *, client: str = "203.0.113.7", **headers: str) -> dict:
    return {
        "type": "http",
        "path": path,
        "client": (client, 12345),
        "headers": [(k.replace("_", "-").encode(), v.encode()) for k, v in headers.items()],
    }


class TestTokenBucket:
    def test_allows_a_burst_up_to_capacity(self) -> None:
        throttle = Throttle(Limit(capacity=3, per_seconds=60))
        assert [throttle.check("a", now=0) for _ in range(3)] == [None, None, None]

    def test_refuses_once_the_bucket_is_empty(self) -> None:
        throttle = Throttle(Limit(capacity=2, per_seconds=60))
        throttle.check("a", now=0)
        throttle.check("a", now=0)
        assert throttle.check("a", now=0) is not None

    def test_reports_when_to_retry(self) -> None:
        throttle = Throttle(Limit(capacity=1, per_seconds=60))
        throttle.check("a", now=0)
        wait = throttle.check("a", now=0)
        assert wait is not None
        assert 0 < wait <= 60

    def test_refills_over_time(self) -> None:
        throttle = Throttle(Limit(capacity=2, per_seconds=10))
        throttle.check("a", now=0)
        throttle.check("a", now=0)
        assert throttle.check("a", now=0) is not None
        # One token accrues every 5s at 2 per 10s.
        assert throttle.check("a", now=5) is None

    def test_does_not_refill_beyond_capacity(self) -> None:
        throttle = Throttle(Limit(capacity=2, per_seconds=10))
        throttle.check("a", now=0)
        # A long idle period must not bank extra tokens.
        assert throttle.check("a", now=10_000) is None
        assert throttle.check("a", now=10_000) is None
        assert throttle.check("a", now=10_000) is not None

    def test_clients_have_separate_budgets(self) -> None:
        throttle = Throttle(Limit(capacity=1, per_seconds=60))
        assert throttle.check("a", now=0) is None
        assert throttle.check("b", now=0) is None
        assert throttle.check("a", now=0) is not None


class TestMemoryBounds:
    def test_tracked_clients_stay_capped(self) -> None:
        """The throttle must not become its own memory-exhaustion vector."""
        throttle = Throttle(Limit(capacity=1, per_seconds=3600), max_clients=50)
        for i in range(5000):
            throttle.check(f"client-{i}", now=0)
        assert throttle.tracked() <= 50

    def test_idle_clients_are_reclaimed_first(self) -> None:
        throttle = Throttle(Limit(capacity=2, per_seconds=10), max_clients=10)
        throttle.check("busy", now=0)
        throttle.check("busy", now=0)
        for i in range(30):
            throttle.check(f"other-{i}", now=100)
        assert throttle.tracked() <= 10

    def test_is_thread_safe(self) -> None:
        throttle = Throttle(Limit(capacity=1000, per_seconds=60), max_clients=100)
        errors: list[BaseException] = []

        def hammer(n: int) -> None:
            try:
                for i in range(200):
                    throttle.check(f"c{(n * 200 + i) % 150}")
            except BaseException as exc:  # noqa: BLE001 - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert throttle.tracked() <= 100


class TestClientIdentification:
    def test_falls_back_to_the_socket_peer(self) -> None:
        assert client_key(_scope(client="198.51.100.4")) == "198.51.100.4"

    def test_uses_the_forwarded_address_behind_one_proxy(self) -> None:
        scope = _scope(x_forwarded_for="203.0.113.9")
        assert client_key(scope, trusted_proxies=1) == "203.0.113.9"

    def test_a_spoofed_header_cannot_change_the_bucket(self) -> None:
        """Reading the leftmost hop would let any client pick its own key, and
        so mint itself unlimited budget."""
        real = "203.0.113.9"
        spoofed = _scope(x_forwarded_for=f"1.2.3.4, {real}")
        assert client_key(spoofed, trusted_proxies=1) == real

    def test_many_spoofed_hops_still_resolve_to_the_trusted_one(self) -> None:
        real = "203.0.113.9"
        chain = ", ".join(["9.9.9.9"] * 20 + [real])
        assert client_key(_scope(x_forwarded_for=chain), trusted_proxies=1) == real

    def test_ports_are_stripped(self) -> None:
        assert client_key(_scope(x_forwarded_for="203.0.113.9:4321")) == "203.0.113.9"

    def test_ipv6_is_normalised(self) -> None:
        assert client_key(_scope(x_forwarded_for="[2001:db8::1]:443")) == "2001:db8::1"

    def test_unparseable_values_are_length_bounded(self) -> None:
        """A hostile header must not become an unbounded dictionary key."""
        assert len(client_key(_scope(x_forwarded_for="x" * 5000))) <= 64

    def test_empty_header_falls_through(self) -> None:
        assert client_key(_scope(x_forwarded_for="", client="198.51.100.4")) == "198.51.100.4"

    def test_missing_client_is_handled(self) -> None:
        assert client_key({"type": "http", "path": "/mcp", "headers": []}) == "unknown"


class TestCredentialIdentification:
    """An address is a weak identity — a rotating NAT pool defeats it. The
    credential a request carries does not rotate."""

    SEALED = "A" * 60

    def test_sealed_url_yields_a_key(self) -> None:
        key = credential_key(_scope(f"/u/{self.SEALED}/mcp"))
        assert key is not None
        assert key.startswith("u:")

    def test_the_same_url_always_yields_the_same_key(self) -> None:
        a = credential_key(_scope(f"/u/{self.SEALED}/mcp"))
        b = credential_key(_scope(f"/u/{self.SEALED}/mcp", client="203.0.113.99"))
        assert a == b, "the key must not depend on the address"

    def test_different_urls_yield_different_keys(self) -> None:
        assert credential_key(_scope(f"/u/{'A' * 60}/mcp")) != credential_key(
            _scope(f"/u/{'B' * 60}/mcp")
        )

    def test_the_credential_is_never_the_key(self) -> None:
        """Bucket keys must not carry anything sensitive."""
        key = credential_key(_scope(f"/u/{self.SEALED}/mcp"))
        assert self.SEALED not in key

    def test_authorization_header_yields_a_key(self) -> None:
        key = credential_key(_scope("/mcp", authorization="Basic dXNlcjpwdw=="))
        assert key is not None
        assert key.startswith("h:")
        assert "dXNlcjpwdw==" not in key

    def test_password_header_yields_a_key(self) -> None:
        key = credential_key(_scope("/mcp", x_loseit_password="hunter2"))
        assert key is not None
        assert "hunter2" not in key

    def test_header_and_url_keys_cannot_collide(self) -> None:
        url_key = credential_key(_scope(f"/u/{self.SEALED}/mcp"))
        header_key = credential_key(_scope("/mcp", authorization="Basic x"))
        assert url_key[:2] != header_key[:2]

    def test_unauthenticated_requests_have_no_key(self) -> None:
        assert credential_key(_scope("/mcp")) is None
        assert credential_key(_scope("/enroll")) is None

    def test_short_path_segments_are_not_treated_as_credentials(self) -> None:
        assert credential_key(_scope("/u/short/mcp")) is None


class TestConfiguredLimits:
    def test_enrollment_is_tighter_than_tool_calls(self) -> None:
        assert ENROLL_LIMIT.refill_rate < MCP_LIMIT.refill_rate

    def test_defaults_are_usable(self) -> None:
        # A conversation can easily make dozens of tool calls.
        assert MCP_LIMIT.capacity >= 60
        # Enrolling is a once-in-a-while action.
        assert ENROLL_LIMIT.capacity <= 10

    def test_credential_limit_is_a_backstop_not_a_ceiling(self) -> None:
        """It exists to catch address rotation, so a client on one address must
        hit the address limit first and never notice this one."""
        assert CREDENTIAL_LIMIT.refill_rate >= MCP_LIMIT.refill_rate

    def test_env_override_is_parsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_RATE", "7/120")
        parsed = limit_from_env("TEST_RATE", ENROLL_LIMIT)
        assert (parsed.capacity, parsed.per_seconds) == (7, 120.0)

    @pytest.mark.parametrize("bad", ["", "nonsense", "5", "0/60", "-1/60", "5/0", "a/b"])
    def test_bad_overrides_fall_back_to_the_default(
        self, monkeypatch: pytest.MonkeyPatch, bad: str
    ) -> None:
        monkeypatch.setenv("TEST_RATE", bad)
        assert limit_from_env("TEST_RATE", ENROLL_LIMIT) == ENROLL_LIMIT

    def test_describe_is_human_readable(self) -> None:
        assert describe(Limit(5, 3600)) == "5 per 3600s"
