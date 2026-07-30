"""Open enrollment plus throttling, exercised through the real ASGI stack."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from loseit_mcp.cli import _add_health_route
from loseit_mcp.config import Settings
from loseit_mcp.enroll import add_enrollment_route
from loseit_mcp.sealed import UrlSealer
from loseit_mcp.server import build_server
from loseit_mcp.throttle import Limit, ThrottleMiddleware
from loseit_mcp.webapp import PathTokenMiddleware

SECRET = b"kJ8x2mQ7vN4pL9wR3tY6uZ1aS5dF0gH8cV7bN2mX"


ENROLL_TEST_LIMIT = Limit(3, 3600)
MCP_TEST_LIMIT = Limit(5, 60)
CREDENTIAL_TEST_LIMIT = Limit(1000, 60)


def _app(
    settings: Settings,
    *,
    enroll_secret: str | None = None,
    enroll_limit: Limit | None = None,
    mcp_limit: Limit | None = None,
    credential_limit: Limit | None = None,
) -> Any:
    sealer = UrlSealer(SECRET)
    mcp = build_server(settings, multi_tenant=True, sealer=sealer)
    _add_health_route(mcp)
    add_enrollment_route(mcp, sealer, mount_path="/mcp", enroll_secret=enroll_secret)
    app = PathTokenMiddleware(mcp.streamable_http_app(streamable_http_path="/mcp"))
    return ThrottleMiddleware(
        app,
        enroll_limit=enroll_limit or ENROLL_TEST_LIMIT,
        mcp_limit=mcp_limit or MCP_TEST_LIMIT,
        credential_limit=credential_limit or CREDENTIAL_TEST_LIMIT,
    )


def _enroll(client: Any, **kw: Any) -> Any:
    return client.post("/enroll", json={"email": "u@example.com", "password": "pw"}, **kw)


class TestOpenEnrollment:
    """With no secret configured, anyone may mint a URL — enrolling requires
    the account password anyway, so this exposes nothing."""

    @pytest.fixture
    def client(self, settings: Settings) -> Any:
        with TestClient(_app(settings)) as c:
            yield c

    def test_no_secret_needed(self, client: Any) -> None:
        assert _enroll(client).status_code == 201

    def test_a_stray_secret_header_is_ignored(self, client: Any) -> None:
        assert _enroll(client, headers={"X-Enroll-Secret": "anything"}).status_code == 201

    def test_the_url_works(self, client: Any) -> None:
        url = _enroll(client).json()["url"]
        sealed = url.split("/u/")[1].split("/")[0]
        assert UrlSealer(SECRET).open(sealed).email == "u@example.com"

    def test_enrolling_without_verification_reveals_nothing(
        self, client: Any
    ) -> None:
        """Without a verifier, sealing never contacts Lose It, so /enroll
        cannot be used to test whether a password is valid.

        The deployed configuration *does* verify (see ``test_enroll_site.py``),
        which trades this property for catching typos at enrollment time. That
        trade is what the per-email throttle pays for; this test pins the
        behaviour of the unverified mode rather than describing the deployment.
        """
        good = client.post("/enroll", json={"email": "real@example.com", "password": "pw"})
        junk = client.post("/enroll", json={"email": "fake@example.com", "password": "xx"})
        assert good.status_code == junk.status_code == 201


class TestRestrictedEnrollment:
    """An operator can still lock an instance down."""

    @pytest.fixture
    def client(self, settings: Settings) -> Any:
        with TestClient(_app(settings, enroll_secret="s3cret")) as c:
            yield c

    def test_refused_without_the_secret(self, client: Any) -> None:
        assert _enroll(client).status_code == 403

    def test_allowed_with_the_secret(self, client: Any) -> None:
        assert _enroll(client, headers={"X-Enroll-Secret": "s3cret"}).status_code == 201


class TestEnrollThrottling:
    @pytest.fixture
    def client(self, settings: Settings) -> Any:
        with TestClient(_app(settings, enroll_limit=Limit(3, 3600))) as c:
            yield c

    def test_burst_then_429(self, client: Any) -> None:
        codes = [_enroll(client).status_code for _ in range(5)]
        assert codes[:3] == [201, 201, 201]
        assert codes[3:] == [429, 429]

    def test_429_carries_retry_after(self, client: Any) -> None:
        for _ in range(4):
            response = _enroll(client)
        assert response.status_code == 429
        assert int(response.headers["retry-after"]) >= 1
        assert "retry_after_seconds" in response.json()

    def test_a_different_client_is_unaffected(self, client: Any) -> None:
        for _ in range(4):
            _enroll(client)
        # A distinct forwarded address gets its own budget.
        other = _enroll(client, headers={"X-Forwarded-For": "198.51.100.77"})
        assert other.status_code == 201

    def test_a_sealed_prefix_does_not_grant_a_fresh_budget(self, client: Any) -> None:
        """Regression: /u/<anything>/enroll is rewritten to /enroll before the
        handler runs, so it must be charged to the enrollment budget. Keying on
        the pre-rewrite path put it in the far larger tool budget instead, and
        because a fresh segment also minted a fresh credential bucket, the
        enrollment limit could be bypassed entirely."""
        junk = "Z" * 40
        for _ in range(3):
            _enroll(client)
        blocked = client.post(
            f"/u/{junk}/enroll", json={"email": "u@example.com", "password": "pw"}
        )
        assert blocked.status_code == 429

    def test_the_prefixed_route_really_does_reach_the_handler(self, client: Any) -> None:
        """Guards the test above: if the prefixed path 404'd, the assertion
        there would pass for the wrong reason."""
        response = client.post(
            f"/u/{'Z' * 40}/enroll", json={"email": "u@example.com", "password": "pw"}
        )
        assert response.status_code == 201
        assert "/u/" in response.json()["url"]

    def test_spoofing_the_header_does_not_grant_a_fresh_budget(
        self, settings: Settings
    ) -> None:
        """The leftmost hop is client-supplied; only the trusted rightmost one
        may pick the bucket."""
        with TestClient(_app(settings, enroll_limit=Limit(2, 3600))) as client:
            for i in range(2):
                assert (
                    client.post(
                        "/enroll",
                        json={"email": "u@example.com", "password": "pw"},
                        headers={"X-Forwarded-For": f"10.0.0.{i}, 203.0.113.5"},
                    ).status_code
                    == 201
                )
            blocked = client.post(
                "/enroll",
                json={"email": "u@example.com", "password": "pw"},
                headers={"X-Forwarded-For": "10.0.0.99, 203.0.113.5"},
            )
            assert blocked.status_code == 429


class TestCredentialThrottling:
    """The point of the credential budget: rotating addresses must not grant a
    fresh budget to the same user."""

    def test_rotating_addresses_still_hits_the_credential_limit(
        self, settings: Settings
    ) -> None:
        sealed = UrlSealer(SECRET).seal("u@example.com", "pw")
        app = _app(
            settings,
            mcp_limit=Limit(2, 60),          # small per-address budget
            credential_limit=Limit(5, 60),   # backstop across addresses
        )
        with TestClient(app) as client:
            codes = []
            for i in range(10):
                # Every request appears to come from a different address.
                codes.append(
                    client.get(
                        f"/u/{sealed}/mcp",
                        headers={"X-Forwarded-For": f"203.0.113.{i}"},
                    ).status_code
                )
            assert codes.count(429) >= 4, (
                "address rotation should stop being effective once the "
                f"credential budget is spent; got {codes}"
            )

    def test_distinct_credentials_have_distinct_budgets(self, settings: Settings) -> None:
        sealer = UrlSealer(SECRET)
        a = sealer.seal("alice@example.com", "pw")
        b = sealer.seal("bob@example.com", "pw")
        app = _app(settings, mcp_limit=Limit(100, 60), credential_limit=Limit(2, 60))
        with TestClient(app) as client:
            for _ in range(3):
                client.get(f"/u/{a}/mcp")
            # Alice is throttled; Bob is unaffected.
            assert client.get(f"/u/{a}/mcp").status_code == 429
            assert client.get(f"/u/{b}/mcp").status_code != 429


class TestMcpThrottling:
    def test_tool_traffic_is_limited_separately(self, settings: Settings) -> None:
        with TestClient(_app(settings, mcp_limit=Limit(2, 60))) as client:
            codes = [client.get("/mcp").status_code for _ in range(4)]
            assert 429 in codes
            # The enrollment budget is untouched by MCP traffic.
            assert _enroll(client).status_code == 201

    def test_health_checks_are_exempt(self, settings: Settings) -> None:
        """Azure probes /healthz continuously; throttling it would flap the
        instance."""
        with TestClient(_app(settings, mcp_limit=Limit(1, 3600))) as client:
            for _ in range(50):
                assert client.get("/healthz").status_code == 200
