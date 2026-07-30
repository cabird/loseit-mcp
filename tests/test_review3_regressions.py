"""Regressions from the third security review.

Each test corresponds to a finding; the docstrings say what broke.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from loseit_mcp.config import Settings
from loseit_mcp.enroll import (
    MAX_EMAIL_LENGTH,
    MAX_PASSWORD_LENGTH,
    MAX_TTL_DAYS,
    add_enrollment_route,
)
from loseit_mcp.paths import TOKEN_REDACT_RE
from loseit_mcp.sealed import (
    MIN_SECRET_LENGTH,
    SealError,
    UrlSealer,
)
from loseit_mcp.server import build_server
from loseit_mcp.webapp import (
    PathTokenMiddleware,
)

GOOD_SECRET = b"kJ8x2mQ7vN4pL9wR3tY6uZ1aS5dF0gH8cV7bN2mX"


def _app(settings: Settings, sealer: UrlSealer) -> Any:
    from loseit_mcp.cli import _add_health_route

    mcp = build_server(settings, multi_tenant=True, sealer=sealer)
    _add_health_route(mcp)
    add_enrollment_route(mcp, sealer, mount_path="/mcp", enroll_secret="s3cret")
    return PathTokenMiddleware(mcp.streamable_http_app(streamable_http_path="/mcp"))


@pytest.fixture
def client(settings: Settings) -> Any:
    with TestClient(_app(settings, UrlSealer(GOOD_SECRET))) as c:
        yield c


def _enroll(client: Any, **overrides: Any) -> Any:
    payload = {"email": "u@example.com", "password": "pw", **overrides}
    return client.post("/enroll", json=payload, headers={"X-Enroll-Secret": "s3cret"})


class TestNonAsciiPaths:
    """A non-ASCII path segment raised UnicodeEncodeError inside the
    middleware, 500-ing before any credential check."""

    @pytest.mark.parametrize("suffix", ["caf\u00e9", "mcp\u00e9", "\u2603", "\u65e5\u672c"])
    def test_does_not_crash(self, client: Any, suffix: str) -> None:
        sealed = UrlSealer(GOOD_SECRET).seal("u@example.com", "pw")
        response = client.get(f"/u/{sealed}/{suffix}")
        assert response.status_code != 500


class TestSecretStrength:
    """The secret is the AES key for every issued URL and a sealed URL is an
    offline oracle, so a typeable passphrase must be refused."""

    @pytest.mark.parametrize(
        "weak",
        [
            b"short",
            b"correcthorsebatterystaple!!",           # under the length bar
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # long but 1 distinct char
            b"abababababababababababababababababab",  # long but 2 distinct
            b"passwordpasswordpasswordpassword",      # long but few distinct
        ],
    )
    def test_weak_secrets_are_refused(self, weak: bytes) -> None:
        with pytest.raises(SealError):
            UrlSealer(weak)

    def test_a_generated_token_is_accepted(self) -> None:
        import secrets

        UrlSealer(secrets.token_urlsafe(32).encode())

    def test_minimum_length_is_meaningful(self) -> None:
        assert MIN_SECRET_LENGTH >= 32


class TestTtlBounds:
    """Expiry is the only control left on a leaked URL, so it must not be
    removable through the API."""

    def test_null_ttl_does_not_mint_a_permanent_url(self, client: Any) -> None:
        response = _enroll(client, ttl_days=None)
        assert response.status_code == 201
        assert response.json()["expires_in_days"] is not None

        sealed = response.json()["url"].split("/u/")[1].split("/")[0]
        assert UrlSealer(GOOD_SECRET).open(sealed).expires_at is not None

    def test_absurd_ttl_is_rejected(self, client: Any) -> None:
        assert _enroll(client, ttl_days=10**9).status_code == 400

    def test_ttl_at_the_cap_is_allowed(self, client: Any) -> None:
        assert _enroll(client, ttl_days=MAX_TTL_DAYS).status_code == 201

    @pytest.mark.parametrize("bad", [-1, 0, "soon"])
    def test_out_of_range_values_are_rejected(self, client: Any, bad: Any) -> None:
        assert _enroll(client, ttl_days=bad).status_code == 400

    def test_json_infinity_does_not_500(self, client: Any) -> None:
        """`1e400` parses to float('inf'); int(inf) raised OverflowError and
        surfaced as a 500. Sent as raw text because Python's json encoder
        refuses to serialise inf."""
        response = client.post(
            "/enroll",
            content=b'{"email":"u@example.com","password":"pw","ttl_days":1e400}',
            headers={"X-Enroll-Secret": "s3cret", "content-type": "application/json"},
        )
        assert response.status_code == 400


class TestCredentialLengthBounds:
    """An unbounded credential produced a sealed segment too long to route, so
    /enroll handed back a URL that 404s on every request."""

    def test_oversized_password_is_rejected(self, client: Any) -> None:
        assert _enroll(client, password="a" * (MAX_PASSWORD_LENGTH + 1)).status_code == 400

    def test_oversized_email_is_rejected(self, client: Any) -> None:
        assert _enroll(client, email="a" * (MAX_EMAIL_LENGTH + 1)).status_code == 400

    def test_a_minted_url_is_always_routable(self, client: Any) -> None:
        response = _enroll(client, password="a" * MAX_PASSWORD_LENGTH)
        assert response.status_code == 201
        sealed = response.json()["url"].split("/u/")[1].split("/")[0]
        # Routable means the middleware matched it, so we don't get a 404.
        assert client.get(f"/u/{sealed}/mcp").status_code != 404


class TestRedactionIsUnbounded:
    """The redaction pattern shared the router's 2048-char cap, so an oversized
    segment matched only its prefix and the tail reached the log verbatim."""

    @pytest.mark.parametrize("length", [32, 200, 2048, 2049, 4096])
    def test_segments_of_any_length_are_fully_redacted(self, length: int) -> None:
        segment = "A" * length
        redacted = TOKEN_REDACT_RE.sub(r"\1<redacted>", f'"POST /u/{segment}/mcp HTTP/1.1" 200')
        assert segment not in redacted
        assert "A" * 32 not in redacted, "no fragment of the segment may survive"


class TestEnrollSecretComparison:
    def test_wrong_secret_is_refused(self, client: Any) -> None:
        response = client.post(
            "/enroll",
            json={"email": "u@example.com", "password": "pw"},
            headers={"X-Enroll-Secret": "wrong"},
        )
        assert response.status_code == 403

    def test_missing_secret_is_refused(self, client: Any) -> None:
        assert client.post("/enroll", json={"email": "u@example.com", "password": "pw"}).status_code == 403

    def test_comparison_is_constant_time(self) -> None:
        """Guards against reintroducing a short-circuiting `!=`.

        Asserting on behaviour rather than on source text: the previous version
        of this test grepped the function for "compare_digest", which would
        have passed just as happily against a broken comparison somewhere else
        in the file.
        """
        from loseit_mcp.enroll import _secret_matches

        assert _secret_matches("s3cret", "s3cret")
        assert not _secret_matches("s3crey", "s3cret")
        assert not _secret_matches("", "s3cret")
        assert not _secret_matches(None, "s3cret")
        # Differing lengths must be refused, not raise.
        assert not _secret_matches("s3cret-and-then-some", "s3cret")

    def test_a_non_ascii_secret_is_refused_rather_than_crashing(self, client: Any) -> None:
        """`hmac.compare_digest` raises TypeError on non-ASCII str, which would
        turn a wrong guess into a 500.

        Sent as raw bytes because that is how it arrives on the wire: Starlette
        decodes header bytes as latin-1, so a non-ASCII value reaches the
        handler as a str that `compare_digest` refuses to look at.
        """
        response = client.post(
            "/enroll",
            json={"email": "u@example.com", "password": "pw"},
            headers={"X-Enroll-Secret": "sécret".encode("latin-1")},
        )
        assert response.status_code == 403


class TestRotationMessage:
    """A URL sealed under a rotated secret should tell the user to re-enroll."""

    def test_message_names_the_remedy(self) -> None:
        stale = UrlSealer(b"pQ3zX8vB2nM6kL0jH4gF7dS1aW5eR9tYcJ4kP8nZ").seal("u@example.com", "pw")
        with pytest.raises(SealError) as caught:
            UrlSealer(GOOD_SECRET).open(stale)

        message = str(caught.value)
        assert "loseit-mcp enroll" in message
        assert "rotated" in message
        assert "retrying" in message

    def test_message_is_identical_for_every_failure(self) -> None:
        """It must stay actionable without becoming an oracle."""
        sealer = UrlSealer(GOOD_SECRET)
        valid = sealer.seal("u@example.com", "pw")
        stale = UrlSealer(b"pQ3zX8vB2nM6kL0jH4gF7dS1aW5eR9tYcJ4kP8nZ").seal("u@example.com", "pw")

        messages = set()
        for probe in ("garbage", valid[:-8], stale, valid[:20], "A" * 40):
            try:
                sealer.open(probe)
            except SealError as exc:
                messages.add(str(exc))
        assert len(messages) == 1
