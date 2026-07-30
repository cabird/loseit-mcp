"""HTTP layer: path-token routing, log redaction, and credential resolution."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from loseit_mcp.auth import Session
from loseit_mcp.config import Settings
from loseit_mcp.paths import TOKEN_PATH_RE
from loseit_mcp.sealed import UrlSealer
from loseit_mcp.tenancy import (
    Credentials,
    CredentialsError,
    SessionResolver,
    credentials_from_headers,
    credentials_from_request,
)
from loseit_mcp.tokencache import TokenCache
from loseit_mcp.webapp import (
    _path_token,
    _RedactTokenFilter,
    current_path_token,
)
from tests.conftest import make_jwt

TOKEN = "AAAABBBBCCCCDDDDEEEEFFFFGGGG1111"


class TestPathMatching:
    @pytest.mark.parametrize(
        "path,expected_remainder",
        [
            (f"/u/{TOKEN}/mcp", "/mcp"),
            (f"/u/{TOKEN}/", "/"),
            (f"/u/{TOKEN}", None),
        ],
    )
    def test_matches_token_paths(self, path: str, expected_remainder: str | None) -> None:
        match = TOKEN_PATH_RE.match(path)
        assert match is not None
        assert match.group(1) == TOKEN
        assert match.group(2) == expected_remainder

    @pytest.mark.parametrize(
        "path",
        ["/mcp", "/healthz", "/enroll", "/u/", "/u/short", "/uu/" + TOKEN, "/x/u/" + TOKEN],
    )
    def test_ignores_everything_else(self, path: str) -> None:
        assert TOKEN_PATH_RE.match(path) is None


class TestLogRedaction:
    """Regression: tokens are bearer credentials AND decryption keys, and they
    ride in the URL path — exactly what access logs record."""

    def _render(self, msg: str, args: Any) -> str:
        record = logging.LogRecord("t", logging.INFO, "f", 1, msg, args, None)
        _RedactTokenFilter().filter(record)
        return record.getMessage()

    @pytest.mark.parametrize(
        "path",
        [
            f"/u/{TOKEN}/mcp",
            f"/u/{TOKEN}",          # regression: bare form escaped an earlier fix
            f"/u/{TOKEN}?a=1",
            f"/u/{TOKEN}/mcp?x=y",
        ],
    )
    def test_redacts_every_url_shape(self, path: str) -> None:
        rendered = self._render('"GET %s HTTP/1.1" 200', (path,))
        assert TOKEN not in rendered
        assert "<redacted>" in rendered

    def test_redacts_when_token_is_a_separate_arg(self) -> None:
        """The token can be split across msg and args, where neither part
        matches a token pattern on its own."""
        rendered = self._render("fetched /u/%s/mcp ok", (TOKEN,))
        assert TOKEN not in rendered

    def test_survives_dict_style_args(self) -> None:
        """Regression: wrapping a mapping in a tuple broke record.getMessage()."""
        rendered = self._render("%(path)s served", ({"path": f"/u/{TOKEN}/mcp"},))
        assert TOKEN not in rendered
        assert "served" in rendered

    def test_leaves_unrelated_records_untouched(self) -> None:
        record = logging.LogRecord("t", logging.INFO, "f", 1, "%s ok", ("/healthz",), None)
        _RedactTokenFilter().filter(record)
        assert record.args == ("/healthz",), "structure preserved when nothing to redact"
        assert record.getMessage() == "/healthz ok"

    def test_applies_to_records_propagating_from_child_loggers(self) -> None:
        """Logger-level filters do NOT run for propagated records; handler-level
        filters do. This is what makes redaction cover third-party libraries."""
        captured: list[str] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                captured.append(record.getMessage())

        handler = Capture()
        handler.addFilter(_RedactTokenFilter())
        parent = logging.getLogger("redaction_test")
        parent.handlers = [handler]
        parent.propagate = False
        parent.setLevel(logging.INFO)

        logging.getLogger("redaction_test.child").info("hit /u/%s/mcp", TOKEN)

        assert captured and TOKEN not in captured[-1]


class TestContextVar:
    def test_defaults_to_none(self) -> None:
        assert current_path_token() is None

    def test_is_reset_after_use(self) -> None:
        reset = _path_token.set(TOKEN)
        assert current_path_token() == TOKEN
        _path_token.reset(reset)
        assert current_path_token() is None


class TestHeaderCredentials:
    def test_reads_basic_auth(self) -> None:
        import base64

        raw = base64.b64encode(b"user@example.com:hunter2").decode()
        creds = credentials_from_headers({"authorization": f"Basic {raw}"})
        assert creds.email == "user@example.com"
        assert creds.password == "hunter2"

    def test_reads_explicit_headers(self) -> None:
        creds = credentials_from_headers(
            {"x-loseit-email": "user@example.com", "x-loseit-password": "hunter2"}
        )
        assert creds.email == "user@example.com"

    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"authorization": "Bearer abc"},
            {"authorization": "Basic !!!not-base64!!!"},
            {"x-loseit-email": "user@example.com"},          # password missing
            {"x-loseit-password": "hunter2"},                # email missing
        ],
    )
    def test_rejects_incomplete_credentials(self, headers: dict[str, str]) -> None:
        with pytest.raises(CredentialsError):
            credentials_from_headers(headers)


class TestRequestCredentials:
    @pytest.fixture
    def sealer(self) -> UrlSealer:
        return UrlSealer(b"kJ8x2mQ7vN4pL9wR3tY6uZ1aS5dF0gH8cV7bN2mX")

    def test_headers_take_precedence_over_the_url(self, sealer: UrlSealer) -> None:
        reset = _path_token.set(sealer.seal("sealed@example.com", "pw"))
        try:
            creds = credentials_from_request(
                {"x-loseit-email": "header@example.com", "x-loseit-password": "pw"}, sealer
            )
            assert creds.email == "header@example.com"
        finally:
            _path_token.reset(reset)

    def test_falls_back_to_the_sealed_url(self, sealer: UrlSealer) -> None:
        reset = _path_token.set(sealer.seal("sealed@example.com", "pw", hours_from_gmt=-7))
        try:
            creds = credentials_from_request({}, sealer)
            assert creds.email == "sealed@example.com"
            assert creds.hours_from_gmt == -7
        finally:
            _path_token.reset(reset)

    def test_no_credentials_anywhere_raises(self, sealer: UrlSealer) -> None:
        with pytest.raises(CredentialsError):
            credentials_from_request({}, sealer)

    def test_url_sealed_with_another_secret_is_rejected(self, sealer: UrlSealer) -> None:
        """Rotating the secret is the revocation mechanism."""
        stale = UrlSealer(b"pQ3zX8vB2nM6kL0jH4gF7dS1aW5eR9tYcJ4kP8nZ").seal("u@example.com", "pw")
        reset = _path_token.set(stale)
        try:
            with pytest.raises(CredentialsError):
                credentials_from_request({}, sealer)
        finally:
            _path_token.reset(reset)

    def test_timezone_header_applies_on_the_url_path(self, sealer: UrlSealer) -> None:
        """Regression: the offset header was discarded on the URL path, leaving
        URL-only clients pinned to the container's UTC clock."""
        reset = _path_token.set(sealer.seal("u@example.com", "pw", hours_from_gmt=None))
        try:
            creds = credentials_from_request({"x-loseit-hours-from-gmt": "-7"}, sealer)
            assert creds.hours_from_gmt == -7
        finally:
            _path_token.reset(reset)

    def test_timezone_header_overrides_the_sealed_value(self, sealer: UrlSealer) -> None:
        reset = _path_token.set(sealer.seal("u@example.com", "pw", hours_from_gmt=0))
        try:
            creds = credentials_from_request({"x-loseit-hours-from-gmt": "5"}, sealer)
            assert creds.hours_from_gmt == 5
        finally:
            _path_token.reset(reset)

    @pytest.mark.parametrize("bad", ["abc", "99", "-99", "1.5"])
    def test_malformed_timezone_header_is_reported(self, sealer: UrlSealer, bad: str) -> None:
        """Regression: it was silently swallowed by the URL fallback."""
        with pytest.raises(CredentialsError):
            credentials_from_request(
                {
                    "x-loseit-email": "u@example.com",
                    "x-loseit-password": "pw",
                    "x-loseit-hours-from-gmt": bad,
                },
                sealer,
            )


class TestSessionResolver:
    def test_multi_tenant_never_persists_sessions_to_disk(self, tmp_path: Any) -> None:
        """Regression: the session file is process-wide, so tenants clobbered
        each other and leaked live JWTs in plaintext."""
        base = Settings(session_file=tmp_path / "shared.json")
        resolver = SessionResolver(base)
        resolver._cache.put(  # type: ignore[attr-defined]
            "u@example.com", "pw", Session(make_jwt(), "1", "U", "u@example.com")
        )
        service = resolver.resolve(Credentials("u@example.com", "pw"))
        assert service._settings.persist_session is False  # type: ignore[attr-defined]

    def test_reauth_hook_refreshes_the_cache(self, tmp_path: Any) -> None:
        """Regression: a revoked-but-unexpired JWT stayed cached, so every
        request paid a fresh login."""
        cache = TokenCache(secret=b"s")
        stale = Session(make_jwt(), "1", "U", "u@example.com")
        cache.put("u@example.com", "pw", stale)

        resolver = SessionResolver(Settings(session_file=tmp_path / "s.json"), cache)
        service = resolver.resolve(Credentials("u@example.com", "pw"))

        fresh = Session(make_jwt(), "1", "U", "u@example.com")
        service.on_reauthenticated(fresh)  # type: ignore[misc]

        assert cache.get("u@example.com", "pw").token == fresh.token
