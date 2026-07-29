"""The `loseit-mcp enroll` client helper.

Secrets must never reach argv, and a plain-http server must not receive
credentials by accident.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from loseit_mcp.cli import build_parser
from loseit_mcp.enroll_client import EnrollClientError, enroll


def _transport(handler: Any) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never pick up the developer's real credentials."""
    for name in ("LOSEIT_EMAIL", "LOSEIT_PASSWORD", "LOSEIT_ENROLL_SECRET"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def creds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOSEIT_EMAIL", "user@example.com")
    monkeypatch.setenv("LOSEIT_PASSWORD", "hunter2")
    monkeypatch.setenv("LOSEIT_ENROLL_SECRET", "s3cret")


class TestArgumentSurface:
    def test_password_is_not_a_command_line_flag(self) -> None:
        """argv is visible in shell history and process listings."""
        with pytest.raises(SystemExit):
            build_parser().parse_args(["enroll", "https://h", "--password", "hunter2"])

    def test_enroll_secret_is_not_a_command_line_flag(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["enroll", "https://h", "--enroll-secret", "x"])

    def test_server_is_required(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["enroll"])

    def test_accepts_the_optional_flags(self) -> None:
        args = build_parser().parse_args(
            ["enroll", "https://h", "--email", "a@b.c", "--ttl-days", "30", "--tz", "-7"]
        )
        assert (args.email, args.ttl_days, args.tz_offset) == ("a@b.c", 30, -7)


class TestTransportSafety:
    def test_refuses_plain_http_by_default(self, creds: None) -> None:
        with pytest.raises(EnrollClientError, match="plain http"):
            enroll("http://example.com")

    def test_allows_plain_http_when_asked(self, creds: None, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(201, json={"url": "http://example.com/u/x/mcp"})

        monkeypatch.setattr(
            httpx, "post", lambda url, **kw: _transport(handler).handle_request(
                httpx.Request("POST", url, **{k: v for k, v in kw.items() if k != "timeout"})
            )
        )
        assert enroll("http://example.com", allow_insecure=True)["url"].endswith("/mcp")

    @pytest.mark.parametrize("bad", ["example.com", "ftp://example.com", "not a url"])
    def test_rejects_non_http_urls(self, creds: None, bad: str) -> None:
        with pytest.raises(EnrollClientError):
            enroll(bad)


class TestRequest:
    def _run(
        self, monkeypatch: pytest.MonkeyPatch, handler: Any, **kwargs: Any
    ) -> dict[str, Any]:
        captured: dict[str, Any] = {}

        def fake_post(url: str, **kw: Any) -> httpx.Response:
            captured["url"] = url
            captured["json"] = kw.get("json")
            captured["headers"] = kw.get("headers")
            return handler()

        monkeypatch.setattr(httpx, "post", fake_post)
        result = enroll("https://example.com", **kwargs)
        return {"captured": captured, "result": result}

    def test_sends_credentials_and_secret_header(
        self, creds: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = self._run(
            monkeypatch,
            lambda: httpx.Response(201, json={"url": "https://example.com/u/x/mcp"}),
        )
        assert out["captured"]["url"] == "https://example.com/enroll"
        assert out["captured"]["json"]["email"] == "user@example.com"
        assert out["captured"]["headers"]["x-enroll-secret"] == "s3cret"

    def test_trailing_slash_is_normalised(
        self, creds: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def fake_post(url: str, **kw: Any) -> httpx.Response:
            captured["url"] = url
            return httpx.Response(201, json={"url": "https://example.com/u/x/mcp"})

        monkeypatch.setattr(httpx, "post", fake_post)
        enroll("https://example.com/")
        assert captured["url"] == "https://example.com/enroll"

    def test_detects_the_local_timezone_by_default(
        self, creds: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = self._run(
            monkeypatch,
            lambda: httpx.Response(201, json={"url": "https://example.com/u/x/mcp"}),
        )
        assert -12 <= out["captured"]["json"]["hours_from_gmt"] <= 14

    def test_explicit_timezone_wins(self, creds: None, monkeypatch: pytest.MonkeyPatch) -> None:
        out = self._run(
            monkeypatch,
            lambda: httpx.Response(201, json={"url": "https://example.com/u/x/mcp"}),
            tz_offset=5,
        )
        assert out["captured"]["json"]["hours_from_gmt"] == 5

    def test_ttl_is_omitted_unless_requested(
        self, creds: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = self._run(
            monkeypatch,
            lambda: httpx.Response(201, json={"url": "https://example.com/u/x/mcp"}),
        )
        assert "ttl_days" not in out["captured"]["json"]


class TestErrorHandling:
    def _fail(self, monkeypatch: pytest.MonkeyPatch, response: httpx.Response) -> None:
        monkeypatch.setattr(httpx, "post", lambda url, **kw: response)

    def test_forbidden_names_the_enroll_secret(
        self, creds: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._fail(monkeypatch, httpx.Response(403, json={"error": "no"}))
        with pytest.raises(EnrollClientError, match="enrollment secret"):
            enroll("https://example.com")

    def test_not_found_suggests_enabling_enrollment(
        self, creds: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._fail(monkeypatch, httpx.Response(404, text="nope"))
        with pytest.raises(EnrollClientError, match="LOSEIT_ENROLLMENT"):
            enroll("https://example.com")

    def test_bad_request_surfaces_the_server_message(
        self, creds: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._fail(monkeypatch, httpx.Response(400, json={"error": "'ttl_days' must be positive."}))
        with pytest.raises(EnrollClientError, match="ttl_days"):
            enroll("https://example.com")

    def test_unreachable_server_is_reported(
        self, creds: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(url: str, **kw: Any) -> httpx.Response:
            raise httpx.ConnectError("no route")

        monkeypatch.setattr(httpx, "post", boom)
        with pytest.raises(EnrollClientError, match="Could not reach"):
            enroll("https://example.com")

    def test_non_json_response_is_reported(
        self, creds: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._fail(monkeypatch, httpx.Response(201, text="<html>"))
        with pytest.raises(EnrollClientError, match="wasn't JSON"):
            enroll("https://example.com")

    def test_missing_url_in_response_is_reported(
        self, creds: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._fail(monkeypatch, httpx.Response(201, json={"ok": True}))
        with pytest.raises(EnrollClientError, match="did not contain a URL"):
            enroll("https://example.com")

    def test_non_interactive_without_credentials_fails_clearly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No prompting is possible when piped, so say so rather than hanging."""
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        with pytest.raises(EnrollClientError, match="required"):
            enroll("https://example.com")
