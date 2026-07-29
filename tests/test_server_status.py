"""The `server_status` diagnostic tool.

Its job is to be answerable when everything else is failing, so the cases that
matter most are the failure ones.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from lose_it.core._http import LoseItError

from loseit_mcp.config import Settings
from loseit_mcp.server import build_server
from loseit_mcp.service import LoseItService


async def _status(server: Any) -> dict[str, Any]:
    result = await server.call_tool("server_status", {})
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError(f"could not read a status payload from {result!r}")


@pytest.fixture
def healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        LoseItService,
        "whoami",
        lambda self: {
            "user_id": "1",
            "user_name": "Tester",
            "email": "user@example.com",
            "hours_from_gmt": -7,
        },
    )
    monkeypatch.setattr(LoseItService, "search_food", lambda self, q, limit=1: [{"name": "Water"}])


class TestToolSurface:
    @pytest.mark.anyio
    async def test_is_exposed(self, settings: Settings) -> None:
        names = {t.name for t in await build_server(settings).list_tools()}
        assert "server_status" in names

    @pytest.mark.anyio
    async def test_takes_no_arguments(self, settings: Settings) -> None:
        """It must stay callable with no setup, since it is what you reach for
        when you don't know what's wrong."""
        tools = {t.name: t for t in await build_server(settings).list_tools()}
        schema = tools["server_status"].input_schema or {}
        assert schema.get("required", []) == []
        assert "ctx" not in schema.get("properties", {})

    @pytest.mark.anyio
    async def test_description_says_it_is_for_diagnosis(self, settings: Settings) -> None:
        tools = {t.name: t for t in await build_server(settings).list_tools()}
        assert "diagnose" in tools["server_status"].description.lower()


class TestHealthyServer:
    @pytest.mark.anyio
    async def test_reports_ok(self, settings: Settings, healthy: None) -> None:
        status = await _status(build_server(settings))
        assert status["ok"] is True
        assert status["authenticated"] is True
        assert status["loseit_reachable"] is True

    @pytest.mark.anyio
    async def test_reports_the_build(self, settings: Settings, healthy: None) -> None:
        build = (await _status(build_server(settings)))["build"]
        assert build["version"]
        # Absent stamps are themselves informative: it means a source checkout.
        assert set(build) == {"version", "commit", "built_at", "image_tag"}

    @pytest.mark.anyio
    async def test_reports_the_account(self, settings: Settings, healthy: None) -> None:
        account = (await _status(build_server(settings)))["account"]
        assert account["user_name"] == "Tester"
        assert account["hours_from_gmt"] == -7

    @pytest.mark.anyio
    async def test_reports_the_mode(self, settings: Settings, healthy: None) -> None:
        assert (await _status(build_server(settings)))["mode"] == "single-account"


class TestDegradedServer:
    """The tool must answer rather than raise — an exception would tell the
    caller nothing about *which* part is broken."""

    @pytest.mark.anyio
    async def test_upstream_failure_is_reported_not_raised(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            LoseItService,
            "whoami",
            lambda self: {"user_name": "Tester", "email": "u@example.com", "hours_from_gmt": -7},
        )

        def boom(self: Any, query: str, limit: int = 1) -> Any:
            raise LoseItError("Unexpected response: <html>")

        monkeypatch.setattr(LoseItService, "search_food", boom)

        status = await _status(build_server(settings))
        assert status["ok"] is False
        assert status["authenticated"] is True, "credentials resolved; Lose It did not"
        assert status["loseit_reachable"] is False
        assert "new version of their web app" in status["loseit_error"]

    @pytest.mark.anyio
    async def test_auth_failure_is_reported_not_raised(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(self: Any) -> Any:
            raise RuntimeError("no credentials configured")

        monkeypatch.setattr(LoseItService, "whoami", boom)

        status = await _status(build_server(settings))
        assert status["ok"] is False
        assert status["authenticated"] is False
        assert "auth_error" in status
        assert "loseit_reachable" not in status, "cannot judge reachability without auth"

    @pytest.mark.anyio
    async def test_build_is_reported_even_when_broken(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Knowing which build is failing is the point."""
        monkeypatch.setattr(
            LoseItService, "whoami", lambda self: (_ for _ in ()).throw(RuntimeError("down"))
        )
        assert (await _status(build_server(settings)))["build"]["version"]

    @pytest.mark.anyio
    async def test_errors_are_length_bounded(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            LoseItService,
            "whoami",
            lambda self: (_ for _ in ()).throw(RuntimeError("x" * 10_000)),
        )
        assert len((await _status(build_server(settings)))["auth_error"]) <= 400
