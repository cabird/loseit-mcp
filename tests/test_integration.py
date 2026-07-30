"""End-to-end tests through the MCP tool layer and the HTTP endpoints.

These exercise the wiring the unit tests don't reach: tool schemas, per-request
credential resolution, error translation, and the /enroll route.
"""

from __future__ import annotations

from typing import Any

import pytest
from lose_it.core._http import LoseItError
from starlette.testclient import TestClient

from loseit_mcp.config import Settings
from loseit_mcp.enroll import add_enrollment_route
from loseit_mcp.errors import LoseItMcpError, translate
from loseit_mcp.sealed import UrlSealer
from loseit_mcp.server import build_server
from loseit_mcp.webapp import PathTokenMiddleware
from loseit_mcp.weight import WeightHistoryError

EXPECTED_TOOLS = {
    "search_food",
    "describe_food",
    "get_diary",
    "log_food",
    "log_custom_food",
    "delete_entry",
    "log_weight",
    "get_weight_history",
    "server_status",
    "whoami",
}


class TestToolSurface:
    @pytest.mark.anyio
    async def test_exposes_the_expected_tools(self, settings: Settings) -> None:
        tools = await build_server(settings).list_tools()
        assert {t.name for t in tools} == EXPECTED_TOOLS

    @pytest.mark.anyio
    async def test_context_is_not_part_of_any_tool_schema(self, settings: Settings) -> None:
        """`ctx` is injected by the runtime; leaking it into the schema would
        make every tool look like it needs an extra argument."""
        for tool in await build_server(settings).list_tools():
            assert "ctx" not in (tool.input_schema or {}).get("properties", {}), tool.name

    @pytest.mark.anyio
    async def test_every_tool_is_described(self, settings: Settings) -> None:
        for tool in await build_server(settings).list_tools():
            assert tool.description and len(tool.description) > 30, tool.name

    @pytest.mark.anyio
    async def test_log_food_declares_both_portion_forms(self, settings: Settings) -> None:
        tools = {t.name: t for t in await build_server(settings).list_tools()}
        props = tools["log_food"].input_schema["properties"]
        assert {"servings", "serving_amount", "serving_unit"} <= set(props)

    @pytest.mark.anyio
    async def test_custom_food_flags_the_unsupported_nutrient(self, settings: Settings) -> None:
        tools = {t.name: t for t in await build_server(settings).list_tools()}
        assert "saturated_fat_g" in tools["log_custom_food"].description


class TestErrorTranslation:
    """An upstream protocol change must reach the user as an explanation, not a
    decoder traceback."""

    def test_protocol_break_is_explained(self) -> None:
        translated = translate(LoseItError("Unexpected response: <html>"))
        assert isinstance(translated, LoseItMcpError)
        text = str(translated)
        assert "new version of their web app" in text
        assert "LOSEIT_STRONG_NAME" in text
        assert "retrying now will not help" in text

    def test_weight_history_decode_failure_is_explained(self) -> None:
        translated = translate(WeightHistoryError("response too large to decode"))
        assert isinstance(translated, LoseItMcpError)
        assert "compatibility" in str(translated)

    def test_auth_failure_tells_the_user_to_check_credentials(self) -> None:
        translated = translate(LoseItError("GWT error: UserAuthenticationFailedException/1"))
        assert isinstance(translated, LoseItMcpError)
        assert "check the email and password" in str(translated)

    def test_network_failure_suggests_retrying(self) -> None:
        import httpx

        translated = translate(httpx.ConnectError("no route"))
        assert isinstance(translated, LoseItMcpError)
        assert "retrying" in str(translated)

    def test_structural_decode_errors_are_explained(self) -> None:
        assert isinstance(translate(KeyError("f3")), LoseItMcpError)
        assert isinstance(translate(IndexError("list index")), LoseItMcpError)

    def test_argument_errors_pass_through_untouched(self) -> None:
        original = ValueError("serving_amount and serving_unit must be supplied together")
        assert translate(original) is original

    def test_unknown_errors_pass_through(self) -> None:
        original = RuntimeError("something else entirely")
        assert translate(original) is original


class TestToolErrorSurfacing:
    @pytest.mark.anyio
    async def test_upstream_break_reaches_the_caller_as_a_message(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp.server.mcpserver.exceptions import ToolError

        server = build_server(settings)

        def explode(*_a: Any, **_k: Any) -> Any:
            raise LoseItError("Unexpected response: <html>")

        from loseit_mcp.service import LoseItService

        monkeypatch.setattr(LoseItService, "search_food", explode)

        with pytest.raises(ToolError) as caught:
            await server.call_tool("search_food", {"query": "apple"})
        assert "new version of their web app" in str(caught.value)

    @pytest.mark.anyio
    async def test_invalid_portion_reaches_the_caller(self, settings: Settings) -> None:
        from mcp.server.mcpserver.exceptions import ToolError

        server = build_server(settings)
        with pytest.raises(ToolError) as caught:
            await server.call_tool(
                "log_food", {"food_id": "a" * 32, "serving_amount": 120, "dry_run": True}
            )
        assert "together" in str(caught.value)


def _http_app(sealer: UrlSealer, settings: Settings, *, enroll_secret: str | None = None) -> Any:
    from loseit_mcp.cli import _add_health_route

    mcp = build_server(settings, multi_tenant=True, sealer=sealer)
    _add_health_route(mcp)
    add_enrollment_route(mcp, sealer, mount_path="/mcp", enroll_secret=enroll_secret)
    return PathTokenMiddleware(mcp.streamable_http_app(streamable_http_path="/mcp"))


class TestEnrollmentEndpoints:
    @pytest.fixture
    def client(self, settings: Settings) -> Any:
        sealer = UrlSealer(b"kJ8x2mQ7vN4pL9wR3tY6uZ1aS5dF0gH8cV7bN2mX")
        with TestClient(_http_app(sealer, settings, enroll_secret="s3cret")) as client:
            client.sealer = sealer  # type: ignore[attr-defined]
            yield client

    def test_enroll_requires_the_shared_secret(self, client: Any) -> None:
        response = client.post("/enroll", json={"email": "u@example.com", "password": "pw"})
        assert response.status_code == 403

    def test_enroll_returns_a_url(self, client: Any) -> None:
        response = client.post(
            "/enroll",
            json={"email": "u@example.com", "password": "pw"},
            headers={"X-Enroll-Secret": "s3cret"},
        )
        assert response.status_code == 201
        body = response.json()
        assert "/u/" in body["url"] and body["url"].endswith("/mcp")
        assert body["expires_in_days"] == 365
        assert "rotate" in body["note"].lower()

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"email": "u@example.com"},
            {"password": "pw"},
            {"email": "", "password": "pw"},
            {"email": "u@example.com", "password": "pw", "ttl_days": -1},
            {"email": "u@example.com", "password": "pw", "ttl_days": "soon"},
            {"email": "u@example.com", "password": "pw", "hours_from_gmt": 99},
        ],
    )
    def test_rejects_bad_payloads(self, client: Any, payload: dict[str, Any]) -> None:
        response = client.post(
            "/enroll", json=payload, headers={"X-Enroll-Secret": "s3cret"}
        )
        assert response.status_code == 400

    def test_rejects_a_non_json_body(self, client: Any) -> None:
        response = client.post(
            "/enroll", content=b"not json", headers={"X-Enroll-Secret": "s3cret"}
        )
        assert response.status_code == 400

    def test_a_sealed_url_works_immediately(self, client: Any) -> None:
        """No enrollment record exists anywhere — the URL is self-contained."""
        url = client.post(
            "/enroll",
            json={"email": "u@example.com", "password": "pw"},
            headers={"X-Enroll-Secret": "s3cret"},
        ).json()["url"]
        sealed = url.split("/u/")[1].split("/")[0]
        opened = client.sealer.open(sealed)
        assert opened.email == "u@example.com"

    def test_healthz_is_open(self, client: Any) -> None:
        response = client.get("/healthz")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        # The build stamp is what makes "is my change deployed?" answerable
        # from outside the box.
        assert body["build"]["version"]
        # And the resolved client address is what rate limiting keys on.
        assert body["client"]["resolved"]


class TestPathTokenRouting:
    @pytest.fixture
    def client(self, settings: Settings) -> Any:
        sealer = UrlSealer(b"kJ8x2mQ7vN4pL9wR3tY6uZ1aS5dF0gH8cV7bN2mX")
        with TestClient(_http_app(sealer, settings, enroll_secret="s3cret")) as client:
            client.sealer = sealer  # type: ignore[attr-defined]
            yield client

    def test_token_path_reaches_the_mcp_mount(self, client: Any) -> None:
        token = client.sealer.seal("u@example.com", "pw")
        # A GET without the MCP handshake headers still proves routing: the MCP
        # app answered rather than the router returning 404.
        assert client.get(f"/u/{token}/mcp").status_code != 404

    def test_unknown_paths_still_404(self, client: Any) -> None:
        assert client.get("/u/short/mcp").status_code == 404
        assert client.get("/nope").status_code == 404

    def test_traversal_attempts_do_not_escape(self, client: Any) -> None:
        token = client.sealer.seal("u@example.com", "pw")
        assert client.get(f"/u/{token}/../enroll").status_code in (404, 405, 307)
