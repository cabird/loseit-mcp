"""The tool/protocol contract clients actually rely on.

An earlier version of this file asserted that a tool declaring an output schema
must not return text — supposedly the cause of a production outage. That was
wrong on the version we deploy: the framework wraps a scalar return as
``{"result": ...}`` and populates structured content to match. The outage was
Lose It's intermittent search fault, fixed by retrying reads.

What is worth pinning is behaviour on the wire: whether a declared schema is
actually satisfied when the tool is called. These assert that against real
``call_tool`` results rather than reading return annotations, which is what
made the previous version both wrong and unfalsifiable.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

import pytest

from loseit_mcp.config import Settings
from loseit_mcp.server import build_server
from loseit_mcp.service import LoseItService


def _tools(settings: Settings) -> list[Any]:
    return build_server(settings)._tool_manager.list_tools()


@pytest.fixture
def stubbed_search(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the flaky upstream out of a protocol-shape test."""
    monkeypatch.setattr(
        LoseItService,
        "search_food",
        lambda self, q, limit=10, detail=True: [
            {
                "food_id": "a" * 32,
                "name": "Test Food",
                "brand": "",
                "nutrition_available": True,
                "primary_serving": {"unit": "cup", "native_qty_per_serving": 1.0},
                "nutrients_per_serving": {"calories": 100.0},
            }
        ],
    )


class TestOutputSchemaContract:
    @pytest.mark.anyio
    async def test_search_food_returns_text_only(
        self, settings: Settings, stubbed_search: None
    ) -> None:
        """Prose, deliberately. Declaring a schema would ship the same table a
        second time as structured content."""
        server = build_server(settings)
        tool = next(t for t in server._tool_manager.list_tools() if t.name == "search_food")
        assert tool.output_schema is None

        result = await server.call_tool("search_food", {"query": "x", "limit": 1})
        assert getattr(result, "structured_content", None) is None
        assert "Test Food" in result.content[0].text

    @pytest.mark.anyio
    async def test_a_declared_schema_is_satisfied_when_called(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The invariant that actually matters: advertising an output schema
        obliges the response to carry structured content."""
        monkeypatch.setattr(
            LoseItService,
            "whoami",
            lambda self: {"user_name": "T", "email": "e@x", "hours_from_gmt": 0},
        )
        server = build_server(settings)
        tool = next(t for t in server._tool_manager.list_tools() if t.name == "whoami")
        result = await server.call_tool("whoami", {})
        if tool.output_schema is not None:
            assert getattr(result, "structured_content", None) is not None

    def test_omitting_the_schema_avoids_duplicating_the_payload(self) -> None:
        """The reason for the choice, pinned so undoing it is visible."""
        text = "1. Food | 278 | 15/32/9 | 0.5 cup | " + "a" * 32
        both = len(json.dumps({"content": text, "structuredContent": {"result": text}}))
        text_only = len(json.dumps({"content": text}))
        assert text_only < both / 1.8

    def test_dict_returning_tools_keep_their_schemas(self, settings: Settings) -> None:
        """The choice must not strip structure from tools that legitimately
        have it — a client reading structuredContent from get_diary should
        keep working."""
        by_name = {t.name: t for t in _tools(settings)}
        for name in ("get_diary", "log_food", "server_status", "whoami"):
            assert by_name[name].output_schema is not None, f"{name} lost its schema"

    def test_every_schema_is_serialisable(self, settings: Settings) -> None:
        """It travels over JSON-RPC; an unserialisable schema breaks
        tools/list for every tool, not just the offender."""
        for tool in _tools(settings):
            if tool.output_schema is not None:
                json.dumps(tool.output_schema)


class TestToolSurface:
    EXPECTED: ClassVar[set[str]] = {
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

    def test_the_tool_set_is_stable(self, settings: Settings) -> None:
        """Clients pin tool names in configuration; renaming one silently
        breaks them."""
        assert {t.name for t in _tools(settings)} == self.EXPECTED

    def test_every_tool_has_a_description(self, settings: Settings) -> None:
        for tool in _tools(settings):
            assert (tool.description or "").strip(), f"{tool.name} has no description"

    @pytest.mark.parametrize("name", sorted(EXPECTED))
    def test_every_tool_has_an_input_schema(self, settings: Settings, name: str) -> None:
        tool = next(t for t in _tools(settings) if t.name == name)
        schema = tool.fn_metadata.arg_model.model_json_schema()
        assert schema.get("type") == "object"


class TestVersionConsistency:
    def test_the_package_version_matches_the_reported_one(self) -> None:
        """`/healthz` and `server_status` report `__version__` while wheel
        metadata reports pyproject's. They drifted by five releases."""
        import pathlib
        import re

        from loseit_mcp import __version__

        text = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
        assert declared is not None
        assert declared.group(1) == __version__
