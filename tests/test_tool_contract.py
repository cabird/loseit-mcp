"""The tool/protocol contract clients actually rely on.

These exist because a change that passed every other test broke a real chat
client in production. `search_food` was changed to return a string; the
framework derived an output schema of ``{"result": string}`` from the return
annotation and then sent no ``structuredContent`` to satisfy it. The MCP spec
requires a tool declaring an output schema to return conforming structured
content, so a validating client rejected every response.

Nothing caught it because the server object's own ``list_tools()`` reports no
schemas at all — the schema only appears on the wire and on the tool manager.
Tests that ask the server object the easy question get the wrong answer.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

import pytest

from loseit_mcp.config import Settings
from loseit_mcp.server import build_server


def _tools(settings: Settings) -> list[Any]:
    return build_server(settings)._tool_manager.list_tools()


class TestOutputSchemaContract:
    def test_every_tool_declaring_a_schema_can_satisfy_it(self, settings: Settings) -> None:
        """A tool may return unstructured text, or structured content matching
        a declared schema — but not declare a schema and return text.

        The framework decides this from the return annotation: anything it
        can't model as an object still gets wrapped in a ``{"result": ...}``
        schema, while the value travels as plain text content.
        """
        offenders = []
        for tool in _tools(settings):
            if tool.output_schema is None:
                continue
            returns = tool.fn.__annotations__.get("return")
            # dict-shaped returns produce structured content; scalars do not.
            if returns is not None and returns is not Any and "dict" not in str(returns):
                offenders.append(f"{tool.name} declares a schema but returns {returns}")
        assert not offenders, "; ".join(offenders)

    def test_search_food_declares_no_output_schema(self, settings: Settings) -> None:
        """It answers with prose. Regression: declaring a schema it could not
        satisfy made a validating client reject every search."""
        tool = next(t for t in _tools(settings) if t.name == "search_food")
        assert tool.output_schema is None

    def test_search_food_still_returns_text(self, settings: Settings) -> None:
        tool = next(t for t in _tools(settings) if t.name == "search_food")
        # Annotations are strings here: the module uses postponed evaluation.
        assert tool.fn.__annotations__.get("return") == "str"

    def test_dict_returning_tools_keep_their_schemas(self, settings: Settings) -> None:
        """The fix must not strip structure from tools that legitimately have
        it — a client that reads structuredContent from get_diary should keep
        working."""
        by_name = {t.name: t for t in _tools(settings)}
        for name in ("get_diary", "log_food", "server_status", "whoami"):
            assert by_name[name].output_schema is not None, f"{name} lost its schema"

    def test_the_schema_is_serialisable(self, settings: Settings) -> None:
        """It goes over JSON-RPC; an unserialisable schema breaks tools/list
        for every tool, not just the offender."""
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
        """Clients pin tool names in their configuration; renaming one silently
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
