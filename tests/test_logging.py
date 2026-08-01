"""Logging: enough to diagnose an incident, never enough to leak one.

Before this the package emitted a single log record. A failing tool was silent
server-side, because MCP catches tool exceptions and answers with a successful
JSON-RPC response — so the access log showed ``200`` for a request the user
experienced as broken. An intermittent upstream fault took a hand-run
experiment against the live API to find, when it should have been a log query.

The constraint pulling the other way is that sealed URLs are bearer
credentials and they ride in request paths, so the tests that matter most here
are the ones asserting what must *not* appear.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from loseit_mcp.config import Settings
from loseit_mcp.observability import _safe_args, account_tag
from loseit_mcp.server import build_server
from loseit_mcp.service import LoseItService
from loseit_mcp.webapp import _RedactTokenFilter, install_log_redaction

SEALED = "AAAABBBBCCCCDDDDEEEEFFFFGGGG1111HHHH2222"


class TestNothingSensitiveIsLogged:
    def test_a_sealed_url_is_redacted_from_a_message(self) -> None:
        record = logging.LogRecord(
            "x", logging.INFO, "f", 1, 'POST /u/%s/mcp HTTP/1.1" 200', (SEALED,), None
        )
        _RedactTokenFilter().filter(record)
        assert SEALED not in record.getMessage()
        assert "<redacted>" in record.getMessage()

    def test_a_sealed_url_is_redacted_from_a_traceback(self) -> None:
        """Regression: redaction only rewrote the message, and a traceback
        never passes through it — the one route carrying the most text."""
        try:
            raise RuntimeError(f"failed handling /u/{SEALED}/mcp")
        except RuntimeError:
            import sys

            record = logging.LogRecord(
                "x", logging.ERROR, "f", 1, "boom", (), sys.exc_info()
            )
        _RedactTokenFilter().filter(record)
        rendered = (record.exc_text or "") + record.getMessage()
        assert SEALED not in rendered

    def test_redaction_survives_a_handler_added_later(self) -> None:
        """An exporter attached after startup would otherwise bypass a
        one-shot install."""
        install_log_redaction()
        logger = logging.getLogger("loseit_mcp.test.late")
        logger.propagate = False
        records: list[logging.LogRecord] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = Capture()
        logger.addHandler(handler)
        try:
            logger.warning("saw /u/%s/mcp", SEALED)
            assert records
            assert SEALED not in records[0].getMessage()
        finally:
            logger.removeHandler(handler)

    def test_a_bare_token_with_no_path_prefix_is_still_redacted(self) -> None:
        """Redaction was anchored on "/u/", so anything logging the segment on
        its own slipped through. Nothing does today; this closes the route
        before something does."""
        record = logging.LogRecord("x", logging.WARNING, "f", 1, "token %s", (SEALED * 4,), None)
        _RedactTokenFilter().filter(record)
        assert SEALED * 4 not in record.getMessage()

    def test_a_jwt_is_redacted(self) -> None:
        """The `liauth` token. Its dots break it into runs shorter than the
        long-secret floor, so it needs its own pattern."""
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDMxMzQ5MiJ9." + "s" * 40
        record = logging.LogRecord("x", logging.WARNING, "f", 1, "cookie=%s", (jwt,), None)
        _RedactTokenFilter().filter(record)
        assert jwt not in record.getMessage()

    @pytest.mark.parametrize(
        "identifier",
        ["a061be32584d138d1144b4d17d31451f", "50788e17f23bcb991743bac708e5bfa3"],
    )
    def test_food_and_entry_ids_stay_legible(self, identifier: str) -> None:
        """Redaction has to stay surgical. These are exactly 32 hex characters
        and are the identifiers an operator most needs to follow a request, so
        a blanket rule on long tokens would make the logs useless."""
        record = logging.LogRecord(
            "x", logging.INFO, "f", 1, "food_id=%s ok", (identifier,), None
        )
        _RedactTokenFilter().filter(record)
        assert identifier in record.getMessage()

    def test_arguments_are_logged_by_shape_not_value(self) -> None:
        """`query` and `password` are content; `limit` and `dry_run` describe
        the call. Only the latter may appear."""
        rendered = _safe_args(
            {"query": "chicken caesar salad", "limit": 5, "dry_run": True, "password": "hunter2"}
        )
        assert "chicken caesar salad" not in rendered
        assert "hunter2" not in rendered
        assert "limit=5" in rendered
        assert "dry_run=True" in rendered

    def test_the_account_tag_is_not_the_email(self) -> None:
        tag = account_tag("someone@example.com")
        assert "someone" not in tag
        assert "@" not in tag
        assert len(tag) == 16

    def test_the_account_tag_is_stable_within_a_process(self) -> None:
        """Useless for correlation otherwise."""
        assert account_tag("a@example.com") == account_tag("a@example.com")
        assert account_tag("a@example.com") != account_tag("b@example.com")

    def test_the_tag_cannot_confirm_a_guessed_address(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Salted per process, so a log plus a guessed email does not confirm
        that the person uses the service.

        Substitutes the salt rather than reloading the module: a reload mutates
        the module dict in place, silently re-salting every later test.
        """
        import os

        import loseit_mcp.observability as obs

        first = obs.account_tag("target@example.com")
        monkeypatch.setattr(obs, "_TAG_SALT", os.urandom(16))
        assert obs.account_tag("target@example.com") != first

    def test_anonymous_identity_is_handled(self) -> None:
        assert account_tag(None) == "anon"


class TestToolCallsAreLogged:
    @pytest.fixture
    def caplog_at_info(self, caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
        caplog.set_level(logging.INFO, logger="loseit_mcp.tools")
        return caplog

    @pytest.mark.anyio
    async def test_a_successful_call_records_name_and_duration(
        self, settings: Settings, caplog_at_info: pytest.LogCaptureFixture, monkeypatch: Any
    ) -> None:
        monkeypatch.setattr(
            LoseItService, "whoami", lambda self: {"user_name": "T", "email": "e", "hours": 0}
        )
        await build_server(settings).call_tool("whoami", {})
        line = "\n".join(r.getMessage() for r in caplog_at_info.records)
        assert "tool=whoami" in line
        assert "outcome=ok" in line
        assert "dur_ms=" in line

    @pytest.mark.anyio
    async def test_a_failing_call_is_recorded(
        self, settings: Settings, caplog_at_info: pytest.LogCaptureFixture, monkeypatch: Any
    ) -> None:
        """The gap that made an outage undiagnosable: MCP converts a tool
        exception into a successful response, so without this the server
        records a healthy-looking request."""

        def boom(self: Any) -> Any:
            raise RuntimeError("upstream exploded")

        monkeypatch.setattr(LoseItService, "whoami", boom)
        # At this level the manager re-raises; on the wire MCP converts it into
        # a successful response carrying the error text, which is exactly why
        # the server saw nothing before this logging existed.
        from mcp.server.mcpserver.exceptions import ToolError

        with pytest.raises(ToolError):
            await build_server(settings).call_tool("whoami", {})
        text = "\n".join(r.getMessage() for r in caplog_at_info.records)
        assert "tool=whoami" in text
        assert "outcome=error" in text

    @pytest.mark.anyio
    async def test_each_call_gets_its_own_id(
        self, settings: Settings, caplog_at_info: pytest.LogCaptureFixture, monkeypatch: Any
    ) -> None:
        monkeypatch.setattr(
            LoseItService, "whoami", lambda self: {"user_name": "T", "email": "e", "hours": 0}
        )
        server = build_server(settings)
        await server.call_tool("whoami", {})
        await server.call_tool("whoami", {})
        ids = {
            part.split("=")[1]
            for r in caplog_at_info.records
            for part in r.getMessage().split()
            if part.startswith("id=")
        }
        assert len(ids) == 2, "calls share an id, so lines cannot be correlated"

    @pytest.mark.anyio
    async def test_a_tool_registered_later_is_still_logged(
        self, settings: Settings, caplog_at_info: pytest.LogCaptureFixture
    ) -> None:
        """Hooking the manager rather than each tool is what makes this true.

        Registers a tool *after* the server is built and calls it, rather than
        asserting on the wrapper's name — which proved only that a wrapper
        existed, and broke on any rename while still proving nothing.
        """
        server = build_server(settings)

        @server.tool(description="Added after build_server ran.")
        def late_tool() -> str:
            return "hi"

        await server.call_tool("late_tool", {})
        text = "\n".join(r.getMessage() for r in caplog_at_info.records)
        assert "tool=late_tool" in text
        assert "outcome=ok" in text

    @pytest.mark.anyio
    async def test_an_abandoned_call_is_recorded(
        self, settings: Settings, caplog_at_info: pytest.LogCaptureFixture, monkeypatch: Any
    ) -> None:
        """A client that disconnects cancels the task, and CancelledError is
        not an Exception — so the literal "it stopped working" symptom used to
        produce no record at all."""
        server = build_server(settings)

        @server.tool(description="Cancels.")
        def cancels() -> str:
            raise asyncio.CancelledError

        with pytest.raises(asyncio.CancelledError):
            await server.call_tool("cancels", {})
        text = "\n".join(r.getMessage() for r in caplog_at_info.records)
        assert "outcome=abandoned" in text

    @pytest.mark.anyio
    async def test_the_logged_detail_is_the_real_fault(
        self, settings: Settings, caplog_at_info: pytest.LogCaptureFixture
    ) -> None:
        """Translated errors lead with prose for the model and put the fault
        after "Technical detail:", so every distinct protocol break logged an
        identical opening sentence."""
        from mcp.server.mcpserver.exceptions import ToolError

        from loseit_mcp.errors import LoseItMcpError

        server = build_server(settings)

        @server.tool(description="Fails.")
        def failing() -> str:
            raise LoseItMcpError(
                "Lose It's private API did not respond as expected.\n\n"
                "Technical detail: Unexpected response token 42"
            )

        with pytest.raises(ToolError):
            await server.call_tool("failing", {})
        text = "\n".join(r.getMessage() for r in caplog_at_info.records)
        assert "Unexpected response token 42" in text
