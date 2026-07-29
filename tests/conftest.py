"""Shared fixtures.

The suite never touches the network or the developer's real config: every test
supplies its own settings and, where an RPC would happen, a fake HTTP client.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

import pytest

from loseit_mcp.auth import Session
from loseit_mcp.config import Settings


def make_jwt(*, sub: str = "10313492", exp_offset: int = 14 * 86400) -> str:
    """A structurally valid, unsigned JWT with a controllable expiry."""

    def seg(data: dict[str, Any]) -> str:
        raw = json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = seg({"alg": "HS256"})
    payload = seg({"sub": sub, "iss": "Lose It!", "iat": int(time.time()), "exp": int(time.time()) + exp_offset})
    return f"{header}.{payload}.signature"


@pytest.fixture
def valid_token() -> str:
    return make_jwt()


@pytest.fixture
def expired_token() -> str:
    return make_jwt(exp_offset=-3600)


@pytest.fixture
def session(valid_token: str) -> Session:
    return Session(
        token=valid_token,
        user_id="10313492",
        user_name="Tester",
        email="user@example.com",
    )


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Isolated settings — never reads the developer's real config."""
    return Settings(
        email="user@example.com",
        password="hunter2",
        user_id="10313492",
        user_name="Tester",
        hours_from_gmt=-7,
        session_file=tmp_path / "session.json",
    )


@pytest.fixture
def anyio_backend() -> str:
    """Run async tests on asyncio only; trio adds no coverage here."""
    return "asyncio"


class FakeHttpClient:
    """Stands in for lose_it's HttpClient, recording payloads it is given."""

    def __init__(self, responses: list[str] | None = None, config: Any = None):
        self.responses = list(responses or [])
        self.payloads: list[str] = []
        self.config = config

    def post_rpc(self, payload: str) -> str:
        self.payloads.append(payload)
        if not self.responses:
            raise AssertionError("FakeHttpClient ran out of canned responses")
        return self.responses.pop(0)
