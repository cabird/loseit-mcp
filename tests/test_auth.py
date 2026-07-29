"""Authentication: token resolution, expiry, caching, and file permissions.

Every case here is a regression that a review caught.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from loseit_mcp import auth
from loseit_mcp.auth import (
    Session,
    _matches_configured_account,
    _write_private,
    decode_jwt_payload,
    is_expired,
    load_cached_session,
    resolve_session,
    save_session,
)
from loseit_mcp.config import ConfigError, Settings
from tests.conftest import make_jwt


class TestJwt:
    def test_decodes_payload_without_verifying(self, valid_token: str) -> None:
        claims = decode_jwt_payload(valid_token)
        assert claims is not None
        assert claims["sub"] == "10313492"

    @pytest.mark.parametrize("garbage", ["", "not-a-jwt", "a.b", "a.!!!.c"])
    def test_malformed_tokens_return_none(self, garbage: str) -> None:
        assert decode_jwt_payload(garbage) is None

    def test_expiry_uses_leeway(self) -> None:
        # Inside the leeway window the token is already considered dead, so it
        # cannot expire mid-request.
        assert is_expired(make_jwt(exp_offset=60), leeway_seconds=300)
        assert not is_expired(make_jwt(exp_offset=3600), leeway_seconds=300)

    def test_token_without_exp_is_not_treated_as_expired(self) -> None:
        # A failing RPC will trigger re-auth anyway; guessing "expired" here
        # would cause needless logins.
        assert not is_expired("a.eyJzdWIiOiAiMSJ9.c")


class TestSessionFile:
    def test_written_private_and_atomically(self, tmp_path: Path) -> None:
        target = tmp_path / "session.json"
        _write_private(target, '{"token": "secret"}')

        assert target.read_text() == '{"token": "secret"}'
        # No temp files left behind.
        assert list(tmp_path.iterdir()) == [target]

        if sys.platform != "win32":
            mode = stat.S_IMODE(os.stat(target).st_mode)
            assert mode == 0o600, f"expected 0600, got {mode:o}"

    def test_concurrent_writers_do_not_collide(self, tmp_path: Path) -> None:
        """Regression: writers previously shared one fixed .tmp filename."""
        import threading

        target = tmp_path / "session.json"
        errors: list[BaseException] = []

        def write(n: int) -> None:
            try:
                for _ in range(20):
                    _write_private(target, json.dumps({"n": n}))
            except BaseException as exc:  # noqa: BLE001 - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=write, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert json.loads(target.read_text())  # intact, not truncated
        assert list(tmp_path.iterdir()) == [target]

    def test_expired_cache_is_ignored(self, tmp_path: Path, expired_token: str) -> None:
        path = tmp_path / "session.json"
        save_session(Session(expired_token, "1", "U", "a@b.c"), path)
        assert load_cached_session(path) is None

    def test_unreadable_cache_is_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "session.json"
        path.write_text("{ not json")
        assert load_cached_session(path) is None


class TestAccountMatching:
    """Regression: a cached session was reused across different accounts."""

    def test_rejects_session_from_another_account(self, settings: Settings, valid_token: str) -> None:
        other = Session(valid_token, "1", "U", "someone-else@example.com")
        assert not _matches_configured_account(other, settings)

    def test_accepts_matching_account_case_insensitively(
        self, settings: Settings, valid_token: str
    ) -> None:
        same = Session(valid_token, "1", "U", "USER@Example.COM")
        assert _matches_configured_account(same, settings)

    def test_resolve_session_ignores_other_accounts_cache(
        self, settings: Settings, valid_token: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        save_session(Session(valid_token, "999", "Other", "other@example.com"), settings.session_file)

        logins: list[str] = []

        def fake_login(email: str, password: str, **_: object) -> Session:
            logins.append(email)
            return Session(make_jwt(), "10313492", "Tester", email)

        monkeypatch.setattr(auth, "login", fake_login)
        resolved = resolve_session(settings)

        assert logins == ["user@example.com"], "should re-login, not reuse the other account"
        assert resolved.email == "user@example.com"


class TestResolveSession:
    def test_expired_explicit_token_triggers_login(
        self, settings: Settings, expired_token: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: an expired --token was used even with credentials available."""
        fresh = make_jwt()
        monkeypatch.setattr(
            auth, "login", lambda e, p, **k: Session(fresh, "10313492", "Tester", e)
        )
        resolved = resolve_session(settings.with_overrides(token=expired_token))
        assert resolved.token == fresh

    def test_expired_token_kept_when_no_credentials(self, tmp_path: Path, expired_token: str) -> None:
        # Nothing better is available; the API error is clearer than a config error.
        only_token = Settings(token=expired_token, session_file=tmp_path / "s.json")
        assert resolve_session(only_token).token == expired_token

    def test_requires_some_credential(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            resolve_session(Settings(session_file=tmp_path / "s.json"))

    def test_persist_session_false_writes_nothing(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: multi-tenant serving persisted each tenant's JWT to a
        shared, process-wide file."""
        monkeypatch.setattr(
            auth, "login", lambda e, p, **k: Session(make_jwt(), "1", "U", e)
        )
        resolve_session(settings.with_overrides(persist_session=False), force_login=True)
        assert not settings.session_file.exists()

    def test_persist_session_true_still_writes(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            auth, "login", lambda e, p, **k: Session(make_jwt(), "1", "U", e)
        )
        resolve_session(settings, force_login=True)
        assert settings.session_file.exists()
