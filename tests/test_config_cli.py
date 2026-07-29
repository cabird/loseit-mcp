"""Configuration layering and CLI behaviour."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from loseit_mcp.cli import _print_logged, build_parser
from loseit_mcp.config import ConfigError, Settings, load_settings


class TestSettings:
    def test_overrides_ignore_none(self) -> None:
        base = Settings(email="a@b.c", password="pw")
        assert base.with_overrides(email=None).email == "a@b.c"
        assert base.with_overrides(email="x@y.z").email == "x@y.z"

    def test_requires_a_credential(self) -> None:
        with pytest.raises(ConfigError):
            Settings().require_credentials()

    def test_token_alone_is_enough(self) -> None:
        Settings(token="a.b.c").require_credentials()

    def test_email_without_password_is_not(self) -> None:
        with pytest.raises(ConfigError):
            Settings(email="a@b.c").require_credentials()

    def test_redaction_hides_secrets(self) -> None:
        shown = Settings(email="a@b.c", password="hunter2", token="a.b.c").redacted()
        assert shown["email"] == "a@b.c"
        assert "hunter2" not in str(shown)
        assert "a.b.c" not in str(shown["token"])


class TestLayering:
    def test_explicit_arguments_beat_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LOSEIT_EMAIL", "env@example.com")
        resolved = load_settings(
            config_file=tmp_path / "none.json",
            env_file=tmp_path / "none.env",
            email="explicit@example.com",
        )
        assert resolved.email == "explicit@example.com"

    def test_environment_beats_the_config_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = tmp_path / "config.json"
        config.write_text(json.dumps({"email": "file@example.com"}))
        monkeypatch.setenv("LOSEIT_EMAIL", "env@example.com")
        assert load_settings(config_file=config, env_file=tmp_path / "n.env").email == (
            "env@example.com"
        )

    def test_config_file_is_used_when_nothing_else_sets_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("LOSEIT_EMAIL", raising=False)
        config = tmp_path / "config.json"
        config.write_text(json.dumps({"email": "file@example.com"}))
        assert load_settings(config_file=config, env_file=tmp_path / "n.env").email == (
            "file@example.com"
        )

    def test_numeric_settings_are_coerced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LOSEIT_HOURS_FROM_GMT", "-7")
        resolved = load_settings(config_file=tmp_path / "n.json", env_file=tmp_path / "n.env")
        assert resolved.hours_from_gmt == -7

    def test_timezone_is_detected_when_unset(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("LOSEIT_HOURS_FROM_GMT", raising=False)
        resolved = load_settings(config_file=tmp_path / "n.json", env_file=tmp_path / "n.env")
        assert resolved.hours_from_gmt is not None
        assert -12 <= resolved.hours_from_gmt <= 14

    def test_unknown_config_keys_are_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stale config file must not crash startup."""
        monkeypatch.delenv("LOSEIT_EMAIL", raising=False)
        config = tmp_path / "config.json"
        config.write_text(json.dumps({"email": "a@b.c", "removed_setting": 1}))
        assert load_settings(config_file=config, env_file=tmp_path / "n.env").email == "a@b.c"

    def test_malformed_config_file_raises_clearly(self, tmp_path: Path) -> None:
        config = tmp_path / "config.json"
        config.write_text("{ not json")
        with pytest.raises(ConfigError):
            load_settings(config_file=config, env_file=tmp_path / "n.env")


class TestParser:
    def test_serve_defaults_to_stdio(self) -> None:
        assert build_parser().parse_args(["serve"]).transport == "stdio"

    def test_accepts_http_transports(self) -> None:
        args = build_parser().parse_args(
            ["serve", "--transport", "streamable-http", "--port", "9000"]
        )
        assert args.transport == "streamable-http"
        assert args.port == 9000

    def test_log_accepts_a_portion(self) -> None:
        args = build_parser().parse_args(["log", "abc", "-m", "lunch", "-a", "120", "-u", "g"])
        assert (args.meal, args.amount, args.unit) == ("lunch", 120.0, "g")

    def test_rejects_an_unknown_meal(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["log", "abc", "-m", "brunch"])

    def test_requires_a_subcommand(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args([])


class TestPrinting:
    def test_missing_calories_does_not_crash(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Regression: this raised a TypeError *after* the write had already
        succeeded, inviting the user to retry and double-log."""
        _print_logged(
            {
                "dry_run": False,
                "food": {"name": "Arugula"},
                "portion_size": 1,
                "measure_unit": "cup",
                "meal": "lunch",
                "date": "2026-07-28",
                "calories": None,
            }
        )
        out = capsys.readouterr().out
        assert "Arugula" in out
        assert "cal" not in out, "no calorie suffix when the food has no calorie data"

    def test_calories_are_shown_when_present(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_logged(
            {
                "dry_run": True,
                "food": {"name": "Banana"},
                "portion_size": 1,
                "measure_unit": "each",
                "meal": "breakfast",
                "date": "2026-07-28",
                "calories": 105.0,
            }
        )
        out = capsys.readouterr().out
        assert "105 cal" in out
        assert "DRY RUN" in out
