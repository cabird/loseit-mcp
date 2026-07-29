"""Layered configuration for the Lose It! MCP server.

Credentials and settings resolve in priority order (highest first):

1. Explicit arguments (CLI flags)
2. Environment variables (``LOSEIT_*``)
3. A ``.env`` file in the working directory
4. A JSON config file (``--config``, else ``~/.config/loseit-mcp/config.json``)
5. Built-in defaults

Only the credential needs to come from one of these; everything else has a
sensible default. Supply either ``email`` + ``password`` (the server logs in
for you) or a pre-obtained ``token`` (the ``liauth`` JWT).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

CONFIG_DIR = Path.home() / ".config" / "loseit-mcp"
DEFAULT_CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_SESSION_FILE = CONFIG_DIR / "session.json"

# Tied to the current Lose It! web build. Override if they ship a new one and
# the RPCs start failing.
DEFAULT_STRONG_NAME = "351AE5DC0CA36AD3BA9C7CBA7B0E07B8"
DEFAULT_POLICY_HASH = "8F87EC8969F17AE77B6283D3A83F6D4C"
DEFAULT_BASE_URL = "https://d3hsih69yn4d89.cloudfront.net/web/"

LOGIN_URL = "https://api.loseit.com/account/login"


class ConfigError(RuntimeError):
    """Configuration is missing or inconsistent."""


def _detect_hours_from_gmt() -> int:
    """Local UTC offset in whole hours, DST-aware."""
    offset = datetime.now().astimezone().utcoffset()
    return 0 if offset is None else round(offset.total_seconds() / 3600)


@dataclass(frozen=True)
class Settings:
    """Resolved configuration."""

    email: str | None = None
    password: str | None = None
    token: str | None = None

    user_id: str | None = None
    user_name: str | None = None
    hours_from_gmt: int | None = None

    strong_name: str = DEFAULT_STRONG_NAME
    policy_hash: str = DEFAULT_POLICY_HASH
    base_url: str = DEFAULT_BASE_URL

    session_file: Path = DEFAULT_SESSION_FILE

    # Whether a resolved session may be written to (and read from) the on-disk
    # cache. Must be False in multi-tenant serving: the path is process-wide,
    # so tenants would otherwise persist their live JWTs to a shared file,
    # clobbering each other and defeating encryption-at-rest for enrollments.
    persist_session: bool = True

    def with_overrides(self, **kwargs: Any) -> Settings:
        """Return a copy with non-``None`` keyword arguments applied."""
        clean = {k: v for k, v in kwargs.items() if v is not None}
        return replace(self, **clean) if clean else self

    @property
    def has_credentials(self) -> bool:
        return bool(self.token) or bool(self.email and self.password)

    def require_credentials(self) -> None:
        if not self.has_credentials:
            raise ConfigError(
                "No Lose It! credentials. Supply --email/--password, set "
                "LOSEIT_EMAIL/LOSEIT_PASSWORD (env or .env), or provide a "
                "token via --token / LOSEIT_TOKEN."
            )

    def redacted(self) -> dict[str, Any]:
        """A dict safe to log or print — secrets replaced with a marker."""

        def mask(v: str | None) -> str | None:
            if not v:
                return None
            return f"<set: {len(v)} chars>"

        return {
            "email": self.email,
            "password": mask(self.password),
            "token": mask(self.token),
            "user_id": self.user_id,
            "user_name": self.user_name,
            "hours_from_gmt": self.hours_from_gmt,
            "strong_name": self.strong_name,
            "base_url": self.base_url,
            "session_file": str(self.session_file),
        }


def _from_config_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Could not read config file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {path} must contain a JSON object")
    return data


def _from_env() -> dict[str, Any]:
    raw = {
        "email": os.environ.get("LOSEIT_EMAIL"),
        "password": os.environ.get("LOSEIT_PASSWORD"),
        "token": os.environ.get("LOSEIT_TOKEN"),
        "user_id": os.environ.get("LOSEIT_USER_ID"),
        "user_name": os.environ.get("LOSEIT_USER_NAME"),
        "hours_from_gmt": os.environ.get("LOSEIT_HOURS_FROM_GMT"),
        "strong_name": os.environ.get("LOSEIT_STRONG_NAME"),
        "policy_hash": os.environ.get("LOSEIT_POLICY_HASH"),
        "base_url": os.environ.get("LOSEIT_BASE_URL"),
        "session_file": os.environ.get("LOSEIT_SESSION_PATH"),
    }
    return {k: v for k, v in raw.items() if v not in (None, "")}


def _coerce(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize types coming from JSON/env (which are strings)."""
    out = dict(data)
    if "hours_from_gmt" in out and out["hours_from_gmt"] is not None:
        out["hours_from_gmt"] = int(out["hours_from_gmt"])
    if "user_id" in out and out["user_id"] is not None:
        out["user_id"] = str(out["user_id"])
    if "session_file" in out and out["session_file"] is not None:
        out["session_file"] = Path(out["session_file"]).expanduser()
    # Ignore unknown keys rather than exploding on a stale config file.
    allowed = set(Settings.__dataclass_fields__)
    return {k: v for k, v in out.items() if k in allowed}


def load_settings(
    *,
    config_file: Path | None = None,
    env_file: Path | None = None,
    **overrides: Any,
) -> Settings:
    """Resolve settings from all layers.

    ``overrides`` (typically CLI flags) win over everything. ``None`` values in
    ``overrides`` are ignored so unset flags don't clobber lower layers.
    """
    # `.env` is loaded into the environment but never overrides a real env var.
    load_dotenv(dotenv_path=env_file, override=False)

    path = config_file or DEFAULT_CONFIG_FILE
    layered: dict[str, Any] = {}
    layered.update(_coerce(_from_config_file(path)))
    layered.update(_coerce(_from_env()))
    layered.update(_coerce({k: v for k, v in overrides.items() if v is not None}))

    settings = Settings(**layered)
    if settings.hours_from_gmt is None:
        settings = replace(settings, hours_from_gmt=_detect_hours_from_gmt())
    return settings
