"""Named-zone compatibility, request isolation and calendar boundaries.

All credentials and RPCs are synthetic; these tests never contact Lose It!.
"""

import json
from datetime import UTC, date, datetime
from types import SimpleNamespace
from unittest.mock import Mock
from zoneinfo import ZoneInfoNotFoundError

import httpx
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from starlette.testclient import TestClient

from loseit_mcp import service as service_module
from loseit_mcp import tenancy, timezones
from loseit_mcp.cli import build_parser
from loseit_mcp.config import ConfigError, Settings, load_settings
from loseit_mcp.enroll_client import EnrollClientError, enroll
from loseit_mcp.sealed import _NONCE_BYTES, _VERSION, UrlSealer, _b64d
from loseit_mcp.service import LoseItService, _parse_date
from loseit_mcp.tenancy import (
    Credentials,
    CredentialsError,
    SessionResolver,
    credentials_from_request,
)
from loseit_mcp.webapp import _path_token
from tests.test_enroll_site import _app, _enroll

ZONE = "America/Los_Angeles"
SECRET = b"kJ8x2mQ7vN4pL9wR3tY6uZ1aS5dF0gH8cV7bN2mX"


class Clock(datetime):
    instant = datetime(2027, 1, 15, 12, tzinfo=UTC)

    @classmethod
    def now(cls, tz=None):
        return cls.instant.astimezone(tz) if tz else cls.instant.replace(tzinfo=None)


@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(timezones, "datetime", Clock)
    monkeypatch.setattr(Clock, "instant", datetime(2027, 1, 15, 12, tzinfo=UTC))
    return Clock


@pytest.mark.parametrize(
    "instant,today,yesterday,offset",
    [
        ("2027-03-14T07:30:00+00:00", "2027-03-13", "2027-03-12", -8),
        ("2027-03-14T09:59:00+00:00", "2027-03-14", "2027-03-13", -8),
        ("2027-03-14T10:01:00+00:00", "2027-03-14", "2027-03-13", -7),
        ("2027-03-15T07:01:00+00:00", "2027-03-15", "2027-03-14", -7),
        ("2027-11-07T08:59:00+00:00", "2027-11-07", "2027-11-06", -7),
        ("2027-11-07T09:01:00+00:00", "2027-11-07", "2027-11-06", -8),
        ("2027-11-08T08:01:00+00:00", "2027-11-08", "2027-11-07", -8),
    ],
)
def test_relative_dates_across_dst_and_midnight(clock, instant, today, yesterday, offset):
    clock.instant = datetime.fromisoformat(instant)
    assert _parse_date("today", timezone_name=ZONE) == date.fromisoformat(today)
    assert _parse_date("yesterday", timezone_name=ZONE) == date.fromisoformat(yesterday)
    assert timezones.offset_for(ZONE) == offset


def test_settings_layer_timezone_choice_replaces_lower_layer(tmp_path, monkeypatch):
    for key in ("LOSEIT_TIMEZONE", "LOSEIT_HOURS_FROM_GMT"):
        monkeypatch.delenv(key, raising=False)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"hours_from_gmt": -8}))
    monkeypatch.setenv("LOSEIT_TIMEZONE", ZONE)
    settings = load_settings(config_file=config, env_file=tmp_path / "none.env")
    assert (settings.timezone_name, settings.hours_from_gmt) == (ZONE, None)
    settings = load_settings(config_file=config, env_file=tmp_path / "none.env", hours_from_gmt=0)
    assert (settings.timezone_name, settings.hours_from_gmt) == (None, 0)
    monkeypatch.setenv("LOSEIT_HOURS_FROM_GMT", "-8")
    with pytest.raises(ConfigError, match="not both"):
        load_settings(config_file=config, env_file=tmp_path / "none.env")


@pytest.mark.parametrize(
    "name", ["", "Not/AZone", "../etc/passwd", "Asia/Kolkata", "Asia/Kathmandu"]
)
def test_bad_or_fractional_zones_are_not_rounded(name):
    with pytest.raises(ConfigError):
        Settings(timezone_name=name)


def test_missing_timezone_database_is_explained(monkeypatch):
    def missing(_):
        raise ZoneInfoNotFoundError("missing")

    monkeypatch.setattr(timezones, "ZoneInfo", missing)
    with pytest.raises(ConfigError, match="timezone data"):
        Settings(timezone_name=ZONE)


def test_cli_timezone_flags_are_mutually_exclusive():
    parser = build_parser()
    args = parser.parse_args(["enroll", "https://example.com", "--timezone", ZONE])
    assert args.timezone_name == ZONE
    with pytest.raises(SystemExit):
        parser.parse_args(["enroll", "https://example.com", "--timezone", ZONE, "--tz", "-8"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--timezone", ZONE, "--hours-from-gmt", "-8", "whoami"])


def test_global_timezone_flag_reaches_commands_and_enrollment():
    parser = build_parser()
    assert parser.parse_args(["--timezone", ZONE, "whoami"]).timezone_name == ZONE
    assert (
        parser.parse_args(["--timezone", ZONE, "enroll", "https://example.com"]).timezone_name
        == ZONE
    )


def test_sealed_named_zone_has_legacy_numeric_fallback(clock):
    sealer = UrlSealer(SECRET)
    sealed = sealer.seal("u@example.com", "synthetic", timezone_name=ZONE)
    raw = _b64d(sealed)
    assert raw[:1] == _VERSION
    data = json.loads(
        AESGCM(sealer._key).decrypt(
            raw[1 : 1 + _NONCE_BYTES],
            raw[1 + _NONCE_BYTES :],
            _VERSION,
        )
    )
    # Existing readers only consume e/p/tz/x and ignore additional fields.
    assert (data["e"], data["p"], data["tz"], data["tz_name"]) == (
        "u@example.com",
        "synthetic",
        -8,
        ZONE,
    )
    clock.instant = datetime(2027, 7, 15, 12, tzinfo=UTC)
    opened = sealer.open(sealed)
    assert opened.timezone_name == ZONE
    assert opened.hours_from_gmt == -8  # Rollback fallback, not the live zone offset.
    legacy = sealer.open(sealer.seal("u@example.com", "synthetic", hours_from_gmt=-8))
    assert legacy.timezone_name is None and legacy.hours_from_gmt == -8


@pytest.mark.parametrize(
    "sealed_zone,headers,expected",
    [
        (False, {}, (None, -8)),
        (False, {"x-loseit-timezone": ZONE}, (ZONE, None)),
        (True, {}, (ZONE, None)),
        (True, {"x-loseit-hours-from-gmt": "0"}, (None, 0)),
    ],
)
def test_request_timezone_precedence(sealed_zone, headers, expected):
    sealer = UrlSealer(SECRET)
    options = {"timezone_name": ZONE} if sealed_zone else {"hours_from_gmt": -8}
    reset = _path_token.set(sealer.seal("u@example.com", "synthetic", **options))
    try:
        creds = credentials_from_request(headers, sealer)
        assert (creds.timezone_name, creds.hours_from_gmt) == expected
    finally:
        _path_token.reset(reset)


def test_bad_timezone_headers_do_not_fall_back_to_sealed_credentials():
    sealer = UrlSealer(SECRET)
    reset = _path_token.set(sealer.seal("u@example.com", "synthetic", hours_from_gmt=-8))
    try:
        for headers in [
            {"x-loseit-timezone": "Invalid/Zone"},
            {"x-loseit-timezone": ZONE, "x-loseit-hours-from-gmt": "-8"},
        ]:
            with pytest.raises(CredentialsError):
                credentials_from_request(headers, sealer)
    finally:
        _path_token.reset(reset)


def test_zone_overrides_do_not_change_auth_cache_identity(monkeypatch, session):
    login = Mock(return_value=session)
    monkeypatch.setattr(tenancy, "login", login)
    resolver = SessionResolver(Settings(timezone_name=ZONE))
    legacy = resolver.resolve(Credentials("u@example.com", "synthetic", hours_from_gmt=-8))
    named = resolver.resolve(
        Credentials("u@example.com", "synthetic", timezone_name="Europe/London")
    )
    inherited = resolver.resolve(Credentials("u@example.com", "synthetic"))
    assert login.call_count == 1
    assert legacy._settings.timezone_name is None
    assert named._settings.timezone_name == "Europe/London"
    assert inherited._settings.timezone_name == ZONE
    assert not named._settings.persist_session


@pytest.mark.parametrize(
    "body",
    [
        {"timezone": "Invalid/Zone"},
        {"timezone": "Asia/Kolkata"},
        {"timezone": ZONE, "hours_from_gmt": -8},
        {"timezone": 123},
    ],
)
def test_bad_enrollment_timezone_is_rejected_before_login(settings, body):
    verify = Mock()
    with TestClient(_app(settings, verify=verify)) as client:
        result = _enroll(client, **body)
    assert result.status_code == 400
    verify.assert_not_called()


def test_enrollment_round_trip_for_named_zone(settings):
    with TestClient(_app(settings)) as client:
        result = _enroll(client, timezone=ZONE)
    assert result.status_code == 201
    token = result.json()["url"].split("/u/", 1)[1].split("/mcp", 1)[0]
    assert UrlSealer(SECRET).open(token).timezone_name == ZONE


def test_enroll_client_sends_zone_without_detected_numeric_offset(monkeypatch):
    monkeypatch.setenv("LOSEIT_PASSWORD", "synthetic")

    def post(url, **kwargs):
        assert kwargs["json"]["timezone"] == ZONE
        assert "hours_from_gmt" not in kwargs["json"]
        return httpx.Response(
            201, json={"url": "https://example.com/u/synthetic/mcp", "timezone": ZONE}
        )

    monkeypatch.setattr(httpx, "post", post)
    assert enroll("https://example.com", email="u@example.com", timezone_name=ZONE)["url"]
    with pytest.raises(EnrollClientError, match="not both"):
        enroll("https://example.com", timezone_name=ZONE, tz_offset=-8)


@pytest.fixture
def dated_service(monkeypatch, session):
    clients = []

    class Client:
        def __init__(self, config, token):
            self.http = SimpleNamespace(config=config)
            self.closed = False
            self.days = []
            clients.append(self)

        def diary(self, day):
            self.days.append(day)
            return []

        def log_food(self, ref, **kwargs):
            self.days.append(kwargs["when"])
            return {"food": {}}

        def close(self):
            self.closed = True

    monkeypatch.setattr(service_module, "LoseIt", Client)
    svc = LoseItService(Settings(timezone_name=ZONE))
    svc._session = session
    return svc, clients


@pytest.mark.parametrize("day,offset", [(date(2027, 1, 1), -8), (date(2027, 7, 1), -7)])
def test_dated_diary_and_food_use_target_date_offset(dated_service, monkeypatch, day, offset):
    svc, clients = dated_service
    assert svc.get_diary(day)["date"] == str(day)
    monkeypatch.setattr(svc, "describe_food", lambda _: {"name": "Synthetic"})
    svc.log_food("0" * 32, when=day, dry_run=True)
    assert [c.http.config.hours_from_gmt for c in clients] == [offset, offset]
    assert all(c.closed and c.days == [day] for c in clients)


def test_dated_weight_and_custom_write_use_target_offset(dated_service, monkeypatch):
    svc, clients = dated_service
    seen = []
    monkeypatch.setattr(
        service_module,
        "save_weight",
        lambda http, weight, day: seen.append(http.config.hours_from_gmt) or weight,
    )
    monkeypatch.setattr(service_module, "get_daydate_key", lambda *args: "synthetic-key")
    monkeypatch.setattr(
        service_module._entries,
        "log_food",
        lambda http, *args: seen.append(http.config.hours_from_gmt),
    )
    svc.log_weight(150, date(2027, 1, 1))
    svc.log_custom_food("Synthetic", 10, when=date(2027, 7, 1))
    assert seen == [-8, -7]
    assert all(c.closed for c in clients)


@pytest.mark.parametrize(
    "start,end,expected",
    [
        (
            date(2027, 3, 13),
            date(2027, 3, 15),
            [
                (date(2027, 3, 13), date(2027, 3, 13), -8),
                (date(2027, 3, 14), date(2027, 3, 15), -7),
            ],
        ),
        (
            date(2027, 11, 6),
            date(2027, 11, 8),
            [
                (date(2027, 11, 6), date(2027, 11, 6), -7),
                (date(2027, 11, 7), date(2027, 11, 8), -8),
            ],
        ),
    ],
)
def test_weight_ranges_split_at_offset_change(dated_service, monkeypatch, start, end, expected):
    svc, clients = dated_service
    seen = []

    def history(http, first, last):
        seen.append((first, last, http.config.hours_from_gmt))
        return []

    monkeypatch.setattr(service_module, "_get_weight_history", history)
    assert svc.get_weight_history(start, end)["count"] == 0
    assert seen == expected
    assert all(c.closed for c in clients)


def test_long_lived_service_refreshes_offset_after_dst(clock, dated_service):
    svc, clients = dated_service
    winter = svc.client
    assert winter.http.config.hours_from_gmt == -8
    clock.instant = datetime(2027, 7, 15, 12, tzinfo=UTC)
    summer = svc.client
    assert summer is not winter and summer.http.config.hours_from_gmt == -7
    assert svc.whoami()["timezone_name"] == ZONE
    assert svc.whoami()["hours_from_gmt"] == -7
    svc.close()
    assert all(c.closed for c in clients)


def test_dated_client_closes_on_failure(dated_service):
    svc, clients = dated_service

    def fail(_):
        raise ValueError("synthetic failure")

    with pytest.raises(ValueError):
        svc._with_day(date(2027, 7, 1), fail)
    assert clients[-1].closed


def test_old_enrollment_server_cannot_silently_ignore_named_zone(monkeypatch):
    monkeypatch.setenv("LOSEIT_PASSWORD", "synthetic")
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(
            201,
            json={"url": "https://example.com/u/synthetic/mcp"},
        ),
    )
    with pytest.raises(EnrollClientError, match="did not confirm"):
        enroll("https://example.com", email="u@example.com", timezone_name=ZONE)


def test_fractional_historical_offset_is_rejected_before_rpc(monkeypatch, session):
    build = Mock()
    monkeypatch.setattr(service_module, "LoseIt", build)
    svc = LoseItService(Settings(timezone_name="Europe/Amsterdam"))
    svc._session = session
    with pytest.raises(ValueError, match="fractional"):
        svc.get_diary(date(1930, 1, 1))
    build.assert_not_called()


def test_concurrent_winter_and_summer_requests_do_not_share_offset(dated_service, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    svc, clients = dated_service
    gate = Barrier(2)

    def diary(self, day):
        gate.wait(timeout=5)
        assert self.http.config.hours_from_gmt == (-8 if day.month == 1 else -7)
        return []

    # _build_client creates this same synthetic client type for every request.
    client_type = service_module.LoseIt
    monkeypatch.setattr(client_type, "diary", diary)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(svc.get_diary, date(2027, month, 1)) for month in (1, 7)]
        assert [f.result()["entry_count"] for f in futures] == [0, 0]
    assert len(clients) == 2 and all(c.closed for c in clients)


def test_dated_auth_retry_uses_replacement_session(dated_service, monkeypatch, session):
    from dataclasses import replace

    from lose_it.core._http import LoseItAuthError

    svc, clients = dated_service
    tokens = []
    original = service_module.LoseIt

    def build(config, token):
        client = original(config, token)
        tokens.append(token)

        def diary(day):
            if token == session.token:
                raise LoseItAuthError("expired")
            return []

        client.diary = diary
        return client

    monkeypatch.setattr(service_module, "LoseIt", build)

    def refresh(*args, **kwargs):
        svc._session = replace(session, token="synthetic-replacement")
        svc._generation += 1

    monkeypatch.setattr(svc, "_reauthenticate", refresh)
    assert svc.get_diary(date(2027, 1, 1))["entry_count"] == 0
    assert tokens == [session.token, "synthetic-replacement"]
    assert all(c.closed for c in clients)


@pytest.mark.anyio
async def test_identity_and_status_report_named_zone_without_credentials(monkeypatch, session):
    from loseit_mcp.server import build_server

    monkeypatch.setattr(service_module, "resolve_session", lambda *a, **kw: session)
    monkeypatch.setattr(LoseItService, "search_food", lambda *a, **kw: [])
    server = build_server(Settings(timezone_name=ZONE))
    result = await server.call_tool("server_status", {})
    data = result.structured_content
    assert data["account"]["timezone_name"] == ZONE
    assert data["account"]["hours_from_gmt"] in (-8, -7)
    assert session.token not in json.dumps(data)


@pytest.mark.parametrize("transport", ["credential_url", "basic_header"])
def test_named_zone_over_streamable_http(transport, monkeypatch, session, clock):
    import base64

    from loseit_mcp.server import build_server
    from loseit_mcp.webapp import PathTokenMiddleware

    monkeypatch.setattr(tenancy, "login", lambda *args: session)
    sealer = UrlSealer(SECRET)
    server = build_server(Settings(), multi_tenant=True, sealer=sealer)
    app = PathTokenMiddleware(server.streamable_http_app(json_response=True, stateless_http=True))
    headers = {"accept": "application/json, text/event-stream"}
    if transport == "credential_url":
        token = sealer.seal("u@example.com", "synthetic", timezone_name=ZONE)
        path = f"/u/{token}/mcp"
    else:
        path = "/mcp"
        headers.update(
            {
                "authorization": "Basic " + base64.b64encode(b"u@example.com:synthetic").decode(),
                "x-loseit-timezone": ZONE,
            }
        )
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        result = client.post(
            path,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "timezone-test", "version": "1"},
                },
            },
        )
        assert result.status_code == 200
        headers["MCP-Protocol-Version"] = result.json()["result"]["protocolVersion"]
        result = client.post(
            path,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "whoami", "arguments": {}},
            },
        )
        assert result.status_code == 200
        body = result.json()["result"]
        assert not body.get("isError")
        assert body["structuredContent"]["timezone_name"] == ZONE
        assert body["structuredContent"]["hours_from_gmt"] == -8
