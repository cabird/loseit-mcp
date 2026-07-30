"""The self-service enrollment site.

Two things carry real risk here and get most of the attention: the page must
not leak credentials (to logs, to query strings, or to third parties), and
verifying credentials must not turn ``/enroll`` into a convenient password
guesser.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest import mock

import pytest
from starlette.testclient import TestClient

from loseit_mcp.auth import InvalidCredentialsError, UpstreamUnavailableError
from loseit_mcp.config import Settings
from loseit_mcp.enroll import add_enrollment_route
from loseit_mcp.sealed import SealError, UrlSealer
from loseit_mcp.server import build_server
from loseit_mcp.throttle import Limit, ThrottleMiddleware
from loseit_mcp.webapp import PathTokenMiddleware, install_log_redaction

SECRET = b"kJ8x2mQ7vN4pL9wR3tY6uZ1aS5dF0gH8cV7bN2mX"
EMAIL = "user@example.com"
PASSWORD = "correct horse battery staple"


def _accepts_anything(email: str, password: str) -> None:
    return None


def _rejects_everything(email: str, password: str) -> None:
    raise InvalidCredentialsError("Lose It! rejected the credentials (HTTP 401).")


def _app(
    settings: Settings,
    *,
    verify: Any = _accepts_anything,
    verify_limit: Limit | None = None,
    serve_page: bool = True,
    throttled: bool = False,
) -> Any:
    sealer = UrlSealer(SECRET)
    mcp = build_server(settings, multi_tenant=True, sealer=sealer)
    add_enrollment_route(
        mcp,
        sealer,
        mount_path="/mcp",
        verify=verify,
        verify_limit=verify_limit,
        serve_page=serve_page,
    )
    app = PathTokenMiddleware(mcp.streamable_http_app(streamable_http_path="/mcp"))
    if throttled:
        app = ThrottleMiddleware(
            app,
            enroll_limit=Limit(1000, 3600),
            mcp_limit=Limit(1000, 60),
            credential_limit=Limit(1000, 60),
        )
    return app


def _enroll(client: Any, **overrides: Any) -> Any:
    body = {"email": EMAIL, "password": PASSWORD}
    body.update(overrides)
    return client.post("/enroll", json=body)


class TestCredentialVerification:
    """The reason this endpoint changed: a typo used to produce a URL that
    looked fine and failed on every single tool call."""

    def test_good_credentials_yield_a_url(self, settings: Settings) -> None:
        with TestClient(_app(settings)) as client:
            response = _enroll(client)
            assert response.status_code == 201
            assert response.json()["verified"] is True

    def test_bad_credentials_are_refused(self, settings: Settings) -> None:
        with TestClient(_app(settings, verify=_rejects_everything)) as client:
            response = _enroll(client)
            assert response.status_code == 401
            assert "didn't accept" in response.json()["error"]

    def test_no_url_is_issued_when_verification_fails(self, settings: Settings) -> None:
        with TestClient(_app(settings, verify=_rejects_everything)) as client:
            assert "url" not in _enroll(client).json()

    def test_credentials_are_verified_before_being_sealed(self, settings: Settings) -> None:
        """Order matters: sealing first and verifying second would still hand
        back a working URL if the check were later removed or short-circuited."""
        seen: list[tuple[str, str]] = []

        def record(email: str, password: str) -> None:
            seen.append((email, password))
            raise InvalidCredentialsError("nope")

        with TestClient(_app(settings, verify=record)) as client:
            _enroll(client)
        assert seen == [(EMAIL, PASSWORD)]

    def test_an_outage_is_not_reported_as_a_bad_password(self, settings: Settings) -> None:
        """Telling someone their password is wrong when Lose It is merely down
        sends them off to reset a password that was fine."""

        def unreachable(email: str, password: str) -> None:
            raise UpstreamUnavailableError("Could not reach the Lose It! login endpoint")

        with TestClient(_app(settings, verify=unreachable)) as client:
            response = _enroll(client)
        assert response.status_code == 502
        assert "not with your password" in response.json()["error"]

    def test_verification_can_be_disabled(self, settings: Settings) -> None:
        with TestClient(_app(settings, verify=None)) as client:
            response = _enroll(client)
            assert response.status_code == 201
            assert response.json()["verified"] is False

    def test_the_issued_url_carries_the_supplied_credentials(self, settings: Settings) -> None:
        with TestClient(_app(settings)) as client:
            url = _enroll(client).json()["url"]
        sealed = url.split("/u/")[1].split("/")[0]
        opened = UrlSealer(SECRET).open(sealed)
        assert opened.email == EMAIL
        assert opened.password == PASSWORD


class TestVerificationThrottling:
    """Verification makes /enroll report whether a password is valid. The
    per-email budget is what keeps that from being a useful guessing tool —
    the per-address one cannot, because addresses are cheap to rotate and the
    account under attack is not."""

    def test_repeated_attempts_on_one_email_are_throttled(self, settings: Settings) -> None:
        app = _app(settings, verify=_rejects_everything, verify_limit=Limit(3, 900))
        with TestClient(app) as client:
            codes = [_enroll(client).status_code for _ in range(5)]
        assert codes[:3] == [401, 401, 401]
        assert codes[3:] == [429, 429]

    def test_throttling_survives_address_rotation(self, settings: Settings) -> None:
        """The whole point: a guesser with many source addresses must still be
        stopped by the email budget."""
        app = _app(settings, verify=_rejects_everything, verify_limit=Limit(3, 900), throttled=True)
        with TestClient(app) as client:
            codes = [
                client.post(
                    "/enroll",
                    json={"email": EMAIL, "password": f"guess-{i}"},
                    headers={"X-Forwarded-For": f"203.0.113.{i}"},
                ).status_code
                for i in range(6)
            ]
        assert codes.count(429) == 3, f"address rotation defeated the email budget: {codes}"

    def test_a_different_email_has_its_own_budget(self, settings: Settings) -> None:
        app = _app(settings, verify=_rejects_everything, verify_limit=Limit(2, 900))
        with TestClient(app) as client:
            for _ in range(3):
                _enroll(client)
            other = client.post(
                "/enroll", json={"email": "someone-else@example.com", "password": "pw"}
            )
        assert other.status_code == 401

    def test_case_and_whitespace_do_not_mint_a_fresh_budget(self, settings: Settings) -> None:
        """Otherwise ' User@Example.com ' is an unlimited supply of attempts
        against exactly the same account."""
        app = _app(settings, verify=_rejects_everything, verify_limit=Limit(2, 900))
        variants = [EMAIL, EMAIL.upper(), f"  {EMAIL}  ", EMAIL.capitalize()]
        with TestClient(app) as client:
            codes = [
                client.post("/enroll", json={"email": v, "password": "pw"}).status_code
                for v in variants
            ]
        assert codes[:2] == [401, 401]
        assert codes[2:] == [429, 429]

    def test_the_429_says_when_to_retry(self, settings: Settings) -> None:
        app = _app(settings, verify=_rejects_everything, verify_limit=Limit(1, 900))
        with TestClient(app) as client:
            _enroll(client)
            response = _enroll(client)
        assert response.status_code == 429
        assert int(response.headers["retry-after"]) >= 1

    def test_the_budget_is_spent_before_lose_it_is_contacted(self, settings: Settings) -> None:
        """A throttled attempt must not reach upstream, or the limiter would
        merely be relaying the flood rather than stopping it."""
        attempts: list[str] = []

        def counting(email: str, password: str) -> None:
            attempts.append(password)
            raise InvalidCredentialsError("nope")

        app = _app(settings, verify=counting, verify_limit=Limit(2, 900))
        with TestClient(app) as client:
            for i in range(6):
                client.post("/enroll", json={"email": EMAIL, "password": f"g{i}"})
        assert len(attempts) == 2


class TestEnrollmentPage:
    @pytest.fixture
    def client(self, settings: Settings) -> Any:
        with TestClient(_app(settings)) as c:
            yield c

    def test_the_page_is_served(self, client: Any) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_it_loads_nothing_from_anywhere_else(self, client: Any) -> None:
        """A third-party asset would hand someone else a request log tied to a
        person about to type their Lose It! password."""
        body = client.get("/").text
        for marker in ("http://", "https://", "//cdn", "src=", "@import"):
            assert marker not in body, f"page references something external: {marker}"

    def test_the_policy_forbids_remote_loading(self, client: Any) -> None:
        policy = client.get("/").headers["content-security-policy"]
        assert "default-src 'none'" in policy
        assert "frame-ancestors 'none'" in policy

    def test_the_form_cannot_navigate_and_leak_the_password(self, client: Any) -> None:
        """A native form submit on a GET form would put the password in the
        URL, and therefore in every access log between here and the browser."""
        assert "form-action 'none'" in client.get("/").headers["content-security-policy"]

    def test_the_policy_allows_the_form_to_submit(self, client: Any) -> None:
        """Regression, caught only in a real browser: with `default-src 'none'`
        and no `connect-src`, Chrome blocks the fetch() the form depends on and
        the page silently does nothing when you press the button."""
        policy = client.get("/").headers["content-security-policy"]
        assert "connect-src 'self'" in policy

    def test_the_page_carries_no_inline_style_attributes(self, client: Any) -> None:
        """Regression: a nonce whitelists `<style>` elements but *not*
        `style="..."` attributes, so any inline style is silently dropped and
        the layout quietly degrades."""
        assert 'style="' not in client.get("/").text

    def test_scripts_are_nonced_and_the_nonce_is_fresh_each_time(self, client: Any) -> None:
        first, second = client.get("/"), client.get("/")
        nonce_one = first.headers["content-security-policy"].split("'nonce-")[1].split("'")[0]
        nonce_two = second.headers["content-security-policy"].split("'nonce-")[1].split("'")[0]
        assert nonce_one != nonce_two
        assert f'nonce="{nonce_one}"' in first.text
        assert f'nonce="{nonce_two}"' in second.text

    def test_the_page_is_not_cached(self, client: Any) -> None:
        """A cached copy would pair a stale nonce with a fresh policy and
        silently break every script on the page."""
        assert client.get("/").headers["cache-control"] == "no-store"

    def test_it_tells_people_the_link_is_a_credential(self, client: Any) -> None:
        assert "like a password" in client.get("/").text

    def test_it_explains_the_link_contains_their_credentials(self, client: Any) -> None:
        """The one claim it would be easy to get wrong: the password really is
        in the URL, encrypted. Saying it is 'never stored anywhere' would be a
        lie, and this is the sentence that keeps the page honest."""
        assert "encrypted into your link" in client.get("/").text

    def test_the_page_is_absent_when_not_requested(self, settings: Settings) -> None:
        with TestClient(_app(settings, serve_page=False)) as client:
            assert client.get("/").status_code == 404


class TestExpiryIsNotAUserDecision:
    """The page no longer asks people how long their link should live.

    It is a question a normal person has no basis to answer, and the real
    revocation story is changing the Lose It! password, which invalidates every
    link immediately. The expiry stays in the payload as a backstop, and stays
    settable through the API for anyone who wants it.
    """

    @pytest.fixture
    def client(self, settings: Settings) -> Any:
        with TestClient(_app(settings)) as c:
            yield c

    def test_the_page_does_not_ask_for_a_lifetime(self, client: Any) -> None:
        body = client.get("/").text
        assert "ttl_days" not in body
        assert "expires after" not in body

    def test_the_page_still_says_the_link_expires(self, client: Any) -> None:
        """Dropping the control must not drop the disclosure."""
        assert "It expires in" in client.get("/").text

    def test_enrolling_without_a_lifetime_gets_the_default(self, client: Any) -> None:
        from loseit_mcp.sealed import DEFAULT_TTL_DAYS

        assert _enroll(client).json()["expires_in_days"] == DEFAULT_TTL_DAYS

    def test_the_api_still_accepts_an_explicit_lifetime(self, client: Any) -> None:
        assert _enroll(client, ttl_days=7).json()["expires_in_days"] == 7


class TestExpiredUrlRemedy:
    """An expired link is most likely held by someone who enrolled on the web
    and has never installed the CLI, so the error has to name somewhere they
    can actually go."""

    def test_the_message_names_the_enrollment_page(self) -> None:
        sealer = UrlSealer(SECRET, enroll_url="https://example.invalid/")
        stale = UrlSealer(b"pQ3zX8vB2nM6kL0jH4gF7dS1aW5eR9tYcJ4kP8nZ").seal(EMAIL, PASSWORD)
        with pytest.raises(SealError) as caught:
            sealer.open(stale)
        message = str(caught.value)
        assert "https://example.invalid/" in message
        assert "loseit-mcp enroll" not in message, "sent a web user to a CLI they don't have"

    def test_an_expired_url_gets_the_same_remedy(self) -> None:
        sealer = UrlSealer(SECRET, enroll_url="https://example.invalid/")
        expired = sealer.seal(EMAIL, PASSWORD, ttl_days=None)
        # Seal with an expiry already in the past.
        past = UrlSealer(SECRET, enroll_url="https://example.invalid/")
        with mock.patch("loseit_mcp.sealed.time.time", return_value=0.0):
            expired = past.seal(EMAIL, PASSWORD, ttl_days=1)
        with pytest.raises(SealError) as caught:
            sealer.open(expired)
        assert "https://example.invalid/" in str(caught.value)

    def test_the_message_is_still_identical_for_every_failure(self) -> None:
        """Naming the remedy must not turn the error into an oracle that
        distinguishes expiry from tampering from a rotated secret."""
        sealer = UrlSealer(SECRET, enroll_url="https://example.invalid/")
        good = sealer.seal(EMAIL, PASSWORD)
        wrong_secret = UrlSealer(b"pQ3zX8vB2nM6kL0jH4gF7dS1aW5eR9tYcJ4kP8nZ").seal(EMAIL, PASSWORD)
        with mock.patch("loseit_mcp.sealed.time.time", return_value=0.0):
            expired = sealer.seal(EMAIL, PASSWORD, ttl_days=1)

        messages = set()
        for bad in (wrong_secret, expired, good[:-4], good + "AAAA", "not-base64!!"):
            with pytest.raises(SealError) as caught:
                sealer.open(bad)
            messages.add(str(caught.value))
        assert len(messages) == 1, "the error distinguishes failure modes"

    def test_without_a_configured_url_it_stays_generic(self) -> None:
        sealer = UrlSealer(SECRET)
        stale = UrlSealer(b"pQ3zX8vB2nM6kL0jH4gF7dS1aW5eR9tYcJ4kP8nZ").seal(EMAIL, PASSWORD)
        with pytest.raises(SealError) as caught:
            sealer.open(stale)
        assert "enrollment page" in str(caught.value)


class TestPublicEnrollUrlDiscovery:
    """The hostname is derived at runtime rather than hardcoded, so no
    particular deployment's address ends up in the source."""

    def test_it_uses_the_app_service_hostname(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from loseit_mcp.cli import _public_enroll_url

        monkeypatch.delenv("LOSEIT_PUBLIC_URL", raising=False)
        monkeypatch.setenv("WEBSITE_HOSTNAME", "example.azurewebsites.net")
        assert _public_enroll_url() == "https://example.azurewebsites.net/"

    def test_an_explicit_override_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from loseit_mcp.cli import _public_enroll_url

        monkeypatch.setenv("WEBSITE_HOSTNAME", "example.azurewebsites.net")
        monkeypatch.setenv("LOSEIT_PUBLIC_URL", "https://diary.example.com")
        assert _public_enroll_url() == "https://diary.example.com/"

    def test_it_falls_back_to_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from loseit_mcp.cli import _public_enroll_url

        monkeypatch.delenv("LOSEIT_PUBLIC_URL", raising=False)
        monkeypatch.delenv("WEBSITE_HOSTNAME", raising=False)
        assert _public_enroll_url() is None

    def test_no_real_deployment_hostname_is_hardcoded(self) -> None:
        """Guards the rule that a specific deployment's address stays out of
        the repo.

        Generic examples are fine and necessary — this only objects to a
        hostname that looks like somebody's actual instance rather than a
        placeholder.
        """
        import pathlib
        import re

        pattern = re.compile(r"([A-Za-z0-9<>-]+)\.azurewebsites\.net")
        offenders: list[str] = []
        for path in pathlib.Path("src/loseit_mcp").rglob("*.py"):
            for label in pattern.findall(path.read_text(encoding="utf-8")):
                placeholder = (
                    label.startswith("my-") or "example" in label or "<" in label
                )
                if not placeholder:
                    offenders.append(f"{path}: {label}.azurewebsites.net")
        assert not offenders, f"real-looking hostname in source: {offenders}"


class TestDeployedWiring:
    """The serving path must actually enable verification and the page.

    Everything else here tests `add_enrollment_route` directly, which would
    keep passing if `cli.py` stopped passing `verify=` — exactly the shape of
    gap that let an unenforced control ship once already.
    """

    def _captured_kwargs(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        import argparse

        import uvicorn

        from loseit_mcp import cli
        from loseit_mcp import enroll as enroll_module

        captured: dict[str, Any] = {}

        def fake_add(mcp: Any, sealer: Any, **kwargs: Any) -> None:
            captured.update(kwargs)

        monkeypatch.setattr(enroll_module, "add_enrollment_route", fake_add)
        monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
        monkeypatch.setenv("LOSEIT_ENROLLMENT", "1")
        monkeypatch.setenv("LOSEIT_URL_SECRET", SECRET.decode())

        args = argparse.Namespace(
            transport="streamable-http",
            multi_tenant=True,
            host="127.0.0.1",
            port=8000,
            path="/mcp",
        )
        cli._run_serve(args, Settings())
        return captured

    def test_serving_verifies_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from loseit_mcp.enroll import verify_credentials

        assert self._captured_kwargs(monkeypatch)["verify"] is verify_credentials

    def test_serving_enables_the_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert self._captured_kwargs(monkeypatch)["serve_page"] is True

    def test_serving_sets_a_verification_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        limit = self._captured_kwargs(monkeypatch)["verify_limit"]
        assert limit is not None
        assert limit.capacity > 0


class TestCredentialsStayOutOfLogs:
    def test_the_password_is_never_logged(
        self, settings: Settings, caplog: pytest.LogCaptureFixture
    ) -> None:
        install_log_redaction()
        with caplog.at_level(logging.DEBUG), TestClient(_app(settings)) as client:
            _enroll(client)
        combined = "\n".join(record.getMessage() for record in caplog.records)
        assert PASSWORD not in combined

    def test_the_issued_url_is_redacted_in_logs(
        self, settings: Settings, caplog: pytest.LogCaptureFixture
    ) -> None:
        install_log_redaction()
        with TestClient(_app(settings)) as client:
            url = _enroll(client).json()["url"]
        sealed = url.split("/u/")[1].split("/")[0]

        logger = logging.getLogger("uvicorn.access")
        with caplog.at_level(logging.INFO):
            logger.info('"POST /u/%s/mcp HTTP/1.1" 200', sealed)
        combined = "\n".join(record.getMessage() for record in caplog.records)
        assert sealed not in combined
        assert "<redacted>" in combined


class TestBodyLimit:
    def test_an_oversized_body_is_refused(self, settings: Settings) -> None:
        with TestClient(_app(settings)) as client:
            response = client.post(
                "/enroll",
                content=b'{"email":"' + b"a" * (128 * 1024) + b'"}',
                headers={"content-type": "application/json"},
            )
        assert response.status_code == 413

    def test_a_normal_body_still_works(self, settings: Settings) -> None:
        with TestClient(_app(settings)) as client:
            assert _enroll(client).status_code == 201
