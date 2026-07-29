"""Sealed credential URLs.

The design property: the URL carries the credentials, encrypted under a key
derived from one server secret. Nothing is stored, so a URL works across
restarts — and a URL sealed with a different secret works nowhere.
"""

from __future__ import annotations

import time

import pytest

from loseit_mcp.sealed import DEFAULT_TTL_DAYS, SealError, UrlSealer

SECRET = b"kJ8x2mQ7vN4pL9wR3tY6uZ1aS5dF0gH8cV7bN2mX"


@pytest.fixture
def sealer() -> UrlSealer:
    return UrlSealer(SECRET)


class TestRoundTrip:
    def test_opens_what_it_sealed(self, sealer: UrlSealer) -> None:
        sealed = sealer.seal("user@example.com", "hunter2", hours_from_gmt=-7)
        opened = sealer.open(sealed)
        assert opened.email == "user@example.com"
        assert opened.password == "hunter2"
        assert opened.hours_from_gmt == -7

    def test_survives_a_fresh_process(self) -> None:
        """The whole point: no state, so a restart changes nothing."""
        sealed = UrlSealer(SECRET).seal("user@example.com", "pw")
        assert UrlSealer(SECRET).open(sealed).email == "user@example.com"

    def test_is_url_safe(self, sealer: UrlSealer) -> None:
        sealed = sealer.seal("user+tag@example.com", "p/a=s&s?w#rd")
        assert all(c.isalnum() or c in "-_" for c in sealed)
        assert sealer.open(sealed).password == "p/a=s&s?w#rd"

    def test_handles_unicode_credentials(self, sealer: UrlSealer) -> None:
        opened = sealer.open(sealer.seal("üser@example.com", "pässwörd✓"))
        assert opened.email == "üser@example.com"
        assert opened.password == "pässwörd✓"

    def test_each_sealing_differs(self, sealer: UrlSealer) -> None:
        """A fresh nonce per seal, so identical credentials don't produce an
        identical URL."""
        seals = {sealer.seal("u@example.com", "pw") for _ in range(50)}
        assert len(seals) == 50

    def test_omitted_timezone_round_trips_as_none(self, sealer: UrlSealer) -> None:
        assert sealer.open(sealer.seal("u@example.com", "pw")).hours_from_gmt is None


class TestSecrecy:
    def test_sealed_url_reveals_nothing(self, sealer: UrlSealer) -> None:
        sealed = sealer.seal("user@example.com", "hunter2")
        assert "user@example.com" not in sealed
        assert "hunter2" not in sealed
        # Not merely encoded.
        import base64

        raw = base64.urlsafe_b64decode(sealed + "=" * (-len(sealed) % 4))
        assert b"hunter2" not in raw
        assert b"user@example.com" not in raw

    def test_a_different_secret_cannot_open_it(self, sealer: UrlSealer) -> None:
        sealed = sealer.seal("user@example.com", "pw")
        with pytest.raises(SealError):
            UrlSealer(b"pQ3zX8vB2nM6kL0jH4gF7dS1aW5eR9tYcJ4kP8nZ").open(sealed)

    def test_rotating_the_secret_invalidates_every_url(self) -> None:
        """This is the revocation story: all-or-nothing, by design."""
        old = UrlSealer(SECRET)
        urls = [old.seal(f"u{i}@example.com", "pw") for i in range(5)]
        rotated = UrlSealer(b"pQ3zX8vB2nM6kL0jH4gF7dS1aW5eR9tYcJ4kP8nZ")
        for url in urls:
            with pytest.raises(SealError):
                rotated.open(url)

    def test_short_secrets_are_refused(self) -> None:
        with pytest.raises(SealError, match="at least"):
            UrlSealer(b"short")


class TestTampering:
    def test_flipping_a_character_is_detected(self, sealer: UrlSealer) -> None:
        sealed = sealer.seal("user@example.com", "pw")
        for index in (5, len(sealed) // 2, len(sealed) - 1):
            original = sealed[index]
            swapped = "A" if original != "A" else "B"
            mutated = sealed[:index] + swapped + sealed[index + 1 :]
            with pytest.raises(SealError):
                sealer.open(mutated)

    @pytest.mark.parametrize(
        "garbage",
        ["", "x", "!!!not base64!!!", "AAAA", "a" * 40, "../../etc/passwd"],
    )
    def test_garbage_is_rejected(self, sealer: UrlSealer, garbage: str) -> None:
        with pytest.raises(SealError):
            sealer.open(garbage)

    def test_truncation_is_rejected(self, sealer: UrlSealer) -> None:
        sealed = sealer.seal("user@example.com", "pw")
        with pytest.raises(SealError):
            sealer.open(sealed[: len(sealed) // 2])

    def test_failures_are_indistinguishable(self, sealer: UrlSealer) -> None:
        """The endpoint must not become an oracle."""
        expired = sealer.seal("u@example.com", "pw", ttl_days=1)
        messages = set()
        for probe in ("garbage", sealer.seal("u@example.com", "pw")[:-4], expired):
            try:
                sealer.open(probe)
            except SealError as exc:
                messages.add(str(exc))
        assert len(messages) == 1, f"messages leak state: {messages}"


class TestExpiry:
    def test_expiry_is_enforced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sealer = UrlSealer(SECRET)
        sealed = sealer.seal("u@example.com", "pw", ttl_days=1)
        assert sealer.open(sealed).email == "u@example.com"

        monkeypatch.setattr(time, "time", lambda: 1e12)
        with pytest.raises(SealError):
            sealer.open(sealed)

    def test_expiry_cannot_be_edited(self, sealer: UrlSealer) -> None:
        """It lives inside the ciphertext, so it is tamper-proof by
        construction — no separate AAD needed."""
        sealed = sealer.seal("u@example.com", "pw", ttl_days=1)
        for index in range(0, len(sealed), 17):
            mutated = sealed[:index] + ("A" if sealed[index] != "A" else "B") + sealed[index + 1 :]
            with pytest.raises(SealError):
                sealer.open(mutated)

    def test_no_ttl_never_expires(self, sealer: UrlSealer) -> None:
        sealed = sealer.seal("u@example.com", "pw", ttl_days=None)
        assert sealer.open(sealed).expires_at is None

    def test_default_ttl_is_applied(self, sealer: UrlSealer) -> None:
        opened = sealer.open(sealer.seal("u@example.com", "pw"))
        assert opened.expires_at is not None
        remaining = (opened.expires_at - time.time()) / 86400
        assert DEFAULT_TTL_DAYS - 1 < remaining <= DEFAULT_TTL_DAYS


class TestValidation:
    @pytest.mark.parametrize("email,password", [("", "pw"), ("u@example.com", ""), ("", "")])
    def test_blank_credentials_are_refused(
        self, sealer: UrlSealer, email: str, password: str
    ) -> None:
        with pytest.raises(SealError):
            sealer.seal(email, password)

    def test_url_length_stays_reasonable(self, sealer: UrlSealer) -> None:
        """Sealed URLs go in client config files; keep them manageable."""
        sealed = sealer.seal("a-fairly-long-address@example.com", "a" * 64)
        assert len(sealed) < 512
