"""Session cache.

The load-bearing property: the cache key includes the password. Keying on email
alone would hand anyone who knows an address that user's live session.
"""

from __future__ import annotations

import threading
import time

from loseit_mcp.auth import Session
from loseit_mcp.tokencache import TokenCache, session_expiry
from tests.conftest import make_jwt


def _session(email: str = "u@example.com", exp_offset: int = 14 * 86400) -> Session:
    return Session(make_jwt(exp_offset=exp_offset), "1", "U", email)


class TestKeyDerivation:
    def test_wrong_password_cannot_reach_a_cached_session(self) -> None:
        """This is the auth-bypass guard. If it ever fails, anyone knowing an
        email address can impersonate that user."""
        cache = TokenCache(secret=b"s")
        cache.put("u@example.com", "right-password", _session())

        assert cache.get("u@example.com", "right-password") is not None
        assert cache.get("u@example.com", "wrong-password") is None

    def test_other_accounts_cannot_reach_it_either(self) -> None:
        cache = TokenCache(secret=b"s")
        cache.put("u@example.com", "pw", _session())
        assert cache.get("someone-else@example.com", "pw") is None

    def test_email_matching_is_case_and_space_insensitive(self) -> None:
        cache = TokenCache(secret=b"s")
        cache.put("User@Example.com", "pw", _session())
        assert cache.get("  user@example.com  ", "pw") is not None

    def test_passwords_are_matched_exactly(self) -> None:
        cache = TokenCache(secret=b"s")
        cache.put("u@example.com", "PassWord", _session())
        assert cache.get("u@example.com", "password") is None

    def test_a_different_server_secret_yields_a_different_key(self) -> None:
        a, b = TokenCache(secret=b"one"), TokenCache(secret=b"two")
        assert a.key_for("u@example.com", "pw") != b.key_for("u@example.com", "pw")

    def test_key_reveals_neither_email_nor_password(self) -> None:
        key = TokenCache(secret=b"s").key_for("u@example.com", "hunter2")
        assert "u@example.com" not in key
        assert "hunter2" not in key


class TestExpiry:
    def test_expiry_comes_from_the_jwt(self) -> None:
        expires = session_expiry(_session(exp_offset=3600))
        assert 3500 < expires - time.time() < 3700

    def test_unreadable_token_falls_back_to_an_hour(self) -> None:
        expires = session_expiry(Session("not-a-jwt", "1", "U", "u@example.com"))
        assert 3500 < expires - time.time() < 3700

    def test_expired_entries_are_not_served(self) -> None:
        cache = TokenCache(secret=b"s")
        cache.put("u@example.com", "pw", _session(exp_offset=-10))
        assert cache.get("u@example.com", "pw") is None

    def test_leeway_retires_a_session_before_it_actually_dies(self) -> None:
        """So a token can't expire mid-request."""
        cache = TokenCache(secret=b"s", leeway_seconds=600)
        cache.put("u@example.com", "pw", _session(exp_offset=300))
        assert cache.get("u@example.com", "pw") is None

    def test_invalidate_drops_an_entry(self) -> None:
        cache = TokenCache(secret=b"s")
        cache.put("u@example.com", "pw", _session())
        cache.invalidate("u@example.com", "pw")
        assert cache.get("u@example.com", "pw") is None

    def test_put_replaces_an_existing_entry(self) -> None:
        cache = TokenCache(secret=b"s")
        cache.put("u@example.com", "pw", _session())
        fresh = _session()
        cache.put("u@example.com", "pw", fresh)
        assert cache.get("u@example.com", "pw").token == fresh.token
        assert cache.stats()["entries"] == 1


class TestBounding:
    def test_entry_count_stays_within_the_cap(self) -> None:
        """A hostile caller must not be able to grow the cache without limit."""
        cache = TokenCache(secret=b"s", max_entries=10)
        for i in range(100):
            cache.put(f"u{i}@example.com", "pw", _session())
        assert cache.stats()["entries"] <= 10

    def test_expired_entries_are_reclaimed_first(self) -> None:
        cache = TokenCache(secret=b"s", max_entries=5)
        for i in range(4):
            cache.put(f"dead{i}@example.com", "pw", _session(exp_offset=-10))
        live = _session()
        cache.put("live@example.com", "pw", live)
        cache.put("another@example.com", "pw", _session())
        assert cache.get("live@example.com", "pw") is not None


class TestConcurrency:
    def test_is_safe_under_concurrent_use(self) -> None:
        cache = TokenCache(secret=b"s", max_entries=50)
        errors: list[BaseException] = []

        def hammer(n: int) -> None:
            try:
                for i in range(100):
                    email = f"u{(n * 100 + i) % 60}@example.com"
                    cache.put(email, "pw", _session(email))
                    cache.get(email, "pw")
            except BaseException as exc:  # noqa: BLE001 - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert cache.stats()["entries"] <= 50
