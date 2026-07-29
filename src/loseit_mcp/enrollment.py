"""URL-token enrollment: credentials behind an opaque, revocable handle.

Some MCP clients can only be pointed at a URL — they have no way to attach
credentials to a request. For those, a user enrolls once and receives a
personal URL:

    https://host/u/<token>/mcp

The token is not the credentials. It is 256 bits of randomness that maps to
them server-side.

**The token is also the decryption key.** We store an HMAC of it (to look the
record up) and the credentials encrypted under a key derived from it — but
never the token itself. The server can therefore only decrypt a user's
credentials while it is holding a request that carries their token: a stolen
database is inert on its own.

The URL is a bearer credential and URLs get logged, so treat it as a secret,
give it an expiry, and revoke it if it leaks. Revoking is cheap and does not
touch the user's actual Lose It! password.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .auth import _write_private  # reuse the 0600 + Windows-ACL writer

TOKEN_BYTES = 32
_KEY_INFO = b"loseit-mcp/enrollment/v1"
DEFAULT_TTL_DAYS = 90
MAX_LABEL_LENGTH = 128
DEFAULT_MAX_RECORDS = 1000


class EnrollmentError(RuntimeError):
    """The enrollment token is unknown, expired, or undecryptable."""


def new_token() -> str:
    """A fresh URL-safe enrollment token."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def _derive_key(token: str, salt: bytes) -> bytes:
    """Derive the record's AES key from the token itself."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_KEY_INFO,
    ).derive(token.encode("utf-8"))


def _aad(lookup_id: str, created_at: float, expires_at: float | None) -> bytes:
    """Additional authenticated data binding the record's plaintext metadata.

    Without this, ``expires_at`` is an unauthenticated JSON field: anyone with
    write access to the store could set it to ``null`` and resurrect an
    enrollment whose TTL had lapsed — precisely the case the TTL exists to
    close. Binding it to the ciphertext makes such an edit fail decryption.
    """
    return json.dumps(
        {"lookup_id": lookup_id, "created_at": created_at, "expires_at": expires_at},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass
class EnrollmentRecord:
    """One enrolled account. Contains no plaintext credential and no token."""

    lookup_id: str
    salt: str
    nonce: str
    ciphertext: str
    created_at: float
    expires_at: float | None = None
    label: str = ""

    def is_expired(self, now: float | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now or time.time()) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EnrollmentStore(Protocol):
    """Persistence for enrollment records."""

    def get(self, lookup_id: str) -> EnrollmentRecord | None: ...
    def put(self, record: EnrollmentRecord) -> None: ...
    def delete(self, lookup_id: str) -> bool: ...
    def purge_expired(self) -> int: ...
    def count(self) -> int: ...


class FileEnrollmentStore:
    """JSON-file store, written owner-only, with an in-memory index.

    Adequate for a single instance. On Azure App Service put it under ``/home``
    (with ``WEBSITES_ENABLE_APP_SERVICE_STORAGE=true``) so it survives container
    restarts; anything else is ephemeral and users would have to re-enroll.

    The file is parsed only when its mtime/size changes, not on every lookup —
    a read on each MCP tool call would make request latency scale with the
    number of enrolled users.
    """

    def __init__(self, path: Path):
        self._path = path
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any]] = {}
        self._stamp: tuple[float, int] | None = None
        self._loaded = False

    def _stat(self) -> tuple[float, int] | None:
        try:
            st = self._path.stat()
        except OSError:
            return None
        return (st.st_mtime, st.st_size)

    def _load_locked(self) -> dict[str, dict[str, Any]]:
        """Return the store contents, re-reading only when the file changed."""
        stamp = self._stat()
        if self._loaded and stamp == self._stamp:
            return self._cache
        if stamp is None:
            self._cache, self._stamp, self._loaded = {}, None, True
            return self._cache
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        self._cache = data if isinstance(data, dict) else {}
        self._stamp = stamp
        self._loaded = True
        return self._cache

    def _save_locked(self, data: dict[str, dict[str, Any]]) -> None:
        _write_private(self._path, json.dumps(data, indent=2))
        self._cache = data
        self._stamp = self._stat()
        self._loaded = True

    def get(self, lookup_id: str) -> EnrollmentRecord | None:
        with self._lock:
            raw = self._load_locked().get(lookup_id)
        if not raw:
            return None
        try:
            return EnrollmentRecord(**raw)
        except TypeError:
            return None

    def put(self, record: EnrollmentRecord) -> None:
        with self._lock:
            data = dict(self._load_locked())
            data[record.lookup_id] = record.to_dict()
            self._save_locked(data)

    def delete(self, lookup_id: str) -> bool:
        with self._lock:
            data = dict(self._load_locked())
            if lookup_id not in data:
                return False
            del data[lookup_id]
            self._save_locked(data)
            return True

    def purge_expired(self) -> int:
        now = time.time()
        with self._lock:
            data = dict(self._load_locked())
            stale = [
                k
                for k, v in data.items()
                if v.get("expires_at") is not None and v["expires_at"] <= now
            ]
            for key in stale:
                del data[key]
            if stale:
                self._save_locked(data)
            return len(stale)

    def count(self) -> int:
        with self._lock:
            return len(self._load_locked())


class MemoryEnrollmentStore:
    """In-process store. Useful for tests; enrollments die with the process."""

    def __init__(self) -> None:
        self._records: dict[str, EnrollmentRecord] = {}
        self._lock = threading.Lock()

    def get(self, lookup_id: str) -> EnrollmentRecord | None:
        with self._lock:
            return self._records.get(lookup_id)

    def put(self, record: EnrollmentRecord) -> None:
        with self._lock:
            self._records[record.lookup_id] = record

    def delete(self, lookup_id: str) -> bool:
        with self._lock:
            return self._records.pop(lookup_id, None) is not None

    def purge_expired(self) -> int:
        now = time.time()
        with self._lock:
            stale = [k for k, v in self._records.items() if v.is_expired(now)]
            for key in stale:
                del self._records[key]
            return len(stale)

    def count(self) -> int:
        with self._lock:
            return len(self._records)


class EnrollmentRegistry:
    """Issues, resolves, and revokes enrollment tokens."""

    def __init__(
        self,
        store: EnrollmentStore,
        secret: bytes,
        *,
        max_records: int = DEFAULT_MAX_RECORDS,
    ):
        self._store = store
        self._secret = secret
        self._max_records = max_records

    def _lookup_id(self, token: str) -> str:
        return hmac.new(self._secret, token.encode("utf-8"), hashlib.sha256).hexdigest()

    def enroll(
        self,
        email: str,
        password: str,
        *,
        ttl_days: int | None = DEFAULT_TTL_DAYS,
        label: str = "",
        hours_from_gmt: int | None = None,
    ) -> str:
        """Store credentials under a fresh token and return it.

        The token is returned exactly once — it is not recoverable afterwards,
        because nothing derived from it is reversible.
        """
        if not email or not password:
            raise EnrollmentError("Both email and password are required to enroll.")
        if len(label) > MAX_LABEL_LENGTH:
            raise EnrollmentError(f"Label must be at most {MAX_LABEL_LENGTH} characters.")
        if self._max_records and self._store.count() >= self._max_records:
            # Purge first — the cap should only bite on genuinely live records.
            self._store.purge_expired()
            if self._store.count() >= self._max_records:
                raise EnrollmentError("Enrollment store is full.")

        token = new_token()
        salt = os.urandom(16)
        nonce = os.urandom(12)
        payload = json.dumps(
            {"email": email, "password": password, "hours_from_gmt": hours_from_gmt}
        ).encode("utf-8")

        now = time.time()
        expires_at = None if ttl_days is None else now + ttl_days * 86400
        lookup_id = self._lookup_id(token)
        ciphertext = AESGCM(_derive_key(token, salt)).encrypt(
            nonce, payload, _aad(lookup_id, now, expires_at)
        )

        self._store.put(
            EnrollmentRecord(
                lookup_id=lookup_id,
                salt=_b64e(salt),
                nonce=_b64e(nonce),
                ciphertext=_b64e(ciphertext),
                created_at=now,
                expires_at=expires_at,
                label=label,
            )
        )
        return token

    def resolve(self, token: str) -> dict[str, Any]:
        """Decrypt the credentials behind ``token``.

        Raises :class:`EnrollmentError` for unknown, expired, or tampered
        records — all with the same message, so the endpoint can't be used to
        distinguish "no such token" from "wrong token".
        """
        record = self._store.get(self._lookup_id(token))
        if record is None or record.is_expired():
            raise EnrollmentError("Unknown or expired enrollment token.")

        try:
            plaintext = AESGCM(_derive_key(token, _b64d(record.salt))).decrypt(
                _b64d(record.nonce),
                _b64d(record.ciphertext),
                _aad(record.lookup_id, record.created_at, record.expires_at),
            )
            data = json.loads(plaintext)
        except Exception as exc:
            raise EnrollmentError("Unknown or expired enrollment token.") from exc

        if not isinstance(data, dict) or "email" not in data:
            raise EnrollmentError("Unknown or expired enrollment token.")
        return data

    def revoke(self, token: str) -> bool:
        """Delete an enrollment. The user's Lose It! password is unaffected."""
        return self._store.delete(self._lookup_id(token))

    def purge_expired(self) -> int:
        return self._store.purge_expired()

    def count(self) -> int:
        return self._store.count()
