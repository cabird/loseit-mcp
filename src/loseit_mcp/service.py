"""Bridges our authentication onto the upstream ``lose_it`` SDK.

:class:`LoseItService` owns a resolved :class:`~loseit_mcp.auth.Session` and a
configured :class:`lose_it.LoseIt` client, transparently re-authenticating when
the token expires. Every method returns plain JSON-serializable data so the MCP
and CLI layers can hand results straight to a client.
"""

from __future__ import annotations

import concurrent.futures
import logging
import random
import re
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from typing import Any, Self, TypeVar

import httpx
from lose_it import LoseIt, MealType, UnsavedFoodLogEntry
from lose_it.core import entries as _entries
from lose_it.core import foods as _foods
from lose_it.core._config import Config
from lose_it.core._dates import day_number_for
from lose_it.core._http import LoseItAuthError, LoseItError
from lose_it.core._ids import hex_to_pk, pk_to_hex
from lose_it.core.daily import get_daydate_key

from .auth import Session, resolve_session
from .config import Settings
from .observability import current_request_id
from .weight import get_weight_history as _get_weight_history
from .weight import save_weight

_T = TypeVar("_T")

logger = logging.getLogger(__name__)

# Cap on how much of an upstream error reaches the log. GWT envelopes can be
# long and can echo server-side text; the exception *class* and a short prefix
# are what identify a fault, and the rest is not worth the risk of carrying
# something we didn't anticipate into a log aggregator.
_BRIEF_CHARS = 160


def _brief(exc: Exception) -> str:
    """A short, log-safe description of an exception."""
    return f"{type(exc).__name__}: {str(exc)[:_BRIEF_CHARS]}"

# FoodNutrient enum ordinals the server accepts inside a logged entry.
#
# Verified empirically via describe_food (olive oil, butter, peanuts): ordinal
# 3 is total fat, 4 is saturated fat, 2 is serving weight in grams. Note the
# SDK's own `_config.NUTRIENT_NAMES` table disagrees (it labels 2 as fat and 3
# as saturated fat) and is stale.
_NUTRIENT_ORDINALS = {
    "calories": 0,
    "total_fat_g": 3,
    "saturated_fat_g": 4,
    "cholesterol_mg": 8,
    "sodium_mg": 9,
    "carb_g": 10,
    "fiber_g": 11,
    "sugar_g": 12,
    "protein_g": 13,
}

# The SDK's payload builder drops any ordinal outside its own accept-list, so
# some nutrients we accept never reach the wire. We intersect against it when
# reporting results rather than claiming to have logged a value that was
# filtered out in transit. `saturated_fat_g` (ordinal 4) is the one casualty
# today — the server does store it (it comes back on reads), but the SDK will
# not send it.
_SENDABLE_ORDINALS = frozenset(_entries._CORE_NUTRIENT_ORDINALS)
_DROPPED_NUTRIENTS = tuple(
    sorted(name for name, ord_ in _NUTRIENT_ORDINALS.items() if ord_ not in _SENDABLE_ORDINALS)
)


def _random_pk() -> list[int]:
    """A random 16-byte primary key in the signed form the wire format uses."""
    return [b - 256 if b >= 128 else b for b in uuid.uuid4().bytes]


# Lose It reports an expired/invalid token as an HTTP 200 carrying a GWT
# exception envelope, which the SDK surfaces as a plain LoseItError. Only the
# rarer transport-level 401/403 becomes LoseItAuthError, so matching on the
# exception type alone would miss the common case.
_AUTH_FAILURE_MARKERS = (
    "UserAuthenticationFailedException",
    "NotAuthenticatedException",
    "InvalidSessionException",
)


def _is_auth_failure(exc: Exception) -> bool:
    """True if ``exc`` means the credentials/token are no longer good."""
    if isinstance(exc, LoseItAuthError):
        return True
    if isinstance(exc, LoseItError):
        message = str(exc)
        return any(marker in message for marker in _AUTH_FAILURE_MARKERS)
    return False


# Lose It's search endpoint intermittently answers with a bare
# ``java.lang.RuntimeException`` — measured at roughly a third of calls in one
# sitting, on the search RPC specifically and not on food lookups. It carries
# no detail and clears on an immediate retry, so it is a fault on their side
# rather than anything about the request.
#
# Deliberately *not* including IncompatibleRemoteServiceException: that means
# Lose It shipped a new GWT build, which is permanent until an operator
# refreshes the strong name. `errors.translate` says as much in the message it
# produces, so retrying it burns the budget during a total outage to arrive at
# an answer that already said retrying won't help.
_TRANSIENT_MARKERS = (
    "java.lang.RuntimeException",
    "java.lang.NullPointerException",
)

# One budget covering *both* the auth retry and transient retries. Kept
# together on purpose: nesting one loop inside the other multiplies them, and
# an earlier arrangement could reach four real password logins from a single
# read — a plausible route to tripping Lose It's own account protection.
_READ_ATTEMPTS = 4
_TRANSIENT_BACKOFF = 0.3


def _is_transient_upstream(exc: Exception) -> bool:
    """True if ``exc`` is a hiccup that a retry is likely to clear.

    Transport failures count. A connection reset or read timeout between a
    container and a third-party API is the commonest transient fault in a
    hosted deployment, and it is the one class where retrying a read is
    unambiguously safe.
    """
    if isinstance(exc, httpx.TransportError):
        return True
    if not isinstance(exc, LoseItError) or _is_auth_failure(exc):
        return False
    return any(marker in str(exc) for marker in _TRANSIENT_MARKERS)


# The widest weight-history range a single call may request. Lose It! launched
# in 2008, so ten years comfortably covers any real account while keeping the
# worst-case fan-out to roughly seventy upstream requests instead of sixty
# thousand.
MAX_HISTORY_SPAN_DAYS = 3660


# The GWT string table ships non-ASCII and quote characters as literal
# ``\uXXXX`` escapes, and the upstream decoder passes them through verbatim —
# so food names arrive looking like ``Mike\u0027s``. Undo that here.
_GWT_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _unescape(text: str) -> str:
    return _GWT_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


def _parse_date(value: str | date | None, hours_from_gmt: int | None = None) -> date | None:
    """Accept ``None``, a ``date``, ``'today'``/``'yesterday'``, or ISO ``YYYY-MM-DD``.

    Relative names resolve against the *account's* timezone rather than the
    host's. A server in UTC would otherwise roll over to "tomorrow" while the
    user is still having dinner, silently logging food to the wrong day.
    """
    if value is None or isinstance(value, date):
        return value
    text = value.strip().lower()
    if not text or text == "today":
        return account_today(hours_from_gmt)
    if text == "yesterday":
        return account_today(hours_from_gmt) - timedelta(days=1)
    try:
        # A calendar date carries no time or zone of its own; the account
        # offset is applied by the caller where it matters.
        return datetime.strptime(text, "%Y-%m-%d").date()  # noqa: DTZ007
    except ValueError as exc:
        raise ValueError(
            f"Invalid date {value!r}; use YYYY-MM-DD, 'today', or 'yesterday'."
        ) from exc


def account_today(hours_from_gmt: int | None) -> date:
    """Today's date in the account's timezone."""
    if hours_from_gmt is None:
        # No configured offset — the host's local date is the best guess.
        return date.today()  # noqa: DTZ011
    return datetime.now(tz=timezone(timedelta(hours=hours_from_gmt))).date()


class LoseItService:
    """A logged-in Lose It! client with auto-refreshing credentials.

    Instances are safe to share across threads: lifecycle transitions (first
    login, re-authentication, shutdown) are serialized by a lock, and a client
    superseded by re-authentication is closed only once no request is still
    using it — so a re-auth triggered by one caller cannot close a client
    another caller is mid-request on.
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        self._session: Session | None = None
        self._client: LoseIt | None = None
        self._lock = threading.RLock()
        # Requests run outside the lock, so a re-auth can land while another
        # thread is still using the previous client. Superseded clients are
        # parked here and closed once nothing is using them.
        self._inflight = 0
        self._retired: list[LoseIt] = []
        # Bumped on every successful re-login, so concurrent callers that fail
        # against the same dead session don't each mint a replacement.
        self._generation = 0
        # Optional hook so a caller-managed cache can be refreshed when we mint
        # a new session behind its back. Set by the multi-tenant resolver.
        self.on_reauthenticated: Callable[[Session], None] | None = None

    # ── Lifecycle ───────────────────────────────────────────────────────

    @property
    def session(self) -> Session:
        with self._lock:
            if self._session is None:
                self._session = resolve_session(self._settings)
            return self._session

    @property
    def client(self) -> LoseIt:
        with self._lock:
            if self._client is None:
                self._client = self._build_client(self.session)
            return self._client

    def _build_client(self, session: Session) -> LoseIt:
        config = Config.model_construct(
            user_id=session.user_id,
            user_name=session.user_name,
            hours_from_gmt=self._settings.hours_from_gmt,
            policy_hash=self._settings.policy_hash,
            strong_name=self._settings.strong_name,
            base_url=self._settings.base_url,
            service_url="https://www.loseit.com/web/service",
        )
        return LoseIt(config, session.token)

    def _reauthenticate(self, seen_generation: int | None = None) -> None:
        """Force a fresh login and rebuild the underlying client.

        ``seen_generation`` lets a caller say which session it was using when
        it failed. If someone else has already replaced that session, there is
        nothing to do — re-logging in again would just invalidate the session
        the other caller is about to succeed with.
        """
        with self._lock:
            if seen_generation is not None and seen_generation != self._generation:
                return
            # Retire rather than close: another thread may be issuing a request
            # through this client right now, and closing its connection pool
            # would fail that request with a confusing transport error.
            if self._client is not None:
                self._retired.append(self._client)
                self._client = None
            # Clear first: if the login below fails, we must not leave the
            # rejected session in place for the next call to rebuild from.
            self._session = None
            session = resolve_session(self._settings, force_login=True)
            self._session = session
            self._client = self._build_client(session)
            self._generation += 1
            generation = self._generation
            reclaimed = self._reclaim_retired()

        logger.info("re-authenticated, session generation=%d", generation)

        for client in reclaimed:
            client.close()

        if self.on_reauthenticated is not None:
            # Outside the lock: the callback belongs to the caller and must not
            # be able to deadlock this service.
            self.on_reauthenticated(session)

    def _reclaim_retired(self) -> list[LoseIt]:
        """Take ownership of retired clients that are safe to close.

        Caller must hold the lock, and must close the returned clients *after*
        releasing it.
        """
        if self._inflight > 0 or not self._retired:
            return []
        retired, self._retired = self._retired, []
        return retired

    @contextmanager
    def _in_flight(self) -> Iterator[None]:
        """Mark a request as active so no client is closed underneath it."""
        with self._lock:
            self._inflight += 1
        try:
            yield
        finally:
            with self._lock:
                self._inflight -= 1
                reclaimed = self._reclaim_retired()
            for client in reclaimed:
                client.close()

    def _retrying(self, fn: Callable[[], _T]) -> _T:
        """Run ``fn``, retrying once after re-authenticating on auth failure.

        Records the session generation before running. If several callers fail
        together — which is exactly what happens when a token expires while a
        search has eight enrichment threads in flight — only the first performs
        the re-login; the rest see a newer generation and simply retry against
        the session it produced, instead of queuing eight sequential logins.
        """
        generation = self._generation
        try:
            with self._in_flight():
                return fn()
        except Exception as exc:
            if not _is_auth_failure(exc):
                raise
            self._reauthenticate(seen_generation=generation)
            with self._in_flight():
                return fn()

    def _reading(self, fn: Callable[[], _T], *, what: str = "read") -> _T:
        """Run a *read* under one attempt budget covering auth and transient faults.

        Only for reads. A write that appears to fail may still have been
        applied, so retrying one risks logging the same food twice.

        The budget is shared rather than nested. Running a transient loop
        around the auth loop multiplied them, and could reach four real logins
        from a single read — invisible, and enough to look like an attack to
        Lose It's own protections.
        """
        generation = self._generation
        last: Exception | None = None
        relogins = 0
        for attempt in range(1, _READ_ATTEMPTS + 1):
            try:
                with self._in_flight():
                    return fn()
            except Exception as exc:
                last = exc
                final = attempt == _READ_ATTEMPTS
                if _is_auth_failure(exc):
                    # One re-login per read. Three back-to-back password logins
                    # in a few hundred milliseconds is lockout-shaped, and if
                    # the first re-auth didn't fix it a second won't.
                    if final or relogins:
                        raise
                    relogins += 1
                    logger.info("auth expired during %s, re-authenticating", what)
                    self._reauthenticate(seen_generation=generation)
                    generation = self._generation
                    time.sleep(_TRANSIENT_BACKOFF * random.uniform(0.5, 1.5))
                    continue
                if not _is_transient_upstream(exc) or final:
                    if _is_transient_upstream(exc):
                        logger.error(
                            "%s failed after %d attempts: %s", what, attempt, _brief(exc)
                        )
                    raise
                delay = _TRANSIENT_BACKOFF * attempt * random.uniform(0.5, 1.5)
                logger.warning(
                    "transient upstream fault on %s (attempt %d/%d): %s",
                    what,
                    attempt,
                    _READ_ATTEMPTS,
                    _brief(exc),
                )
                time.sleep(delay)
        raise last  # pragma: no cover - the loop always returns or raises

    def _call(self, fn_name: str, *args: Any, **kwargs: Any) -> Any:
        """Invoke an SDK method, retrying once after a re-login on auth failure."""
        return self._retrying(lambda: getattr(self.client, fn_name)(*args, **kwargs))

    def close(self) -> None:
        """Shut down, releasing every client this service has built.

        Unlike re-authentication this is an explicit teardown, so retired
        clients are closed even if a request is somehow still in flight.
        """
        with self._lock:
            pending = self._retired
            self._retired = []
            if self._client is not None:
                pending.append(self._client)
                self._client = None
        for client in pending:
            client.close()

    # ── Dates ───────────────────────────────────────────────────────────

    def _parse(self, value: str | date | None) -> date | None:
        """Parse a date argument against the account's timezone."""
        return _parse_date(value, self._settings.hours_from_gmt)

    def _day(self, value: str | date | None) -> date:
        """Resolve a date argument, defaulting to today in the account's zone."""
        return self._parse(value) or account_today(self._settings.hours_from_gmt)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ── Operations ──────────────────────────────────────────────────────

    def whoami(self) -> dict[str, Any]:
        """Identity of the authenticated account."""
        session = self.session
        return {
            "user_id": session.user_id,
            "user_name": session.user_name,
            "email": session.email,
            "hours_from_gmt": self._settings.hours_from_gmt,
        }

    def search_food(
        self,
        query: str,
        limit: int = 15,
        *,
        detail: bool = True,
    ) -> list[dict[str, Any]]:
        """Search the Lose It! food database.

        With ``detail`` (the default) each hit is enriched with its nutrition
        and serving. The search RPC returns only name/brand/category/id, so
        without this a caller comparing five candidates pays six round trips —
        and in practice settles for one, which is how an entry whose calories
        contradict its own macros gets reported as fact.

        Enrichment is per-food best-effort: one unresolvable hit yields a
        result carrying just its name, never an exception for the whole search.
        """
        started = time.monotonic()
        results = self._reading(lambda: self.client.search(query), what="search_food")
        hits = [_food_to_dict(r) for r in results[:limit]]
        if not detail or not hits:
            return hits

        # Serialized, these are ~0.2s each; a five-candidate comparison would
        # otherwise spend over a second doing nothing but waiting. Only the
        # first few are enriched — see _MAX_ENRICHED.
        #
        # Futures are submitted explicitly rather than via `map` so that a
        # failure can wait for the workers already running. `map` cancels only
        # *pending* futures, leaving up to seven live requests behind — which
        # then keep using a client the request's `finally` has already closed.
        targets = hits[:_MAX_ENRICHED]
        futures = [_ENRICH_POOL.submit(self._enrich_hit, h) for h in targets]
        try:
            enriched = [f.result() for f in futures]
        except BaseException:
            for f in futures:
                f.cancel()
            concurrent.futures.wait(futures)
            raise
        rest = [{**h, "nutrition_available": False} for h in hits[_MAX_ENRICHED:]]
        degraded = [h for h in enriched if not h.get("nutrition_available")]
        logger.info(
            "search_food id=%s hits=%d enriched=%d degraded=%d elapsed_ms=%d%s",
            current_request_id() or "-",
            len(hits),
            len(enriched) - len(degraded),
            len(degraded) + len(rest),
            int((time.monotonic() - started) * 1000),
            # One representative reason rather than one line per failed hit.
            f" reason={degraded[0].get('_reason')}" if degraded else "",
        )
        for hit in enriched:
            hit.pop("_reason", None)
        return enriched + rest

    def _enrich_hit(self, hit: dict[str, Any]) -> dict[str, Any]:
        """Attach nutrition to one search hit, or leave it as-is.

        Auth failures are re-raised rather than absorbed: the outer read needs
        to see them to re-authenticate, and swallowing them would report every
        food as having no nutrition and keep doing so until some unrelated
        call happened to refresh the token.
        """
        try:
            detail = self.describe_food(hit["food_id"], retry=False)
        except Exception as exc:
            if _is_auth_failure(exc):
                raise
            # Counted in the search summary rather than logged per hit: a
            # degraded upstream would otherwise emit ten records per search,
            # which is thousands a minute during exactly the outage an
            # operator is trying to read through.
            return {**hit, "nutrition_available": False, "_reason": _brief(exc)}
        return {
            **hit,
            "name": detail.get("name") or hit.get("name"),
            "brand": detail.get("brand") or hit.get("brand"),
            "nutrition_available": True,
            "primary_serving": detail.get("primary_serving"),
            "nutrients_per_serving": detail.get("nutrients_per_serving"),
        }

    def describe_food(self, food_id: str, *, retry: bool = True) -> dict[str, Any]:
        """Full nutrition detail for a food, by its hex ID.

        Deliberately not the SDK's ``describe_food``. That resolves the ID with
        ``getFood`` before fetching nutrition, and uses the result for nothing
        but passing along — every field it returns comes from the second call.
        Worse, ``getFood`` only finds foods that exist as database *records*,
        so it fails for every food created by :meth:`log_custom_food`, which
        mints a synthetic key and stores the nutrition on the diary entry
        itself. Those foods stay in search results forever, undescribable.

        Going straight to ``getUnsavedFoodLogEntry`` costs one RPC instead of
        two and resolves them. Verified against 90 foods: identical values
        wherever the old path worked, and working for the six where it didn't.

        ``retry=False`` is used by search enrichment, where ten of these run
        per call: retrying each would multiply one tool call into forty
        upstream requests, and enrichment already degrades gracefully to
        "nutrition unavailable" for a hit it cannot resolve.
        """

        def run() -> dict[str, Any]:
            return _describe_from_unsaved(
                food_id, _get_unsaved(self.client.http, _food_ref(food_id))
            )

        if retry:
            return self._reading(run, what="describe_food")
        return self._retrying(run)

    def get_diary(self, when: str | date | None = None) -> dict[str, Any]:
        """All food log entries for a day."""
        day = self._day(when)
        entries = self._call("diary", day)
        items = [_entry_to_dict(e) for e in entries]
        return {
            "date": day.isoformat(),
            "entry_count": len(items),
            "total_calories": round(sum(i.get("calories") or 0 for i in items), 1),
            "entries": items,
        }

    def log_food(
        self,
        food_id: str,
        meal: str = "snacks",
        servings: float | None = None,
        serving_amount: float | None = None,
        serving_unit: str | None = None,
        when: str | date | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Log a food to a meal.

        Supply either ``servings`` (a canonical multiplier) or the pair
        ``serving_amount`` + ``serving_unit`` (e.g. ``120`` + ``"g"``).

        Combining the two, or giving only half of the amount/unit pair, is
        rejected rather than silently resolved — guessing wrong here logs the
        wrong quantity of food, which the caller has no easy way to notice.
        """
        if (serving_amount is None) != (serving_unit is None):
            raise ValueError(
                "serving_amount and serving_unit must be supplied together "
                "(e.g. 120 and 'g')."
            )
        if serving_amount is not None and servings is not None:
            raise ValueError(
                "Specify a portion either as servings OR as "
                "serving_amount + serving_unit, not both."
            )

        kwargs: dict[str, Any] = {
            "meal": meal,
            "when": self._day(when),
            "dry_run": dry_run,
        }
        # Resolve the food first. Passing a bare ID would make the SDK call
        # `getFood`, which only finds database records and so fails for
        # anything log_custom_food created — "log what I had last week" is
        # exactly when that gets attempted. Resolving here also supplies the
        # name and brand for the confirmation, which a reference built from an
        # ID alone cannot carry, and tells us whether this food is measured by
        # weight before we interpret an ounce.
        detail = self.describe_food(food_id)
        ref = _food_ref(food_id, name=detail.get("name") or "", brand=detail.get("brand") or "")

        if serving_amount is not None:
            serving_amount, serving_unit, note = _normalise_ounces(
                serving_amount, serving_unit, detail
            )
            kwargs["serving_amount"] = serving_amount
            kwargs["serving_unit"] = serving_unit
            kwargs["servings"] = 1.0
        else:
            note = None
            kwargs["servings"] = 1.0 if servings is None else servings

        result = _to_dict(self._call("log_food", ref, **kwargs))
        # The SDK echoes back the reference it was handed, so without this the
        # confirmation for a *write* would not say what was written.
        food = result.get("food")
        if isinstance(food, dict):
            food.setdefault("food_id", food_id)
            food["name"] = food.get("name") or detail.get("name") or ""
            food["brand"] = food.get("brand") or detail.get("brand") or ""
        if note:
            result["unit_interpreted_as"] = note
        return result

    def log_custom_food(
        self,
        name: str,
        calories: float,
        meal: str = "snacks",
        brand: str = "",
        protein_g: float | None = None,
        carb_g: float | None = None,
        fat_g: float | None = None,
        saturated_fat_g: float | None = None,
        fiber_g: float | None = None,
        sugar_g: float | None = None,
        sodium_mg: float | None = None,
        cholesterol_mg: float | None = None,
        servings: float = 1.0,
        when: str | date | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Log arbitrary nutrition values without a food-database entry.

        ``updateFoodLogEntry`` carries the food's name, brand, and nutrient map
        inline, so a diary entry can describe a food the database has never
        heard of. We mint a random food primary key for it — the server stores
        the nutrition we send rather than resolving the key.

        Use this for restaurant meals, homemade dishes, or anything where you
        know the macros but no good database match exists.

        Values are *per serving*; the server multiplies them by ``servings``.
        """
        nutrients = {
            ord_: float(value)
            for ord_, value in (
                (_NUTRIENT_ORDINALS["calories"], calories),
                (_NUTRIENT_ORDINALS["protein_g"], protein_g),
                (_NUTRIENT_ORDINALS["carb_g"], carb_g),
                (_NUTRIENT_ORDINALS["total_fat_g"], fat_g),
                (_NUTRIENT_ORDINALS["saturated_fat_g"], saturated_fat_g),
                (_NUTRIENT_ORDINALS["fiber_g"], fiber_g),
                (_NUTRIENT_ORDINALS["sugar_g"], sugar_g),
                (_NUTRIENT_ORDINALS["sodium_mg"], sodium_mg),
                (_NUTRIENT_ORDINALS["cholesterol_mg"], cholesterol_mg),
            )
            if value is not None
        }

        meal_ordinal = int(MealType.parse(meal))
        day = self._day(when)

        # Report only what actually reaches the wire, so the caller is never
        # told a nutrient was recorded when the payload builder dropped it.
        sent = {ord_: v for ord_, v in nutrients.items() if ord_ in _SENDABLE_ORDINALS}
        ignored = sorted(
            label
            for label, ord_ in _NUTRIENT_ORDINALS.items()
            if ord_ in nutrients and ord_ not in _SENDABLE_ORDINALS
        )

        result: dict[str, Any] = {
            "action": "log_custom",
            "dry_run": dry_run,
            "date": day.isoformat(),
            "meal": meal,
            "food": {"name": name, "brand": brand},
            "servings": servings,
            "calories": round(calories * servings, 1),
            "nutrients": {
                label: round(value * servings, 2)
                for label, ord_ in _NUTRIENT_ORDINALS.items()
                if (value := sent.get(ord_)) is not None
            },
        }
        if ignored:
            result["ignored_nutrients"] = ignored
            result["warning"] = (
                f"Not recorded (unsupported by the upstream payload builder): "
                f"{', '.join(ignored)}."
            )
        if dry_run:
            return result

        self._log_custom(name, brand, sent, meal_ordinal, day, servings)
        return result

    def _log_custom(
        self,
        name: str,
        brand: str,
        nutrients: dict[int, float],
        meal_ordinal: int,
        day: date,
        servings: float,
    ) -> None:
        """Send a synthetic ``updateFoodLogEntry``, re-authenticating if needed."""

        def send() -> None:
            http = self.client.http
            day_num = day_number_for(day)
            day_key = get_daydate_key(http, day_num) or ""
            unsaved = UnsavedFoodLogEntry(
                name=name,
                brand=brand,
                category="Food",
                food_pk_bytes=_random_pk(),
                day_key=day_key,
                nutrients=nutrients,
                # 27 = "serving"; the entry is defined by its nutrients, not a
                # measurable unit, so a generic serving is the honest label.
                food_measure_ordinal=27,
            )
            _entries.log_food(http, unsaved, meal_ordinal, day_key, day_num, servings)

        self._retrying(send)

    def log_weight(
        self,
        weight: float,
        when: str | date | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Record a weigh-in for a day.

        The unit follows the account's display setting (lb or kg); the API
        carries no unit itself.
        """
        day = self._day(when)
        result: dict[str, Any] = {
            "action": "weigh_in",
            "dry_run": dry_run,
            "date": day.isoformat(),
            "weight": weight,
        }
        if dry_run:
            return result

        saved = self._retrying(lambda: save_weight(self.client.http, weight, day))
        result["weight"] = saved
        return result

    def get_weight_history(
        self,
        start: str | date | None = None,
        end: str | date | None = None,
        days: int = 30,
    ) -> dict[str, Any]:
        """Return recorded weigh-ins over a date range.

        Defaults to the last ``days`` days ending today. Explicit ``start`` /
        ``end`` override that.

        The span is capped. Cost here is not proportional to the number of
        *results* but to the number of days asked for: the range is fetched in
        windows of about seven weeks, so an open-ended ``start`` turns one tool
        call into tens of thousands of upstream requests. Those all run inside a
        single request, where no rate limiter gets another say, so the bound has
        to live here.
        """
        end_date = self._day(end)
        start_date = self._parse(start) or (end_date - timedelta(days=max(days, 1) - 1))

        if end_date < start_date:
            raise ValueError(
                f"start {start_date.isoformat()} is after end {end_date.isoformat()}."
            )

        span = (end_date - start_date).days + 1
        if span > MAX_HISTORY_SPAN_DAYS:
            raise ValueError(
                f"Requested {span:,} days of weight history "
                f"({start_date.isoformat()} to {end_date.isoformat()}); the maximum "
                f"is {MAX_HISTORY_SPAN_DAYS:,} (about "
                f"{MAX_HISTORY_SPAN_DAYS // 365} years). Narrow start/end and, if "
                "you need more, request it in several ranges."
            )

        entries = self._retrying(
            lambda: _get_weight_history(self.client.http, start_date, end_date)
        )

        weights = [e["weight"] for e in entries]
        summary: dict[str, Any] = {
            "start": start_date.isoformat(),
            "end": end_date.isoformat(),
            "count": len(entries),
            "entries": entries,
        }
        if weights:
            summary["latest"] = weights[-1]
            summary["min"] = min(weights)
            summary["max"] = max(weights)
            summary["change"] = round(weights[-1] - weights[0], 2)
        return summary

    def delete_entry(
        self,
        entry_id: str,
        when: str | date | None = None,
    ) -> dict[str, Any]:
        """Delete a diary entry by its ID, on the given day.

        The entry is looked up in that day's diary first so we delete exactly
        what the caller saw. A recoverable trash record is written before the
        wire delete (an upstream SDK invariant).
        """
        day = self._day(when)
        entries = self._call("diary", day)
        match = next((e for e in entries if _entry_id(e) == entry_id), None)
        if match is None:
            available = [_entry_id(e) for e in entries]
            raise ValueError(
                f"No entry {entry_id!r} in the diary for {day.isoformat()}. "
                f"Entries that day: {available}"
            )
        result = self._call("delete_entry", match)
        return _to_dict(result)


# ── Serialization helpers ───────────────────────────────────────────────
#
# The SDK returns a mix of dataclasses and pydantic-ish models; normalize them
# all to plain dicts without caring which is which.


def _to_dict(obj: Any) -> Any:
    if obj is None or isinstance(obj, int | float | bool):
        return obj
    if isinstance(obj, str):
        return _unescape(obj)
    if isinstance(obj, list | tuple):
        return [_to_dict(o) for o in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    for attr in ("to_dict", "model_dump", "_asdict"):
        fn = getattr(obj, attr, None)
        if callable(fn):
            return _to_dict(fn())
    if hasattr(obj, "__dataclass_fields__"):
        return {f: _to_dict(getattr(obj, f)) for f in obj.__dataclass_fields__}
    if hasattr(obj, "__dict__"):
        return {k: _to_dict(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return str(obj)


def _entry_id(entry: Any) -> str | None:
    """Stable hex handle for a diary entry.

    The SDK keeps the entry primary key internal (no RPC takes it as input),
    but MCP clients need *some* durable way to say "delete that one". Its hex
    form is unique within a day and round-trips through :meth:`get_diary`.
    """
    pk = getattr(entry, "entry_pk_response", None)
    if isinstance(pk, list) and len(pk) == 16:
        return pk_to_hex(pk)
    return None


def _food_to_dict(food: Any) -> dict[str, Any]:
    data = _to_dict(food)
    return data if isinstance(data, dict) else {"value": data}


# Nutrient labels worth surfacing by default; the rest stay in `nutrients`.
_MACRO_KEYS = (
    "calories",
    "protein_g",
    "carb_g",
    "total_fat_g",
    "saturated_fat_g",
    "fiber_g",
    "sugar_g",
    "sodium_mg",
    "cholesterol_mg",
)


def _round(value: Any, places: int = 2) -> Any:
    """Round floats for display; the API returns long binary-float tails."""
    return round(value, places) if isinstance(value, float) else value


# For measure ordinal 8 Lose It! stores nutrients per 100 g and uses `servings`
# as the multiplier — so `servings=2` means 200 g, not 2 g.
_GRAMS_ORDINAL = 8
_GRAMS_PER_SERVING = 100.0

# Measure ordinals the SDK leaves unlabelled, which surface as
# ``unknown_ord_<N>`` and read as noise to a model comparing candidates.
#
# Ordinal 6 is the weight ounce. Established by probing 56 foods: the gram
# weight per unit clusters on 28.0 and 28.3495 (a rounded and an exact ounce),
# and the giveaway is the fractional quantities — 113 g stored as 4.03571
# units, 128 g as 4.57143 — which are gram weights divided by an ounce
# constant, not numbers anybody typed. It sits alongside GRAMS=8 and
# FLUID_OUNCE=10, so a weight-ounce slot is exactly what the enum was missing.
#
# A minority of entries (all `qty=3.0, g=100.0`) are USDA per-100g records
# whose author set the display quantity to the conventional 3 oz serving
# without reconciling it — those really do claim 3 oz for 100 g. This is why
# the label is for *display only*: every conversion still goes through the
# food's own `per_serving_g`, so a mislabelled entry reads oddly but never
# computes wrongly.
_MEASURE_LABEL_OVERRIDES = {6: "oz"}

# Weight ounces, converted here rather than passed through. The SDK rejects a
# bare "oz" as ambiguous between weight and fluid, which was reasonable while
# ordinal 6 was unlabelled — but now that a search result can read "18 oz", a
# caller will quite reasonably try to log "9 oz" and hit that refusal.
#
# Converting to grams resolves the ambiguity in the direction the label
# implies, and is more accurate than trusting the food's own unit: the entries
# that claim 3 oz for 100 g would otherwise log 18% heavy. Fluid ounces still
# go through untouched, because those really are a different measurement.
_GRAMS_PER_OUNCE = 28.349523125
_ML_PER_FLUID_OUNCE = 29.5735295625
_OUNCE_ALIASES = frozenset({"oz", "ounce", "ounces"})


def _normalise_ounces(
    amount: float, unit: str | None, detail: dict[str, Any]
) -> tuple[float, str | None, str | None]:
    """Resolve a bare "oz" against the food, returning what we decided.

    The SDK refuses a bare "oz" because it can mean a weight ounce (~28.35 g)
    or a fluid ounce (~29.57 mL). That refusal was right while ordinal 6 was
    unlabelled, but a search result now reads "18 oz", so a caller will try to
    log "9 oz" and deserve better than a rejection.

    The ambiguity is resolved against the food rather than globally: something
    sold by weight becomes grams, something that only carries a volume becomes
    fluid ounces. "8 oz of milk" therefore stays a volume instead of silently
    logging 227 g where 244 g was meant. The decision is reported back in
    ``unit_interpreted_as`` so it is never silent.
    """
    if unit is None or unit.strip().lower() not in _OUNCE_ALIASES:
        return amount, unit, None

    conversion = detail.get("cross_class_conversion") or {}
    if conversion.get("per_serving_g") is not None:
        return amount * _GRAMS_PER_OUNCE, "g", f"weight ounces ({_GRAMS_PER_OUNCE:g} g each)"
    if conversion.get("per_serving_ml") is not None:
        return amount, "fl_oz", "fluid ounces (this food is measured by volume)"
    # Nothing to go on; weight is the commoner reading for a bare "oz".
    return amount * _GRAMS_PER_OUNCE, "g", f"weight ounces ({_GRAMS_PER_OUNCE:g} g each)"


def _measure_label(ordinal: int | None, sdk_label: str | None) -> str | None:
    """Prefer the SDK's label, filling gaps we have evidence for."""
    if sdk_label and not sdk_label.startswith("unknown_ord_"):
        return sdk_label
    return _MEASURE_LABEL_OVERRIDES.get(ordinal, sdk_label)


def _food_ref(food_id: str, *, name: str = "", brand: str = "") -> Any:
    """A minimal food reference for ``getUnsavedFoodLogEntry``.

    Name, brand and category default to empty on purpose: the RPC carries them
    but the server ignores them entirely and answers from the primary key.
    Confirmed by sending a deliberately wrong name with a valid key (the key
    won) and by sending no name at all (still correct). Not relying on them
    is what lets this resolve a food from an ID alone.

    They can still be supplied, because the SDK echoes this object back in the
    logging result — where an empty name leaves a write confirmation that
    doesn't say what was written.
    """
    return _foods.FoodSearchResult(
        name=name, brand=brand, category="", pk_bytes=hex_to_pk(food_id)
    )


def _get_unsaved(http: Any, ref: Any) -> UnsavedFoodLogEntry:
    return _foods.get_unsaved_food_log_entry(http, ref)


def _describe_from_unsaved(food_id: str, unsaved: UnsavedFoodLogEntry) -> dict[str, Any]:
    """Project an unsaved entry into the shape ``describe_food`` returns.

    ``raw_nutrients_by_ord`` is dropped: it restates ``nutrients_per_serving``
    by ordinal, and shipping both doubles the payload for no reader. Unmapped
    nutrients are kept — this tool promises full detail, and an unrecognised
    micronutrient is still data the caller asked for.

    Raises when the response is blank. ``getUnsavedFoodLogEntry`` answers an
    unknown key with a default-constructed entry rather than an error, so
    without this a stale or invented ID would return a plausible-looking food
    with no name and no nutrients — which reads as "this food has no calories"
    rather than "this food does not exist".
    """
    nutrients = {
        label: _round(value) for label, value in (unsaved.nutrients_by_label or {}).items()
    }
    if not (unsaved.name or "").strip() and not nutrients:
        raise LoseItError(f"Food with id {food_id} not found")

    return {
        "food_id": food_id,
        "name": _unescape(unsaved.name or ""),
        "brand": _unescape(unsaved.brand or ""),
        "category": unsaved.category or "",
        "primary_serving": {
            "ordinal": unsaved.food_measure_ordinal,
            "unit": _measure_label(unsaved.food_measure_ordinal, unsaved.food_measure_unit),
            "canonical_per_serving": _round(unsaved.canonical_per_serving),
            "native_qty_per_serving": _round(_native_qty_per_serving(unsaved), 3),
        },
        "cross_class_conversion": {
            "per_serving_g": _round(unsaved.per_serving_g),
            "per_serving_ml": _round(unsaved.per_serving_ml),
        },
        "nutrients_per_serving": nutrients,
    }


def _native_qty_per_serving(unsaved: UnsavedFoodLogEntry) -> float | None:
    """How much of the food, in its own unit, one serving actually is.

    The raw field is only half the answer. Per the SDK's own model notes the
    per-serving quantity is ``f4 / f3`` — ``native_qty_per_serving`` divided by
    ``canonical_per_serving`` — and roughly 40% of foods carry a ``f3`` that
    isn't 1.

    Reporting the raw value understates those badly, and the errors are not
    subtle: whole almonds are stored as 575 calories against ``f4=1 each`` with
    ``f3=0.012``, so the honest figure is 83 almonds, not one. Rice and oils
    are wrong the same way. The SDK's own CLI prints the raw field and has the
    same flaw.
    """
    native = unsaved.native_qty_per_serving
    canonical = unsaved.canonical_per_serving
    if native is None:
        return None
    if not canonical:
        return native
    return native / canonical


# Enrichment fans out one RPC per hit, so it is capped independently of the
# caller's `limit`: throttling admits a request, not the however-many upstream
# calls it turns into, and comparing candidates needs a handful rather than 50.
_ENRICH_WORKERS = 8
_MAX_ENRICHED = 10

# One pool for the whole process. A pool per call would let MCP's own thread
# dispatch (40 concurrent sync tools by default) multiply into hundreds of
# threads and upstream connections, which is precisely the ceiling anyio's
# limiter exists to impose.
_ENRICH_POOL = ThreadPoolExecutor(max_workers=_ENRICH_WORKERS, thread_name_prefix="loseit-enrich")


def _display_portion(data: dict[str, Any]) -> tuple[float | None, str | None]:
    """Human-facing (amount, unit) for an entry's portion."""
    servings = data.get("servings")
    unit = data.get("food_measure_unit")
    if data.get("food_measure_ordinal") == _GRAMS_ORDINAL and isinstance(servings, int | float):
        return round(servings * _GRAMS_PER_SERVING, 1), "g"
    return _round(servings, 3), unit


def _entry_to_dict(entry: Any) -> dict[str, Any]:
    """Compact projection of a diary entry.

    The SDK's own ``to_dict`` carries two full nutrient maps (raw ordinals and
    labels, including ``unknown_nutrient_*`` noise), which is far more than an
    MCP client needs per entry. Keep the useful macros and drop the rest.
    """
    data = _to_dict(entry)
    if not isinstance(data, dict):
        return {"value": data}

    labeled = data.get("nutrients_by_label") or {}
    macros = {k: _round(labeled[k]) for k in _MACRO_KEYS if k in labeled}
    amount, unit = _display_portion(data)

    return {
        "entry_id": _entry_id(entry),
        "food_id": data.get("food_id"),
        "food_name": data.get("food_name"),
        "food_brand": data.get("food_brand"),
        "meal": data.get("meal"),
        "amount": amount,
        "unit": unit,
        "servings": _round(data.get("servings"), 3),
        "calories": _round(labeled.get("calories"), 1),
        "nutrients": macros,
        "logged_at": data.get("modified_at"),
    }
