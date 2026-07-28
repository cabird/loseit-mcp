"""Bridges our authentication onto the upstream ``lose_it`` SDK.

:class:`LoseItService` owns a resolved :class:`~loseit_mcp.auth.Session` and a
configured :class:`lose_it.LoseIt` client, transparently re-authenticating when
the token expires. Every method returns plain JSON-serializable data so the MCP
and CLI layers can hand results straight to a client.
"""

from __future__ import annotations

import re
import uuid
from datetime import date, datetime
from typing import Any

from lose_it import LoseIt, MealType, UnsavedFoodLogEntry
from lose_it.core import entries as _entries
from lose_it.core._config import Config
from lose_it.core._dates import day_number_for
from lose_it.core._http import LoseItAuthError
from lose_it.core._ids import pk_to_hex
from lose_it.core.daily import get_daydate_key

from .auth import Session, resolve_session
from .config import Settings

# FoodNutrient enum ordinals the server accepts inside a logged entry.
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


def _random_pk() -> list[int]:
    """A random 16-byte primary key in the signed form the wire format uses."""
    return [b - 256 if b >= 128 else b for b in uuid.uuid4().bytes]


# The GWT string table ships non-ASCII and quote characters as literal
# ``\uXXXX`` escapes, and the upstream decoder passes them through verbatim —
# so food names arrive looking like ``Mike\u0027s``. Undo that here.
_GWT_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _unescape(text: str) -> str:
    return _GWT_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


def _parse_date(value: str | date | None) -> date | None:
    """Accept ``None``, a ``date``, ``'today'``/``'yesterday'``, or ISO ``YYYY-MM-DD``."""
    if value is None or isinstance(value, date):
        return value
    text = value.strip().lower()
    if not text or text == "today":
        return date.today()
    if text == "yesterday":
        return date.fromordinal(date.today().toordinal() - 1)
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError(
            f"Invalid date {value!r}; use YYYY-MM-DD, 'today', or 'yesterday'."
        ) from exc


class LoseItService:
    """A logged-in Lose It! client with auto-refreshing credentials."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._session: Session | None = None
        self._client: LoseIt | None = None

    # ── Lifecycle ───────────────────────────────────────────────────────

    @property
    def session(self) -> Session:
        if self._session is None:
            self._session = resolve_session(self._settings)
        return self._session

    @property
    def client(self) -> LoseIt:
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

    def _reauthenticate(self) -> None:
        """Force a fresh login and rebuild the underlying client."""
        self.close()
        self._session = resolve_session(self._settings, force_login=True)
        self._client = self._build_client(self._session)

    def _call(self, fn_name: str, *args: Any, **kwargs: Any) -> Any:
        """Invoke an SDK method, retrying once after a re-login on auth failure."""
        try:
            return getattr(self.client, fn_name)(*args, **kwargs)
        except LoseItAuthError:
            self._reauthenticate()
            return getattr(self.client, fn_name)(*args, **kwargs)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> LoseItService:
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

    def search_food(self, query: str, limit: int = 15) -> list[dict[str, Any]]:
        """Search the Lose It! food database."""
        results = self._call("search", query)
        return [_food_to_dict(r) for r in results[:limit]]

    def describe_food(self, food_id: str) -> dict[str, Any]:
        """Full nutrition detail for a food, by its hex ID."""
        return _to_dict(self._call("describe_food", food_id))

    def get_diary(self, when: str | date | None = None) -> dict[str, Any]:
        """All food log entries for a day."""
        day = _parse_date(when) or date.today()
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
        """
        if servings is None and serving_amount is None:
            servings = 1.0
        kwargs: dict[str, Any] = {
            "meal": meal,
            "when": _parse_date(when),
            "dry_run": dry_run,
        }
        if serving_amount is not None:
            kwargs["serving_amount"] = serving_amount
            kwargs["serving_unit"] = serving_unit
            kwargs["servings"] = 1.0
        else:
            kwargs["servings"] = servings
        return _to_dict(self._call("log_food", food_id, **kwargs))

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
        day = _parse_date(when) or date.today()

        result = {
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
                if (value := nutrients.get(ord_)) is not None
            },
        }
        if dry_run:
            return result

        self._log_custom(name, brand, nutrients, meal_ordinal, day, servings)
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

        try:
            send()
        except LoseItAuthError:
            self._reauthenticate()
            send()

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
        day = _parse_date(when) or date.today()
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
