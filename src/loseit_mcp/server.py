"""MCP tool definitions for Lose It!.

The same tool set serves two deployment shapes:

- **Single-tenant** (default, and the only sane shape for stdio): one account,
  configured from the environment. Every request uses the same service.
- **Multi-tenant**: credentials arrive per request as headers and sessions are
  cached, so one hosted server can serve many accounts. See
  :mod:`loseit_mcp.tenancy`.

Tools take a ``Context`` so they can read request headers in multi-tenant mode;
the MCP runtime injects it and keeps it out of the tool's input schema.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Annotated, Any

from mcp.server.mcpserver import Context, MCPServer
from pydantic import Field

from . import __version__
from .config import Settings
from .errors import translate
from .sealed import UrlSealer
from .service import LoseItService
from .tenancy import SessionResolver, resolve_or_raise

INSTRUCTIONS = """\
Read and write the user's Lose It! food diary.

Logging a meal:
1. `search_food` returns candidates with nutrition. Entries are user-submitted
   and often wrong, so compare them rather than taking the first: a sound entry
   has protein*4 + carb*4 + fat*9 near its calories, and values that recur
   across duplicates are the trustworthy ones.
2. `log_food` with the chosen `food_id`, a meal, and a portion.

Prefer parts over wholes: a Chipotle bowl is chicken + rice + beans + sour
cream, each searched and logged separately.

Portions: `serving_amount` + `serving_unit` (e.g. 120 + "g") for a concrete
quantity, else `servings` as a multiplier of the serving shown in the search
result. One or the other, never both. `dry_run=true` previews the math.

`log_custom_food` is a last resort, after searching for both the dish and its
parts.

Deleting: `get_diary` for an `entry_id`, then `delete_entry`.
"""


def _cell(text: str) -> str:
    """Make a user-submitted string safe to place in a delimited row.

    Food names come from Lose It's public, user-submitted database, so they can
    contain anything — including a newline and a pipe, which is enough to forge
    an entire extra row with a different food_id and let a model log something
    nobody offered. Verified before this guard existed.
    """
    flattened = " ".join(str(text).split())
    return flattened.replace("|", "/")


def _gram(nutrients: dict[str, Any], key: str) -> str:
    """One macro, rounded, or ``?`` when the entry doesn't carry it.

    Deliberately not ``0``: a missing nutrient is unknown, and printing zero
    would invite logging a food as having none of it. Values below 1 keep a
    significant digit for the same reason — rounding 0.4 g to "0" states the
    very thing this is trying to avoid.
    """
    value = nutrients.get(key)
    if value is None:
        return "?"
    if 0 < abs(value) < 1:
        return f"{value:.2g}"
    return f"{round(value):g}"


def _format_search(query: str, hits: list[dict[str, Any]]) -> str:
    """Render search hits as text rather than JSON.

    JSON repeats every key on every row; for five enriched candidates that is
    roughly eight times the tokens of the same information laid out in columns.
    The layout matters as much as the size: putting the candidates in aligned
    rows is what makes an entry claiming 90 calories for the same macros as its
    four 278-calorie siblings visible at a glance.

    Values are stated per the serving shown, because Lose It stores them that
    way and the serving differs between otherwise identical entries.
    """
    if not hits:
        return f'No matches for "{query}". Try a shorter or more common name.'

    lines = [
        f'{len(hits)} matches for "{query}". Values are per the serving shown.',
        "name (brand) | cal | protein/carb/fat g | serving | food_id",
    ]
    for index, hit in enumerate(hits, 1):
        name = _cell(hit.get("name") or "(unnamed)")
        brand = hit.get("brand")
        label = f"{name} ({_cell(brand)})" if brand else name
        food_id = _cell(hit.get("food_id") or "?")

        nutrients = hit.get("nutrients_per_serving") or {}
        if not hit.get("nutrition_available") or not nutrients:
            # Keep the column count so the row still aligns with the header,
            # but say plainly that the blanks are missing data.
            lines.append(f"{index}. {label} | ? | ?/?/? | ? | {food_id}  (nutrition unavailable)")
            continue

        serving = hit.get("primary_serving") or {}
        amount = serving.get("native_qty_per_serving")
        unit = _cell(serving.get("unit") or "serving")
        portion = f"{round(amount, 3):g} {unit}" if isinstance(amount, int | float) else unit

        lines.append(
            f'{index}. {label} | {_gram(nutrients, "calories")} | '
            f'{_gram(nutrients, "protein_g")}/{_gram(nutrients, "carb_g")}'
            f'/{_gram(nutrients, "total_fat_g")} | '
            f"{portion} | {food_id}"
        )
    return "\n".join(lines)


def build_server(
    settings: Settings,
    *,
    multi_tenant: bool = False,
    sealer: UrlSealer | None = None,
) -> MCPServer:
    """Construct the MCP server.

    With ``multi_tenant`` set, each request must identify an account — either
    with credential headers or, when ``sealer`` is supplied, via a
    ``/u/<sealed>/`` credential URL. Each request gets its own service instance,
    so concurrent callers never share state. Otherwise a single service is
    built from ``settings`` and shared.
    """
    shared: LoseItService | None = None
    resolver: SessionResolver | None = None

    if multi_tenant:
        resolver = SessionResolver(settings)
    else:
        shared = LoseItService(settings)

    @contextmanager
    def acquire(ctx: Context) -> Iterator[LoseItService]:
        """Yield a service for this request, translating failures for the user.

        Wraps the whole tool body so a protocol break inside an RPC surfaces as
        an explanation rather than a decoder traceback.
        """
        try:
            if resolver is None:
                assert shared is not None
                yield shared
                return
            service, _ = resolve_or_raise(resolver, ctx.headers or {}, sealer)
            try:
                yield service
            finally:
                service.close()
        except Exception as exc:
            translated = translate(exc)
            if translated is exc:
                raise
            raise translated from exc

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if shared is not None:
                shared.close()

    mcp = MCPServer(
        name="loseit",
        version=__version__,
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
    )

    @mcp.tool(
        description=(
            "Search the Lose It! food database. Returns candidate foods with "
            "their nutrition and a `food_id` to pass to log_food. Compare the "
            "candidates before choosing one — the database is user-submitted "
            "and contains entries whose calories contradict their own macros."
        ),
        # This tool answers with prose, not a record. Left on, the framework
        # derives an output schema of {"result": string} from the return
        # annotation and then sends no structuredContent to satisfy it, which
        # is a protocol violation: a client that validates the declared schema
        # rejects every response and the connection looks broken.
        structured_output=False,
    )
    def search_food(
        ctx: Context,
        query: Annotated[str, Field(description="Food name to search for, e.g. 'greek yogurt'.")],
        limit: Annotated[int, Field(description="Max results to return.", ge=1, le=50)] = 10,
    ) -> str:
        with acquire(ctx) as svc:
            return _format_search(query, svc.search_food(query, limit=limit))

    @mcp.tool(
        description=(
            "Get full nutrition detail and serving information for one food, "
            "identified by the `food_id` returned from search_food."
        )
    )
    def describe_food(
        ctx: Context,
        food_id: Annotated[str, Field(description="32-character hex food ID.")],
    ) -> dict[str, Any]:
        with acquire(ctx) as svc:
            return svc.describe_food(food_id)

    @mcp.tool(
        description=(
            "Read the food diary for a day: every logged entry with calories and "
            "macros, plus the day's totals. Each entry carries an `entry_id` for "
            "delete_entry."
        )
    )
    def get_diary(
        ctx: Context,
        date: Annotated[
            str | None,
            Field(description="Day to read: 'YYYY-MM-DD', 'today', or 'yesterday'."),
        ] = None,
    ) -> dict[str, Any]:
        with acquire(ctx) as svc:
            return svc.get_diary(date)

    @mcp.tool(
        description=(
            "Log a food to a meal in the diary. Specify the portion EITHER as "
            "`serving_amount` + `serving_unit` (e.g. 120 and 'g') OR as `servings` "
            "(a multiplier of the food's default serving), never both. Set dry_run "
            "to preview."
        )
    )
    def log_food(
        ctx: Context,
        food_id: Annotated[str, Field(description="32-character hex food ID from search_food.")],
        meal: Annotated[
            str,
            Field(description="One of: breakfast, lunch, dinner, snacks."),
        ] = "snacks",
        servings: Annotated[
            float | None,
            Field(description="Multiplier of the food's default serving.", gt=0),
        ] = None,
        serving_amount: Annotated[
            float | None,
            Field(description="Quantity in `serving_unit`, e.g. 120.", gt=0),
        ] = None,
        serving_unit: Annotated[
            str | None,
            Field(description="Unit for `serving_amount`, e.g. 'g', 'mL', 'cup', 'oz'."),
        ] = None,
        date: Annotated[
            str | None,
            Field(description="Day to log to: 'YYYY-MM-DD', 'today', or 'yesterday'."),
        ] = None,
        dry_run: Annotated[
            bool,
            Field(description="Preview the result without writing to the diary."),
        ] = False,
    ) -> dict[str, Any]:
        with acquire(ctx) as svc:
            return svc.log_food(
                food_id,
                meal=meal,
                servings=servings,
                serving_amount=serving_amount,
                serving_unit=serving_unit,
                when=date,
                dry_run=dry_run,
            )

    @mcp.tool(
        description=(
            "Log a food by its exact nutrition values, without needing a match in "
            "the food database. Use this for restaurant meals, homemade dishes, or "
            "anything where you know the calories and macros but search_food has no "
            "good match. Values are per serving. Note: saturated_fat_g cannot "
            "currently be recorded and is reported back under `ignored_nutrients`."
        )
    )
    def log_custom_food(
        ctx: Context,
        name: Annotated[str, Field(description="Food name as it should appear in the diary.")],
        calories: Annotated[float, Field(description="Calories per serving.", ge=0)],
        meal: Annotated[
            str, Field(description="One of: breakfast, lunch, dinner, snacks.")
        ] = "snacks",
        brand: Annotated[
            str, Field(description="Brand or restaurant, e.g. 'Microsoft Gastrohub 75'.")
        ] = "",
        protein_g: Annotated[float | None, Field(description="Protein in grams.")] = None,
        carb_g: Annotated[float | None, Field(description="Carbohydrate in grams.")] = None,
        fat_g: Annotated[float | None, Field(description="Total fat in grams.")] = None,
        saturated_fat_g: Annotated[
            float | None, Field(description="Saturated fat in grams. Not currently recorded.")
        ] = None,
        fiber_g: Annotated[float | None, Field(description="Fiber in grams.")] = None,
        sugar_g: Annotated[float | None, Field(description="Sugar in grams.")] = None,
        sodium_mg: Annotated[float | None, Field(description="Sodium in milligrams.")] = None,
        cholesterol_mg: Annotated[
            float | None, Field(description="Cholesterol in milligrams.")
        ] = None,
        servings: Annotated[
            float, Field(description="How many of this serving to log.", gt=0)
        ] = 1.0,
        date: Annotated[
            str | None,
            Field(description="Day to log to: 'YYYY-MM-DD', 'today', or 'yesterday'."),
        ] = None,
        dry_run: Annotated[bool, Field(description="Preview without writing.")] = False,
    ) -> dict[str, Any]:
        with acquire(ctx) as svc:
            return svc.log_custom_food(
                name=name,
                calories=calories,
                meal=meal,
                brand=brand,
                protein_g=protein_g,
                carb_g=carb_g,
                fat_g=fat_g,
                saturated_fat_g=saturated_fat_g,
                fiber_g=fiber_g,
                sugar_g=sugar_g,
                sodium_mg=sodium_mg,
                cholesterol_mg=cholesterol_mg,
                servings=servings,
                when=date,
                dry_run=dry_run,
            )

    @mcp.tool(
        description=(
            "Delete a diary entry. Get the `entry_id` from get_diary for the same "
            "day. A recoverable copy is written to local trash before deleting."
        )
    )
    def delete_entry(
        ctx: Context,
        entry_id: Annotated[str, Field(description="`entry_id` from get_diary.")],
        date: Annotated[
            str | None,
            Field(description="The day the entry is on: 'YYYY-MM-DD', 'today', 'yesterday'."),
        ] = None,
    ) -> dict[str, Any]:
        with acquire(ctx) as svc:
            return svc.delete_entry(entry_id, when=date)

    @mcp.tool(
        description=(
            "Record a weigh-in for a day. The unit follows the account's display "
            "setting (lb or kg)."
        )
    )
    def log_weight(
        ctx: Context,
        weight: Annotated[float, Field(description="Body weight in the account's unit.", gt=0)],
        date: Annotated[
            str | None,
            Field(description="Day to record: 'YYYY-MM-DD', 'today', or 'yesterday'."),
        ] = None,
        dry_run: Annotated[bool, Field(description="Preview without writing.")] = False,
    ) -> dict[str, Any]:
        with acquire(ctx) as svc:
            return svc.log_weight(weight, when=date, dry_run=dry_run)

    @mcp.tool(
        description=(
            "Read recorded weigh-ins over a date range, with min/max/change "
            "summary. Defaults to the last 30 days. A single call may span at "
            "most about 10 years; ask for a wider history in several calls."
        )
    )
    def get_weight_history(
        ctx: Context,
        start: Annotated[
            str | None, Field(description="First day: 'YYYY-MM-DD'. Defaults to `days` back.")
        ] = None,
        end: Annotated[
            str | None, Field(description="Last day: 'YYYY-MM-DD'. Defaults to today.")
        ] = None,
        days: Annotated[
            int, Field(description="Window size when `start` is omitted.", ge=1, le=365)
        ] = 30,
    ) -> dict[str, Any]:
        with acquire(ctx) as svc:
            return svc.get_weight_history(start=start, end=end, days=days)

    @mcp.tool(
        description=(
            "Report the health and configuration of this MCP server: version, "
            "build, connectivity to Lose It, and which account the current "
            "request resolves to. Use this to diagnose problems — if other "
            "tools are failing, this says whether the cause is the server, the "
            "credentials, or Lose It itself."
        )
    )
    def server_status(ctx: Context) -> dict[str, Any]:
        from . import build_info

        status: dict[str, Any] = {
            "server": "loseit-mcp",
            "build": build_info(),
            "mode": "multi-tenant" if resolver is not None else "single-account",
            "credential_urls_enabled": sealer is not None,
        }

        # Resolving credentials and making a live call are separate failure
        # modes, so report them separately rather than collapsing both into a
        # single "unhealthy".
        try:
            with acquire(ctx) as svc:
                identity = svc.whoami()
                status["authenticated"] = True
                status["account"] = {
                    "user_name": identity.get("user_name"),
                    "email": identity.get("email"),
                    "hours_from_gmt": identity.get("hours_from_gmt"),
                }
                try:
                    # detail=False: this is a reachability probe, and enriching
                    # would make a nutrition failure look like Lose It being
                    # down when the search itself succeeded.
                    svc.search_food("water", limit=1, detail=False)
                    status["loseit_reachable"] = True
                except Exception as exc:  # noqa: BLE001 - reported, not raised
                    status["loseit_reachable"] = False
                    status["loseit_error"] = str(translate(exc))[:400]
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            status["authenticated"] = False
            status["auth_error"] = str(translate(exc))[:400]

        status["ok"] = bool(status.get("authenticated") and status.get("loseit_reachable"))
        return status

    @mcp.tool(description="Show which Lose It! account this server is authenticated as.")
    def whoami(ctx: Context) -> dict[str, Any]:
        with acquire(ctx) as svc:
            return svc.whoami()

    return mcp
