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

from .config import Settings
from .enrollment import EnrollmentRegistry
from .service import LoseItService
from .tenancy import SessionResolver, resolve_or_raise

INSTRUCTIONS = """\
Read and write the user's Lose It! food diary.

Typical flow for logging a meal:
1. `search_food` to find the food and get its `food_id`.
2. `log_food` with that `food_id`, a meal, and a portion.

Portions: pass `serving_amount` + `serving_unit` (e.g. 120 + "g") when you know
a concrete quantity, otherwise pass `servings` as a multiplier of the food's
default serving. Supply one form or the other, never both. Use `dry_run=true`
to preview the calorie math without writing.

If `search_food` has no good match — a restaurant dish, a homemade meal — use
`log_custom_food` to record the calories and macros directly instead of forcing
a bad match.

Deleting: call `get_diary` first to get an `entry_id`, then `delete_entry`.
"""


def build_server(
    settings: Settings,
    *,
    multi_tenant: bool = False,
    registry: EnrollmentRegistry | None = None,
) -> MCPServer:
    """Construct the MCP server.

    With ``multi_tenant`` set, each request must identify an account — either
    with credential headers or, when ``registry`` is supplied, via a
    ``/u/<token>/`` enrollment URL. Each request gets its own service instance,
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
        if resolver is None:
            assert shared is not None
            yield shared
            return
        service, _ = resolve_or_raise(resolver, ctx.headers or {}, registry)
        try:
            yield service
        finally:
            service.close()

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if shared is not None:
                shared.close()

    mcp = MCPServer(
        name="loseit",
        version="0.1.0",
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
    )

    @mcp.tool(
        description=(
            "Search the Lose It! food database. Returns candidate foods with a "
            "`food_id` to pass to log_food or describe_food."
        )
    )
    def search_food(
        ctx: Context,
        query: Annotated[str, Field(description="Food name to search for, e.g. 'greek yogurt'.")],
        limit: Annotated[int, Field(description="Max results to return.", ge=1, le=50)] = 10,
    ) -> list[dict[str, Any]]:
        with acquire(ctx) as svc:
            return svc.search_food(query, limit=limit)

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
            "summary. Defaults to the last 30 days."
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

    @mcp.tool(description="Show which Lose It! account this server is authenticated as.")
    def whoami(ctx: Context) -> dict[str, Any]:
        with acquire(ctx) as svc:
            return svc.whoami()

    return mcp
