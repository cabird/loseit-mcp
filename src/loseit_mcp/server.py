"""MCP tool definitions for Lose It!.

Exposes the food diary as MCP tools. The same :class:`MCPServer` instance
serves both transports, so ``build_server()`` is shared by the stdio and
streamable-HTTP entry points in :mod:`loseit_mcp.cli`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from .config import Settings
from .service import LoseItService

INSTRUCTIONS = """\
Read and write the user's Lose It! food diary.

Typical flow for logging a meal:
1. `search_food` to find the food and get its `food_id`.
2. `log_food` with that `food_id`, a meal, and a portion.

Portions: pass `serving_amount` + `serving_unit` (e.g. 120 + "g") when you know
a concrete quantity, otherwise pass `servings` as a multiplier of the food's
default serving. Use `dry_run=true` to preview the calorie math without
writing.

If `search_food` has no good match — a restaurant dish, a homemade meal — use
`log_custom_food` to record the calories and macros directly instead of forcing
a bad match.

Deleting: call `get_diary` first to get an `entry_id`, then `delete_entry`.
"""


def build_server(settings: Settings) -> MCPServer:
    """Construct the MCP server bound to a configured Lose It! account."""
    service = LoseItService(settings)

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[None]:
        try:
            yield
        finally:
            # Release the HTTP connection pool on shutdown rather than leaking
            # it for the life of the process.
            service.close()

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
        query: Annotated[str, Field(description="Food name to search for, e.g. 'greek yogurt'.")],
        limit: Annotated[int, Field(description="Max results to return.", ge=1, le=50)] = 10,
    ) -> list[dict[str, Any]]:
        return service.search_food(query, limit=limit)

    @mcp.tool(
        description=(
            "Get full nutrition detail and serving information for one food, "
            "identified by the `food_id` returned from search_food."
        )
    )
    def describe_food(
        food_id: Annotated[str, Field(description="32-character hex food ID.")],
    ) -> dict[str, Any]:
        return service.describe_food(food_id)

    @mcp.tool(
        description=(
            "Read the food diary for a day: every logged entry with calories and "
            "macros, plus the day's totals. Each entry carries an `entry_id` for "
            "delete_entry."
        )
    )
    def get_diary(
        date: Annotated[
            str | None,
            Field(description="Day to read: 'YYYY-MM-DD', 'today', or 'yesterday'."),
        ] = None,
    ) -> dict[str, Any]:
        return service.get_diary(date)

    @mcp.tool(
        description=(
            "Log a food to a meal in the diary. Specify the portion EITHER as "
            "`serving_amount` + `serving_unit` (e.g. 120 and 'g') OR as `servings` "
            "(a multiplier of the food's default serving). Set dry_run to preview."
        )
    )
    def log_food(
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
        return service.log_food(
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
            "good match. Values are per serving."
        )
    )
    def log_custom_food(
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
            float | None, Field(description="Saturated fat in grams.")
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
        return service.log_custom_food(
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
        entry_id: Annotated[str, Field(description="`entry_id` from get_diary.")],
        date: Annotated[
            str | None,
            Field(description="The day the entry is on: 'YYYY-MM-DD', 'today', 'yesterday'."),
        ] = None,
    ) -> dict[str, Any]:
        return service.delete_entry(entry_id, when=date)

    @mcp.tool(
        description=(
            "Record a weigh-in for a day. The unit follows the account's display "
            "setting (lb or kg)."
        )
    )
    def log_weight(
        weight: Annotated[float, Field(description="Body weight in the account's unit.", gt=0)],
        date: Annotated[
            str | None,
            Field(description="Day to record: 'YYYY-MM-DD', 'today', or 'yesterday'."),
        ] = None,
        dry_run: Annotated[bool, Field(description="Preview without writing.")] = False,
    ) -> dict[str, Any]:
        return service.log_weight(weight, when=date, dry_run=dry_run)

    @mcp.tool(
        description=(
            "Read recorded weigh-ins over a date range, with min/max/change "
            "summary. Defaults to the last 30 days."
        )
    )
    def get_weight_history(
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
        return service.get_weight_history(start=start, end=end, days=days)

    @mcp.tool(description="Show which Lose It! account this server is authenticated as.")
    def whoami() -> dict[str, Any]:
        return service.whoami()

    return mcp
