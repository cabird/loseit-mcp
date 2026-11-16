"""Named zones at the boundary of Lose It's whole-hour-offset protocol."""

from datetime import date, datetime, time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def named_zone(name: str) -> ZoneInfo:
    if not isinstance(name, str) or not name or len(name) > 100:
        raise ValueError("Timezone must be an IANA name such as America/Los_Angeles.")
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(
            f"Unknown timezone {name!r}, or timezone data is unavailable. "
            "Install system timezone data (or tzdata) and use an IANA timezone name."
        ) from exc


def offset_for(name: str, day: date | None = None) -> int:
    """Resolve now, or local noon on a calendar date, without rounding offsets.

    Dated RPCs carry a calendar day, not a wall-clock timestamp. Noon avoids
    ambiguous/nonexistent local times at ordinary DST transitions.
    """
    zone = named_zone(name)
    when = datetime.now(zone) if day is None else datetime.combine(day, time(12), zone)
    offset = when.utcoffset()
    if offset is None or offset.total_seconds() % 3600:
        raise ValueError(
            f"Timezone {name!r} has a fractional-hour offset for this date; "
            "Lose It's SDK only supports whole-hour offsets."
        )
    hours = int(offset.total_seconds() // 3600)
    if not -12 <= hours <= 14:
        raise ValueError("Timezone offset must be between -12 and 14 hours for Lose It!.")
    return hours


def today_in_zone(name: str) -> date:
    # Validate the SDK boundary too, even for relative-date-only dry runs.
    offset_for(name)
    return datetime.now(named_zone(name)).date()
