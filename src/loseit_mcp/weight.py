"""Weight recording via the ``saveRecordedWeight`` GWT-RPC method.

Not covered by the upstream SDK, so the envelope is built here. Captured from
the web app's "today's weight" widget:

    7|0|10|<base>|<policy>|<service>|saveRecordedWeight
      |<ServiceRequestToken>|D|<DayDate>|<UserId>|<user_name>|<Date>
      |1|2|3|4|3|5|6|7|5|0|8|<user_id>|9|<tz>|<weight>|7|10|<day_key>|<day_num>|<tz>|

The three arguments are the request token, a primitive ``double`` (the weight,
in the account's display unit), and the ``DayDate`` to record it against.

The UI also calls ``isRecordedWeightSuspect`` first, which is a client-side
sanity prompt for implausible jumps rather than a precondition for saving, so
it is not replicated here.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

import lose_it.core.daily as _daily
from lose_it.core._config import Config
from lose_it.core._dates import day_number_for
from lose_it.core._decoder import decode_response
from lose_it.core._gwt import build_envelope, fmt_num, parse_response
from lose_it.core._http import HttpClient
from lose_it.core.daily import get_daydate_key

_SERVICE = "com.loseit.core.client.service.LoseItRemoteService"
_REQUEST_TOKEN = "com.loseit.core.client.service.ServiceRequestToken/1076571655"
_DAY_DATE = "com.loseit.core.shared.model.DayDate/1611136587"
_USER_ID = "com.loseit.core.client.model.UserId/4281239478"
_DATE = "java.util.Date/3385151746"

_RECORDED_WEIGHT = "com.loseit.core.client.model.RecordedWeight/1309383152"

# The server accepts this placeholder wherever a day_key is expected but not
# cached; it only really keys off day_num.
_FALLBACK_DAY_KEY = "ZZZZZZZ"

# Range responses grow with the number of logged entries, and past roughly
# 200 KB the SDK's decoder degrades to a partial result. 60 days keeps us well
# inside that limit for a heavily-logged account.
MAX_RANGE_DAYS = 60

# Bisection bound, so a pathological response can't fan out unboundedly.
MAX_BISECT_DEPTH = 7


class WeightHistoryError(RuntimeError):
    """The weight history could not be read reliably."""


def _build_payload(config: Config, weight: float, day_key: str, day_num: int) -> str:
    strings = [
        config.base_url,  # 1
        config.policy_hash,  # 2
        _SERVICE,  # 3
        "saveRecordedWeight",  # 4
        _REQUEST_TOKEN,  # 5
        "D",  # 6 — primitive double
        _DAY_DATE,  # 7
        _USER_ID,  # 8
        config.user_name,  # 9
        _DATE,  # 10
    ]
    tz = str(config.hours_from_gmt)
    data = [
        "1",
        "2",
        "3",
        "4",
        "3",  # three arguments follow
        "5",  # arg 1 type: ServiceRequestToken
        "6",  # arg 2 type: double
        "7",  # arg 3 type: DayDate
        # arg 1 value
        "5",
        "0",
        "8",
        str(config.user_id),
        "9",
        tz,
        # arg 2 value
        fmt_num(weight),
        # arg 3 value
        "7",
        "10",
        day_key,
        str(day_num),
        tz,
    ]
    return build_envelope(strings, data)


def save_weight(http: HttpClient, weight: float, when: date) -> float:
    """Record ``weight`` for ``when``; returns the weight the server echoes back.

    The weight is interpreted in whatever unit the account displays (lb or kg);
    the API carries no unit of its own.
    """
    day_num = day_number_for(when)
    day_key = get_daydate_key(http, day_num) or ""
    payload = _build_payload(http.config, weight, day_key, day_num)
    response = http.post_rpc(payload)

    # The response leads with the saved value, but the surrounding slots are
    # response-shape-specific and a bare positional scan can pick up an
    # unrelated number. Only trust the echo when it corroborates what we sent;
    # a confidently wrong confirmation is worse than none.
    tokens, _ = parse_response(response)
    for token in tokens[:3]:
        if isinstance(token, int | float) and token > 0 and abs(float(token) - weight) <= 0.5:
            return float(token)
    return weight


def _walk(node: Any, out: list[dict[str, Any]]) -> None:
    """Collect every RecordedWeight object nested anywhere in a decoded tree."""
    if isinstance(node, dict):
        if node.get("__type__") == _RECORDED_WEIGHT:
            out.append(node)
        for value in node.values():
            _walk(value, out)
    elif isinstance(node, list):
        for value in node:
            _walk(value, out)


def _epoch_ms_to_iso(millis: Any) -> str | None:
    if not isinstance(millis, int | float) or millis <= 0:
        return None
    return datetime.fromtimestamp(millis / 1000, tz=UTC).isoformat()


def _fetch_window(
    http: HttpClient,
    start_num: int,
    end_num: int,
) -> tuple[list[dict[str, Any]], bool]:
    """Fetch one range window; returns (RecordedWeight nodes, was_partial)."""
    payload = _daily.build_range_payload(
        http.config,
        start_num,
        _FALLBACK_DAY_KEY,
        end_num,
        _FALLBACK_DAY_KEY,
    )
    decoded = decode_response(http.post_rpc(payload))
    partial = bool(isinstance(decoded, dict) and decoded.get("__partial__"))
    found: list[dict[str, Any]] = []
    _walk(decoded, found)
    return found, partial


def _collect_window(
    http: HttpClient,
    window_start: int,
    window_end: int,
    into: dict[int, dict[str, Any]],
    origin: date,
    origin_num: int,
    depth: int = 0,
) -> None:
    """Fetch one window, bisecting when the response is too large to decode.

    Response size scales with how much was logged, not with the number of days,
    so no fixed window is safe for every account or period. On a partial decode
    we halve the window and retry rather than guessing — and rather than
    returning the empty result an undetected partial decode would produce.
    """
    found, partial = _fetch_window(http, window_start, window_end)

    if partial:
        if window_start >= window_end:
            raise WeightHistoryError(
                "A single day's Lose It! response was too large to decode "
                f"({_num_to_date(origin, origin_num, window_start).isoformat()})."
            )
        if depth >= MAX_BISECT_DEPTH:
            raise WeightHistoryError(
                "Could not decode the Lose It! weight history even after "
                f"{depth} range subdivisions. Try a shorter date range."
            )
        midpoint = window_start + (window_end - window_start) // 2
        _collect_window(http, window_start, midpoint, into, origin, origin_num, depth + 1)
        _collect_window(http, midpoint + 1, window_end, into, origin, origin_num, depth + 1)
        return

    for node in found:
        day_date = node.get("f0") or {}
        day_num = day_date.get("f1") if isinstance(day_date, dict) else None
        weight = node.get("f3")
        if not isinstance(day_num, int) or not isinstance(weight, int | float):
            continue
        # Anchor weights (starting weight, goal baselines) ride along outside
        # the requested window; drop anything we didn't ask for.
        if not (window_start <= day_num <= window_end):
            continue
        into[day_num] = {
            "date": _num_to_date(origin, origin_num, day_num).isoformat(),
            "weight": round(float(weight), 2),
            "recorded_at": _epoch_ms_to_iso(node.get("f2")),
        }


def get_weight_history(
    http: HttpClient,
    start: date,
    end: date,
    *,
    chunk_days: int = MAX_RANGE_DAYS,
) -> list[dict[str, Any]]:
    """Return recorded weigh-ins for the inclusive range ``[start, end]``.

    Read-only: this reuses ``getDailyDetailsIncludingPendingForDateRange``,
    whose payload embeds a ``RecordedWeight`` per day, rather than
    ``saveRecordedWeight`` (which would write).

    The request is split into windows of at most ``chunk_days``, and any window
    whose response is still too large is bisected further. A single wide range
    overflows the SDK decoder and degrades to a partial decode in which the only
    surviving ``RecordedWeight`` nodes are out-of-range anchors — so an
    unchunked year-long query would otherwise return "no weigh-ins" rather than
    failing.
    """
    if end < start:
        raise ValueError(f"end {end.isoformat()} is before start {start.isoformat()}")

    start_num = day_number_for(start)
    end_num = day_number_for(end)
    span = max(1, min(chunk_days, MAX_RANGE_DAYS))

    by_day: dict[int, dict[str, Any]] = {}
    window_start = start_num
    while window_start <= end_num:
        window_end = min(window_start + span - 1, end_num)
        _collect_window(http, window_start, window_end, by_day, start, start_num)
        window_start = window_end + 1

    return [by_day[k] for k in sorted(by_day)]


def _num_to_date(start: date, start_num: int, day_num: int) -> date:
    """Map a Lose It day number back to a calendar date.

    Both directions are plain proleptic-ordinal arithmetic (``day_number_for``
    is ``anchor + (d - anchor).days``), so this is timezone- and DST-immune.
    """
    return start + timedelta(days=day_num - start_num)
