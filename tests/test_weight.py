"""Weight recording and history.

The history regression is the important one: an oversize response degraded to a
partial decode whose only surviving records were out-of-range anchors, so a
year-long query confidently answered "no weigh-ins".
"""

from __future__ import annotations

from datetime import date, timedelta
from itertools import pairwise
from typing import Any

import pytest
from lose_it.core._dates import day_number_for

from loseit_mcp import weight as W
from loseit_mcp.weight import (
    MAX_RANGE_DAYS,
    WeightHistoryError,
    _build_payload,
    _num_to_date,
    get_weight_history,
    save_weight,
)


class FakeConfig:
    base_url = "https://example.invalid/web/"
    policy_hash = "POLICY"
    user_id = "10313492"
    user_name = "Tester"
    hours_from_gmt = -7


def _recorded_weight(day_num: int, value: float) -> dict[str, Any]:
    return {
        "__type__": "com.loseit.core.client.model.RecordedWeight/1309383152",
        "f0": {
            "__type__": "com.loseit.core.shared.model.DayDate/1611136587",
            "f1": day_num,
        },
        "f1": False,
        "f2": 1785288782000,
        "f3": value,
    }


class TestDayNumberMapping:
    """The mapping is pure ordinal arithmetic, so it must be DST- and
    timezone-immune."""

    @pytest.mark.parametrize(
        "anchor",
        [
            date(2025, 3, 8),   # US DST spring-forward
            date(2025, 11, 1),  # US DST fall-back
            date(2024, 2, 29),  # leap day
            date(2026, 7, 28),
        ],
    )
    def test_round_trips_across_dst_and_leap_boundaries(self, anchor: date) -> None:
        start_num = day_number_for(anchor)
        for offset in range(-400, 401):
            target = anchor + timedelta(days=offset)
            assert _num_to_date(anchor, start_num, day_number_for(target)) == target


class TestSaveWeight:
    def test_payload_carries_method_and_values(self) -> None:
        payload = _build_payload(FakeConfig(), 199.2, "DAYKEY", 9340)
        assert "saveRecordedWeight" in payload
        assert "199.2" in payload
        assert "DAYKEY" in payload
        assert payload.startswith("7|0|10|")

    def test_integer_weights_are_not_rendered_as_floats(self) -> None:
        assert "|200|" in _build_payload(FakeConfig(), 200.0, "K", 1)

    def test_echo_is_trusted_only_when_it_corroborates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Regression: the echo scanned for the first positive number in the
        response preamble, which is not a stable slot across RPCs."""
        monkeypatch.setattr(W, "get_daydate_key", lambda *a, **k: "K")

        class Http:
            config = FakeConfig()

            def __init__(self, body: str) -> None:
                self._body = body

            def post_rpc(self, payload: str) -> str:
                return self._body

        # Server echoes the value we sent -> trusted.
        assert save_weight(Http('//OK[0,199.2,"X",1,["a"],0,7]'), 199.2, date(2026, 7, 28)) == 199.2

        # Response leads with an unrelated quantity -> fall back to our input
        # rather than reporting a confidently wrong confirmation.
        assert save_weight(Http('//OK[0,170.4,2425.9,1,["a"],0,7]'), 199.2, date(2026, 7, 28)) == 199.2


class TestWeightHistory:
    def _install(
        self, monkeypatch: pytest.MonkeyPatch, windows: list[tuple[list[dict], bool]]
    ) -> list[tuple[int, int]]:
        """Record which day-number windows get requested."""
        seen: list[tuple[int, int]] = []
        queue = list(windows)

        def fake_fetch(http: Any, start_num: int, end_num: int) -> tuple[list[dict], bool]:
            seen.append((start_num, end_num))
            return queue.pop(0) if queue else ([], False)

        monkeypatch.setattr(W, "_fetch_window", fake_fetch)
        return seen

    def test_rejects_backwards_range(self) -> None:
        with pytest.raises(ValueError):
            get_weight_history(None, date(2026, 7, 28), date(2026, 7, 1))

    def test_filters_out_of_range_anchor_weights(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The response carries the account's starting weight from years ago."""
        start, end = date(2026, 7, 21), date(2026, 7, 23)
        s = day_number_for(start)
        self._install(
            monkeypatch,
            [([_recorded_weight(s, 201.0), _recorded_weight(4777, 235.0)], False)],
        )
        out = get_weight_history(None, start, end)
        assert [e["weight"] for e in out] == [201.0]

    def test_long_ranges_are_chunked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        start = date(2025, 7, 28)
        end = date(2026, 7, 28)
        seen = self._install(monkeypatch, [])
        get_weight_history(None, start, end)

        assert len(seen) > 1, "a year must not be requested as one window"
        assert all(e - s + 1 <= MAX_RANGE_DAYS for s, e in seen)
        # Contiguous and complete.
        assert seen[0][0] == day_number_for(start)
        assert seen[-1][1] == day_number_for(end)
        for (_, prev_end), (next_start, _) in pairwise(seen):
            assert next_start == prev_end + 1

    def test_partial_decode_bisects_rather_than_returning_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: a partial decode silently produced zero weigh-ins."""
        start, end = date(2026, 6, 1), date(2026, 6, 4)
        s = day_number_for(start)
        # First call reports partial; the two halves then succeed.
        self._install(
            monkeypatch,
            [
                ([], True),
                ([_recorded_weight(s, 200.0)], False),
                ([_recorded_weight(s + 2, 199.0)], False),
            ],
        )
        out = get_weight_history(None, start, end)
        assert [e["weight"] for e in out] == [200.0, 199.0]

    def test_single_day_partial_decode_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        day = date(2026, 6, 1)
        self._install(monkeypatch, [([], True)])
        with pytest.raises(WeightHistoryError):
            get_weight_history(None, day, day)

    def test_results_are_sorted_and_deduplicated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        start, end = date(2026, 6, 1), date(2026, 6, 3)
        s = day_number_for(start)
        self._install(
            monkeypatch,
            [([_recorded_weight(s + 2, 3.0), _recorded_weight(s, 1.0), _recorded_weight(s, 1.0)], False)],
        )
        out = get_weight_history(None, start, end)
        assert [e["date"] for e in out] == ["2026-06-01", "2026-06-03"]

    def test_malformed_nodes_are_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        start = date(2026, 6, 1)
        s = day_number_for(start)
        bad = {"__type__": W._RECORDED_WEIGHT, "f0": None, "f3": "not-a-number"}
        self._install(monkeypatch, [([bad, _recorded_weight(s, 1.0)], False)])
        assert len(get_weight_history(None, start, start)) == 1
