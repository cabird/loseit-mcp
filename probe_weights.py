"""Count upstream RPCs a single get_weight_history tool call can trigger."""

from datetime import date

import loseit_mcp.weight as weight_mod
from loseit_mcp.service import LoseItService
from loseit_mcp.config import Settings
from loseit_mcp.auth import Session

CALLS = {"n": 0}


def fake_fetch_window(http, start_num, end_num):
    CALLS["n"] += 1
    return [], False


weight_mod._fetch_window = fake_fetch_window


class FakeHttp:
    config = None


class FakeClient:
    http = FakeHttp()

    def close(self):
        pass


def fake_resolve(settings, *, force_login=False):
    return Session(token="t", user_id="1", user_name="n", email="e@x.y")


import loseit_mcp.service as service_mod

service_mod.resolve_session = fake_resolve


class Probe(LoseItService):
    def _build_client(self, session):
        return FakeClient()


svc = Probe(Settings(email="e@x.y", password="pw", hours_from_gmt=0))

for kwargs in (
    {"days": 30},
    {"days": 365},
    {"start": "1970-01-01", "end": "2026-07-29"},
    {"start": "0001-01-01", "end": "9999-12-31"},
):
    CALLS["n"] = 0
    res = svc.get_weight_history(**kwargs)
    print(kwargs, "-> upstream RPCs:", CALLS["n"], "| span:", res["start"], "to", res["end"])
