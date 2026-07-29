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

from datetime import date

from lose_it.core._config import Config
from lose_it.core._dates import day_number_for
from lose_it.core._gwt import build_envelope, fmt_num, parse_response
from lose_it.core._http import HttpClient
from lose_it.core.daily import get_daydate_key

_SERVICE = "com.loseit.core.client.service.LoseItRemoteService"
_REQUEST_TOKEN = "com.loseit.core.client.service.ServiceRequestToken/1076571655"
_DAY_DATE = "com.loseit.core.shared.model.DayDate/1611136587"
_USER_ID = "com.loseit.core.client.model.UserId/4281239478"
_DATE = "java.util.Date/3385151746"


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

    # The response opens with the saved value, so echo it back as confirmation
    # rather than trusting our own input.
    tokens, _ = parse_response(response)
    for token in tokens[:3]:
        if isinstance(token, int | float) and token > 0:
            return float(token)
    return weight
