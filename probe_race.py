"""Demonstrate the shared-LoseItService close-during-request race."""

import threading
import time

from lose_it.core._http import LoseItError

from loseit_mcp.config import Settings
from loseit_mcp.service import LoseItService
from loseit_mcp.auth import Session

CALLS = {"n": 0}
ERRORS = []


class FakeClient:
    def __init__(self, tag):
        self.tag = tag
        self.closed = False

    def close(self):
        self.closed = True

    def search(self, q):
        # Simulate an in-flight HTTP request.
        time.sleep(0.30)
        if self.closed:
            raise RuntimeError(
                "Cannot send a request, as the client has been closed. "
                f"(client {self.tag} was closed mid-request)"
            )
        return []


class Probe(LoseItService):
    def __init__(self, settings):
        super().__init__(settings)
        self._n = 0

    def _build_client(self, session):
        self._n += 1
        return FakeClient(self._n)


def fake_resolve(settings, *, force_login=False):
    time.sleep(0.05)
    return Session(token="t", user_id="1", user_name="n", email="e@x.y")


import loseit_mcp.service as service_mod

service_mod.resolve_session = fake_resolve

svc = Probe(Settings(email="e@x.y", password="pw", hours_from_gmt=0))
svc.client  # prime


def reader():
    try:
        svc._retrying(lambda: svc.client.search("water"))
    except Exception as exc:  # noqa: BLE001
        ERRORS.append(repr(exc))


def reauther():
    time.sleep(0.10)  # let the reader get into its request
    svc._reauthenticate()


t1 = threading.Thread(target=reader)
t2 = threading.Thread(target=reauther)
t1.start()
t2.start()
t1.join()
t2.join()

print("errors seen by the concurrent reader:")
for e in ERRORS:
    print("  ", e)
print("race reproduced:", bool(ERRORS))
