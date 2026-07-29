"""Local probe: run the real serve stack with login stubbed out."""

import base64
import json
import os
import threading
import time

import uvicorn

os.environ["LOSEIT_ALLOWED_HOSTS"] = "localhost,127.0.0.1"

from loseit_mcp import auth as auth_mod
from loseit_mcp import tenancy as tenancy_mod
from loseit_mcp.auth import Session
from loseit_mcp.sealed import UrlSealer
from loseit_mcp.server import build_server
from loseit_mcp.config import Settings
from loseit_mcp.throttle import ThrottleMiddleware
from loseit_mcp.webapp import PathTokenMiddleware, add_enrollment_route

LOGINS = []


def _fake_jwt(email):
    payload = {"sub": "u-" + email, "exp": int(time.time()) + 3600, "name": email}
    b = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return "h." + b + ".s"


def fake_login(email, password, *, timeout=30.0):
    LOGINS.append((email, password, threading.current_thread().name))
    time.sleep(0.15)  # widen any race window
    return Session(
        token=_fake_jwt(email), user_id="uid-" + email, user_name="name-" + email, email=email
    )


auth_mod.login = fake_login
tenancy_mod.login = fake_login

SECRET = b"kJ8x2mQ7vN4pL9wR3tY6uZ1aS5dF0gH8cV7bN2mX"
sealer = UrlSealer(SECRET)

settings = Settings(hours_from_gmt=0)
mcp = build_server(settings, multi_tenant=True, sealer=sealer)
add_enrollment_route(mcp, sealer, mount_path="/mcp", enroll_secret=None)

app = mcp.streamable_http_app(streamable_http_path="/mcp", transport_security=None)
app = PathTokenMiddleware(app, mount_path="/mcp")
app = ThrottleMiddleware(app)

if __name__ == "__main__":
    with open("probe_urls.json", "w") as fh:
        json.dump(
            {
                "a": sealer.seal("alice@example.com", "pw-alice"),
                "b": sealer.seal("bob@example.com", "pw-bob"),
            },
            fh,
        )
    uvicorn.run(app, host="127.0.0.1", port=8972, log_level="warning")
