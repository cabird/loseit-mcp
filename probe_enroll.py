"""Adversarial probes against the enroll route and sealer."""

import json

from starlette.testclient import TestClient

from loseit_mcp.config import Settings
from loseit_mcp.sealed import UrlSealer
from loseit_mcp.server import build_server
from loseit_mcp.throttle import ThrottleMiddleware
from loseit_mcp.webapp import PathTokenMiddleware, add_enrollment_route

SECRET = b"kJ8x2mQ7vN4pL9wR3tY6uZ1aS5dF0gH8cV7bN2mX"
sealer = UrlSealer(SECRET)
mcp = build_server(Settings(hours_from_gmt=0), multi_tenant=True, sealer=sealer)
add_enrollment_route(mcp, sealer, mount_path="/mcp", enroll_secret="s3cret-value")
app = mcp.streamable_http_app(streamable_http_path="/mcp", transport_security=None)
app = PathTokenMiddleware(app, mount_path="/mcp")
app = ThrottleMiddleware(app)

c = TestClient(app, raise_server_exceptions=False)
body = {"email": "a@b.c", "password": "pw"}

print("no secret       ->", c.post("/enroll", json=body).status_code)
print("wrong secret    ->", c.post("/enroll", json=body, headers={"x-enroll-secret": "nope"}).status_code)
print("non-ascii secret->", end=" ")
r = c.post("/enroll", json=body, headers={"x-enroll-secret": "\u00ff\u00fe"})
print(r.status_code, r.text[:200])
print("right secret    ->", c.post("/enroll", json=body, headers={"x-enroll-secret": "s3cret-value"}).status_code)
