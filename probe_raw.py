"""Raw-ASGI probes: send byte headers a normal client library refuses to build."""

import json

import anyio

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


async def raw_post(path, headers, body: bytes):
    out = {"status": None, "body": b""}
    sent = {"done": False}

    async def receive():
        if not sent["done"]:
            sent["done"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            out["body"] += msg.get("body", b"")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("10.0.0.1", 5555),
        "server": ("testserver", 80),
    }
    try:
        await app(scope, receive, send)
    except Exception as exc:  # noqa: BLE001
        return "EXC:" + type(exc).__name__ + ": " + str(exc)[:160]
    return out["status"], out["body"][:180]


BODY = json.dumps({"email": "a@b.c", "password": "pw"}).encode()
BASE = [(b"host", b"testserver"), (b"content-type", b"application/json"),
        (b"content-length", str(len(BODY)).encode())]


async def main():
    print("wrong secret   ->", await raw_post("/enroll", BASE + [(b"x-enroll-secret", b"nope")], BODY))
    print("non-ascii sec  ->", await raw_post("/enroll", BASE + [(b"x-enroll-secret", b"\xff\xfe")], BODY))
    print("correct secret ->", await raw_post("/enroll", BASE + [(b"x-enroll-secret", b"s3cret-value")], BODY))


anyio.run(main)
