"""Drive the probe server with the real MCP client, concurrently."""

import asyncio
import json

from mcp import ClientSession
import httpx2
from mcp.client.streamable_http import streamable_http_client

URLS = json.load(open("probe_urls.json"))
BASE = "http://127.0.0.1:8972"


async def call(sealed, tool, args=None, headers=None, n=1):
    url = f"{BASE}/u/{sealed}/mcp" if sealed else f"{BASE}/mcp"
    out = []
    async with httpx2.AsyncClient(headers=headers or {}, timeout=60) as hc:
      async with streamable_http_client(url, http_client=hc) as streams:
        r, w = streams[0], streams[1]
        async with ClientSession(r, w) as s:
            await s.initialize()
            for _ in range(n):
                res = await s.call_tool(tool, args or {})
                out.append(res.content[0].text if res.content else None)
    return out


async def main():
    # 1. Sequential sanity
    print("--- alice whoami ---")
    print((await call(URLS["a"], "whoami"))[0])
    print("--- bob whoami ---")
    print((await call(URLS["b"], "whoami"))[0])

    # 2. Concurrent, two different sealed URLs, repeated
    print("--- concurrent interleave x8 ---")
    tasks = []
    for _ in range(8):
        tasks.append(call(URLS["a"], "whoami"))
        tasks.append(call(URLS["b"], "whoami"))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    bad = 0
    for i, r in enumerate(results):
        want = "alice" if i % 2 == 0 else "bob"
        txt = str(r)
        if want not in txt:
            bad += 1
            print("MISMATCH", i, "want", want, "got", txt[:200])
    print("mismatches:", bad, "of", len(results))

    # 3. Same session, many calls in sequence
    print("--- alice 3 calls one session ---")
    print(await call(URLS["a"], "whoami", n=3))

    # 4. header creds override sealed url
    print("--- bob url + alice headers ---")
    import base64

    b = base64.b64encode(b"alice@example.com:pw-alice").decode()
    print((await call(URLS["b"], "whoami", headers={"Authorization": f"Basic {b}"}))[0])

    # 5. server_status
    print("--- server_status (alice) ---")
    print((await call(URLS["a"], "server_status"))[0])

    # 6. no credential at all
    print("--- bare /mcp no creds ---")
    try:
        print((await call(None, "whoami"))[0])
    except Exception as e:
        print("ERR", type(e).__name__, e)


asyncio.run(main())
