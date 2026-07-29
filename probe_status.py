import asyncio
import json

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

U = json.load(open("probe_urls.json"))
A = U["a"]


async def call(url, tool, args=None, headers=None):
    async with httpx2.AsyncClient(headers=headers or {}, timeout=60) as hc:
        async with streamable_http_client(url, http_client=hc) as st:
            async with ClientSession(st[0], st[1]) as s:
                await s.initialize()
                r = await s.call_tool(tool, args or {})
                return r.content[0].text if r.content else None


async def main():
    print("== server_status via sealed url ==")
    print(await call("http://127.0.0.1:8972/u/" + A + "/mcp", "server_status"))
    for tool in ("whoami", "server_status"):
        print("== " + tool + " no creds ==")
        try:
            print(await call("http://127.0.0.1:8972/mcp", tool))
        except Exception as e:
            print("ERR", repr(e)[:400])
    print("== server_status with garbage sealed url ==")
    try:
        print(await call("http://127.0.0.1:8972/u/" + ("Z" * 60) + "/mcp", "server_status"))
    except Exception as e:
        print("ERR", repr(e)[:400])


asyncio.run(main())
