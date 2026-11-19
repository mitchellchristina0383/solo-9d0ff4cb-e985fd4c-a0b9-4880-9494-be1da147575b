"""Bundled demo service reachable only through the proxy.

* ``GET /``         – small HTML page, used by the test-connect probe.
* ``POST /echo``    – echoes the request body back.
* ``GET /slow``     – trickles bytes with delays, useful for half-close tests.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse

app = FastAPI(title="Egress Demo Service", docs_url=None, openapi_url=None)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>demo</title></head>
<body style="font-family:system-ui;background:#0f1419;color:#e6edf3;padding:40px">
<h1>演示服务已连通</h1>
<p>你通过受控代理到达了容器内的演示服务。</p>
<ul>
  <li>时间：<code>{now}</code></li>
  <li>进程：<code>demo</code></li>
</ul>
<p><code>POST /echo</code> 回显请求体；<code>GET /slow</code> 慢速输出。</p>
</body></html>"""


@app.post("/echo", response_class=PlainTextResponse)
async def echo(request: Request) -> str:
    body = await request.body()
    return body.decode("utf-8", errors="replace")


@app.get("/slow")
async def slow() -> StreamingResponse:
    async def generate():
        for index in range(10):
            yield f"chunk {index}\n".encode()
            await asyncio.sleep(0.25)

    return StreamingResponse(generate(), media_type="text/plain")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(
        "demo.demo_app:app",
        host=os.environ.get("DEMO_BIND", "0.0.0.0"),
        port=int(os.environ.get("DEMO_PORT", "8080")),
        log_level="info",
    )
