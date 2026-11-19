"""End-to-end: real web app, real proxy, real upstream HTTP server."""

from __future__ import annotations

import asyncio
import contextlib
import socket
from dataclasses import replace

import httpx
import pytest
import uvicorn

from app.config import Settings
from app.web import create_app

from conftest import read_head


def free_port() -> int:
    """Best-effort free port; the fixture retries startup if it is stolen."""

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def start_http_upstream(response_body: bytes = b"hello from upstream"):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(response_body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + response_body
            )
            await writer.drain()
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.fixture
async def live_app(tmp_path):
    upstream_server, upstream_port = await start_http_upstream()
    proxy_port = free_port()
    web_port = free_port()
    settings = Settings(
        db_path=str(tmp_path / "e2e.db"),
        proxy_host="127.0.0.1",
        proxy_port=proxy_port,
        web_host="127.0.0.1",
        web_port=web_port,
        dns_timeout=1.0,
        connect_timeout=2.0,
        header_timeout=2.0,
        idle_timeout=30.0,
        max_header_bytes=8192,
        test_connect_timeout=3.0,
        demo_host="localhost",
        demo_port=upstream_port,
        demo_cidr="127.0.0.0/8",
        bootstrap_rules=(
            {"host": "localhost", "ports": [upstream_port], "networks": ["127.0.0.0/8"]},
        ),
    )
    # Retry the whole startup if either listener lost its port to another test.
    last_error: Exception | None = None
    for _ in range(10):
        app = create_app(settings)
        config = uvicorn.Config(
            app, host="127.0.0.1", port=web_port, log_level="warning", lifespan="on"
        )
        server = uvicorn.Server(config)
        task = asyncio.create_task(server.serve())
        for _ in range(300):
            if server.started:
                break
            if task.done():
                break
            await asyncio.sleep(0.01)
        if server.started:
            break
        last_error = RuntimeError(f"uvicorn failed to start on {web_port}/{proxy_port}")
        with contextlib.suppress(Exception):
            await asyncio.wait_for(task, timeout=3)
        proxy_port = free_port()
        web_port = free_port()
        settings = replace(settings, proxy_port=proxy_port, web_port=web_port)
    else:
        raise last_error or RuntimeError("could not start live app")
    try:
        yield {
            "app": app,
            "settings": settings,
            "web_port": web_port,
            "proxy_port": proxy_port,
            "upstream_port": upstream_port,
        }
    finally:
        server.should_exit = True
        with contextlib.suppress(Exception):
            await asyncio.wait_for(task, timeout=5)
        upstream_server.close()
        await upstream_server.wait_closed()


def http_base(ctx) -> str:
    return f"http://127.0.0.1:{ctx['web_port']}"


async def test_web_ui_and_bootstrap_rule(live_app):
    async with httpx.AsyncClient(base_url=http_base(live_app), timeout=5) as client:
        page = await client.get("/")
        assert page.status_code == 200
        assert "受控出口代理" in page.text

        health = await client.get("/api/health")
        assert health.status_code == 200

        rules = (await client.get("/api/rules")).json()
        assert rules["revision"] == 1
        assert rules["rules"][0]["host"] == "localhost"

        config = (await client.get("/api/config")).json()
        assert config["demo_port"] == live_app["upstream_port"]


async def test_probe_endpoint_connects_through_proxy(live_app):
    async with httpx.AsyncClient(base_url=http_base(live_app), timeout=10) as client:
        res = await client.post("/api/probe", json={})
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["ok"] is True, data
        assert data["proxy_status"] == 200
        assert "hello from upstream" in data["body"]

        records = (await client.get("/api/admissions")).json()
        assert records["total"] >= 1
        assert any(row["decision"] == "allowed" for row in records["items"])


async def test_probe_reports_denied_target(live_app):
    async with httpx.AsyncClient(base_url=http_base(live_app), timeout=10) as client:
        res = await client.post(
            "/api/probe", json={"host": "nope.invalid", "port": live_app["upstream_port"]}
        )
        data = res.json()
        assert data["ok"] is False
        assert data["proxy_status"] == 403
        detail = (await client.get("/api/admissions?decision=denied")).json()
        assert detail["total"] >= 1


async def test_put_rules_validation_is_atomic(live_app):
    async with httpx.AsyncClient(base_url=http_base(live_app), timeout=5) as client:
        before = (await client.get("/api/rules")).json()
        bad = await client.put(
            "/api/rules",
            json={"rules": [{"host": "x.test", "ports": [0], "networks": ["10.0.0.0/8"]}]},
        )
        assert bad.status_code == 422
        assert bad.json()["errors"]
        after = (await client.get("/api/rules")).json()
        assert after["revision"] == before["revision"]

        good = await client.put(
            "/api/rules",
            json={"rules": [{"host": "new.test", "ports": [443], "networks": ["10.0.0.0/8"]}],
                  "note": "tighten"},
        )
        assert good.status_code == 200
        assert good.json()["revision"] == before["revision"] + 1

        revisions = (await client.get("/api/rules/revisions")).json()
        assert revisions["items"][0]["revision"] == before["revision"] + 1


async def test_connect_through_real_proxy_and_http_upstream(live_app):
    reader, writer = await asyncio.open_connection("127.0.0.1", live_app["proxy_port"])
    target = f"localhost:{live_app['upstream_port']}"
    writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    await writer.drain()
    status, _, _ = await read_head(reader)
    assert status == 200
    writer.write(f"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(), timeout=5)
    assert b"hello from upstream" in raw
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()

    async with httpx.AsyncClient(base_url=http_base(live_app), timeout=5) as client:
        row = (await client.get("/api/admissions?decision=allowed")).json()["items"][0]
        await asyncio.sleep(0.2)
        row = (await client.get(f"/api/admissions/{row['id']}")).json()
        assert row["revision"] == 1
        assert row["status"] == "closed"
        assert row["bytes_client_to_target"] > 0
        assert row["bytes_target_to_client"] > 0


async def test_rule_update_interleaved_with_connections(live_app):
    """Hammer CONNECT while rules flip; each tunnel reports one revision."""

    async with httpx.AsyncClient(base_url=http_base(live_app), timeout=5) as client:
        stable = {"host": "localhost", "ports": [live_app["upstream_port"]],
                  "networks": ["127.0.0.0/8"]}
        empty: list = []

        statuses: list[int] = []

        async def one_connection() -> None:
            reader, writer = await asyncio.open_connection("127.0.0.1", live_app["proxy_port"])
            target = f"localhost:{live_app['upstream_port']}"
            writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            await writer.drain()
            status, _, _ = await read_head(reader)
            statuses.append(status)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

        async def flip() -> None:
            for i in range(12):
                await client.put("/api/rules", json={"rules": empty if i % 2 else [stable]})
                await asyncio.sleep(0.01)

        await asyncio.gather(flip(), *[one_connection() for _ in range(40)])
        assert set(statuses) <= {200, 403}
        assert 200 in statuses

        items = (await client.get("/api/admissions?limit=200")).json()["items"]
        allowed = [row for row in items if row["decision"] == "allowed"]
        assert allowed
        assert all(row["revision"] is not None for row in allowed)
        # Each denial was judged at a revision too.
        denied = [row for row in items if row["decision"] == "denied"]
        assert all(row["revision"] is not None for row in denied)


async def test_summary_route_not_shadowed_by_id(live_app):
    async with httpx.AsyncClient(base_url=http_base(live_app), timeout=5) as client:
        res = await client.get("/api/admissions/summary")
        assert res.status_code == 200
        assert "total" in res.json()


async def test_oversized_request_body_rejected(live_app):
    async with httpx.AsyncClient(base_url=http_base(live_app), timeout=5) as client:
        res = await client.put(
            "/api/rules", content=b"x" * (600 * 1024), headers={"Content-Type": "application/json"}
        )
        assert res.status_code == 413


async def test_concurrent_rule_commits_are_serialized(live_app):
    async with httpx.AsyncClient(base_url=http_base(live_app), timeout=10) as client:
        base = (await client.get("/api/rules")).json()["revision"]
        rules = [{"host": f"h{i}.test", "ports": [443], "networks": ["10.0.0.0/8"]} for i in range(10)]
        results = await asyncio.gather(
            *[client.put("/api/rules", json={"rules": rules[: i + 1]}) for i in range(10)]
        )
        assert all(r.status_code == 200 for r in results)
        revisions = sorted(r.json()["revision"] for r in results)
        assert revisions == list(range(base + 1, base + 11))
        latest = (await client.get("/api/rules")).json()
        assert latest["revision"] == base + 10
