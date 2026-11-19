"""Dialer and DNS-pinning unit tests, plus concurrency stress."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket

import pytest

from app.proxy import PinnedDialer, ProxyError, SystemResolver


async def test_system_resolver_rejects_non_ipv4_only_hosts(monkeypatch):
    resolver = SystemResolver(timeout=1.0)

    async def fake_getaddrinfo(host, port, **kwargs):
        return []

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ProxyError) as info:
        await resolver.resolve("empty.test")
    assert info.value.reason == "dns_no_ipv4"


async def test_system_resolver_returns_literal_for_ip(monkeypatch):
    resolver = SystemResolver(timeout=1.0)
    assert await resolver.resolve("10.1.2.3") == ["10.1.2.3"]


async def test_system_resolver_dedupes(monkeypatch):
    resolver = SystemResolver(timeout=1.0)

    async def fake_getaddrinfo(host, port, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0)),
        ]

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    assert await resolver.resolve("multi.test") == ["10.0.0.1", "10.0.0.2"]


async def test_pinned_dialer_refuses_hostnames():
    dialer = PinnedDialer()
    with pytest.raises(ProxyError) as info:
        await dialer.dial("example.com", 80, 1.0)
    assert info.value.reason == "dial_invalid_address"


async def test_pinned_dialer_connects_to_literal(monkeypatch):
    seen: list[tuple] = []

    async def fake_sock_connect(sock, address):
        seen.append(address)
        raise ConnectionRefusedError("nope")

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "sock_connect", fake_sock_connect)
    dialer = PinnedDialer()
    with pytest.raises(ProxyError) as info:
        await dialer.dial("127.0.0.9", 8080, 1.0)
    assert info.value.reason == "dial_failed"
    assert seen == [("127.0.0.9", 8080)]


async def test_pinned_dialer_uses_numeric_only(monkeypatch):
    """getaddrinfo must be asked for AI_NUMERICHOST so a name cannot slip in."""

    captured = {}

    async def fake_getaddrinfo(host, port, **kwargs):
        captured.update(kwargs, host=host, port=port)
        raise socket.gaierror("refused")

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    dialer = PinnedDialer()
    with pytest.raises(ProxyError):
        await dialer.dial("127.0.0.1", 9000, 1.0)
    assert captured["flags"] & socket.AI_NUMERICHOST
    assert captured["host"] == "127.0.0.1"


async def test_pinned_dialer_success_returns_streams():
    async def handler(reader, writer):
        writer.write(b"ok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await PinnedDialer().dial("127.0.0.1", port, 2.0)
        assert await asyncio.wait_for(reader.readexactly(2), timeout=2) == b"ok"
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


async def test_many_concurrent_tunnels(tmp_path):
    from conftest import connect_raw, make_harness, read_head, teardown_harness

    h = await make_harness(tmp_path, header_timeout=5.0, idle_timeout=10.0)
    active = 0
    peak = 0

    async def handler(reader, writer):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        finally:
            active -= 1
            with contextlib.suppress(Exception):
                writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async def dial():
        return await asyncio.open_connection("127.0.0.1", port)

    h.dialer.add("10.0.0.5", dial)
    h.resolver.answer["demo.internal"] = ["10.0.0.5"]

    async def one(index: int) -> bool:
        async with connect_raw(h, "demo.internal:8080") as (reader, writer):
            status, _, _ = await read_head(reader)
            if status != 200:
                return False
            payload = f"payload-{index}".encode()
            writer.write(payload)
            await writer.drain()
            got = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=3)
            return got == payload

    try:
        results = await asyncio.gather(*[one(i) for i in range(50)])
        assert all(results)
        assert peak >= 10  # genuinely concurrent, not serialized
    finally:
        server.close()
        await server.wait_closed()
        await teardown_harness(h)


async def test_shutdown_closes_live_tunnels_cleanly(tmp_path):
    from conftest import connect_raw, make_harness, read_head

    h = await make_harness(tmp_path, idle_timeout=30.0)

    async def handler(reader, writer):
        with contextlib.suppress(Exception):
            await reader.read()
        with contextlib.suppress(Exception):
            writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async def dial():
        return await asyncio.open_connection("127.0.0.1", port)

    h.dialer.add("10.0.0.5", dial)
    h.resolver.answer["demo.internal"] = ["10.0.0.5"]

    ctx = connect_raw(h, "demo.internal:8080")
    reader, writer = await ctx.__aenter__()
    try:
        assert (await read_head(reader))[0] == 200
        await h.proxy.stop()
        with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError)):
            await asyncio.wait_for(reader.readexactly(1), timeout=3)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await ctx.__aexit__(None, None, None)
        await h.storage.close()
        server.close()
        await server.wait_closed()


async def test_shutdown_records_final_admission_row(tmp_path):
    from conftest import connect_raw, make_harness, read_head

    h = await make_harness(tmp_path, idle_timeout=30.0)

    async def handler(reader, writer):
        with contextlib.suppress(Exception):
            await reader.read()
        with contextlib.suppress(Exception):
            writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async def dial():
        return await asyncio.open_connection("127.0.0.1", port)

    h.dialer.add("10.0.0.5", dial)
    h.resolver.answer["demo.internal"] = ["10.0.0.5"]

    async with connect_raw(h, "demo.internal:8080") as (reader, _):
        assert (await read_head(reader))[0] == 200
        await h.proxy.stop()
    # The row was created before stop; give a short beat for the shielded write.
    for _ in range(100):
        page = await h.storage.list_admissions()
        row = page["items"][0]
        if row["status"] != "connecting":
            break
        await asyncio.sleep(0.01)
    assert row["status"] == "closed"
    assert row["close_reason"] == "shutdown"
    await h.storage.close()
    server.close()
    await server.wait_closed()
