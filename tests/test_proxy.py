from __future__ import annotations

import asyncio
import contextlib
import socket

import pytest

from app.proxy import ProxyError

from conftest import (
    connect_raw,
    make_harness,
    read_head,
    teardown_harness,
    wait_for_admission,
)


async def echo_handler(*, half_close: bool = True):
    """An upstream that echoes bytes; returns a waitable for test control."""

    done = asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
            if half_close and writer.can_write_eof():
                writer.write_eof()
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            done.set()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async def dial():
        return await asyncio.open_connection("127.0.0.1", port)

    return server, dial, done


async def raw_handler(handler):
    """Wrap a (reader, writer) handler into the dialer's expected signature."""

    async def dial():
        client_reader, client_writer = await asyncio.open_connection(*handler["addr"])
        return client_reader, client_writer

    return dial


@pytest.fixture
async def harness(tmp_path):
    h = await make_harness(tmp_path)
    try:
        yield h
    finally:
        await teardown_harness(h)


async def test_allowed_connect_tunnels_bytes(harness):
    server, dial, _ = await echo_handler()
    harness.dialer.add("10.0.0.5", dial)
    harness.resolver.answer["demo.internal"] = ["10.0.0.5"]
    try:
        async with connect_raw(harness, "demo.internal:8080") as (reader, writer):
            status, _, _ = await read_head(reader)
            assert status == 200
            writer.write(b"hello tunnel")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(12), timeout=2) == b"hello tunnel"
    finally:
        server.close()
        await server.wait_closed()


async def test_denied_target_is_never_dialed(harness):
    harness.resolver.answer["evil.test"] = ["10.0.0.9"]
    async with connect_raw(harness, "evil.test:443") as (reader, writer):
        status, _, _ = await read_head(reader)
        assert status == 403
    assert harness.dialer.dialed == []
    page = await harness.storage.list_admissions()
    row = page["items"][0]
    assert row["decision"] == "denied"
    assert row["reason"] == "no_rule"
    assert row["revision"] == 1


async def test_address_outside_network_is_denied_before_dial(harness):
    harness.resolver.answer["demo.internal"] = ["192.168.5.5"]
    async with connect_raw(harness, "demo.internal:8080") as (reader, _):
        status, _, _ = await read_head(reader)
        assert status == 403
    assert harness.dialer.dialed == []


async def test_partial_dns_answer_is_denied(harness):
    harness.resolver.answer["demo.internal"] = ["10.0.0.5", "192.168.5.5"]
    async with connect_raw(harness, "demo.internal:8080") as (reader, _):
        status, _, _ = await read_head(reader)
        assert status == 403
    assert harness.dialer.dialed == []


async def test_dial_uses_validated_address_not_a_name(harness):
    harness.resolver.answer["demo.internal"] = ["10.0.0.7"]
    server, dial, _ = await echo_handler()
    harness.dialer.add("10.0.0.7", dial)
    try:
        async with connect_raw(harness, "demo.internal:8080") as (reader, writer):
            assert (await read_head(reader))[0] == 200
    finally:
        server.close()
        await server.wait_closed()
    assert harness.dialer.dialed == [("10.0.0.7", 8080)]
    page = await harness.storage.list_admissions()
    assert page["items"][0]["dial_address"] == "10.0.0.7"


async def test_second_resolution_cannot_change_the_dialed_address(harness):
    """The resolver is consulted once; the dialer only ever sees the literal."""

    calls = []

    class CountingResolver:
        async def resolve(self, host):
            calls.append(host)
            return ["10.0.0.8"] if len(calls) == 1 else ["192.0.2.1"]

    harness.proxy.resolver = CountingResolver()
    server, dial, _ = await echo_handler()
    harness.dialer.add("10.0.0.8", dial)
    try:
        async with connect_raw(harness, "demo.internal:8080") as (reader, _):
            assert (await read_head(reader))[0] == 200
    finally:
        server.close()
        await server.wait_closed()
    assert calls == ["demo.internal"]
    assert harness.dialer.dialed == [("10.0.0.8", 8080)]


async def test_dial_failure_is_recorded_as_error(harness):
    harness.resolver.answer["demo.internal"] = ["10.0.0.5"]
    async with connect_raw(harness, "demo.internal:8080") as (reader, _):
        status, _, _ = await read_head(reader)
        assert status == 502
    page = await harness.storage.list_admissions()
    row = page["items"][0]
    assert row["decision"] == "error"
    assert row["reason"] == "dial_failed"


async def test_invalid_request_forms(harness):
    async def send(raw: bytes) -> int:
        reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
        writer.write(raw)
        await writer.drain()
        status, _, _ = await read_head(reader)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return status

    assert await send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == 405
    assert await send(b"CONNECT demo.internal HTTP/1.1\r\n\r\n") == 400
    assert await send(b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n") == 400
    assert await send(b"CONNECT demo.internal:99999 HTTP/1.1\r\n\r\n") == 400
    assert await send(b"CONNECT demo.internal:80 HTTP/1.1\r\n\r\n") == 403


async def test_header_too_large_is_rejected(harness):
    reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
    writer.write(b"CONNECT demo.internal:8080 HTTP/1.1\r\n" + b"X: " + b"a" * 20000 + b"\r\n\r\n")
    with contextlib.suppress(Exception):
        await writer.drain()
    status = 0
    with contextlib.suppress(Exception):
        status, _, _ = await read_head(reader)
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    assert status == 431


async def test_half_close_from_client_still_delivers_upstream_data(harness):
    """Client half-closes after sending; server's reply must still arrive."""

    received = bytearray()
    finished = asyncio.Event()

    async def upstream_read_until_eof_then_reply(reader, writer):
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                received.extend(chunk)
            writer.write(b"reply-after-eof")
            await writer.drain()
            if writer.can_write_eof():
                writer.write_eof()
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            finished.set()

    server = await asyncio.start_server(
        upstream_read_until_eof_then_reply, "127.0.0.1", 0
    )
    port = server.sockets[0].getsockname()[1]

    async def dial():
        return await asyncio.open_connection("127.0.0.1", port)

    harness.dialer.add("10.0.0.5", dial)
    harness.resolver.answer["demo.internal"] = ["10.0.0.5"]
    try:
        async with connect_raw(harness, "demo.internal:8080") as (reader, writer):
            assert (await read_head(reader))[0] == 200
            writer.write(b"question")
            await writer.drain()
            writer.write_eof()  # half-close: we are done sending
            assert await asyncio.wait_for(reader.readexactly(15), timeout=3) == b"reply-after-eof"
            assert bytes(received) == b"question"
    finally:
        server.close()
        await server.wait_closed()


async def test_half_close_from_upstream_still_accepts_client_data(harness):
    """Upstream half-closes; the proxy must keep forwarding client bytes to it."""

    received = asyncio.get_running_loop().create_future()
    buffer = bytearray()

    async def upstream(reader, writer):
        writer.write(b"greeting")
        await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()  # upstream won't send any more
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                if not received.done():
                    received.set_result(bytes(buffer))
                break
            buffer.extend(chunk)
        with contextlib.suppress(Exception):
            writer.close()

    server = await asyncio.start_server(upstream, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async def dial():
        return await asyncio.open_connection("127.0.0.1", port)

    harness.dialer.add("10.0.0.5", dial)
    harness.resolver.answer["demo.internal"] = ["10.0.0.5"]
    try:
        async with connect_raw(harness, "demo.internal:8080") as (reader, writer):
            status, _, rest = await read_head(reader)
            assert status == 200
            # The 200 head and the greeting can share a TCP segment.
            while len(rest) < 8:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=3)
                if not chunk:
                    break
                rest += chunk
            assert rest == b"greeting"
            assert await asyncio.wait_for(reader.read(), timeout=3) == b""  # upstream EOF
            writer.write(b"late payload")
            await writer.drain()
            writer.write_eof()
            assert await asyncio.wait_for(received, timeout=3) == b"late payload"
    finally:
        server.close()
        await server.wait_closed()


async def test_idle_tunnel_is_closed_and_recorded(tmp_path):
    idle_seen = asyncio.Event()

    async def sink(reader, writer):
        try:
            await reader.read()
        finally:
            idle_seen.set()

    server = await asyncio.start_server(sink, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    h = await make_harness(
        tmp_path,
        idle_timeout=0.3,
        bootstrap_rules=({"host": "demo.internal", "ports": [8080], "networks": ["10.0.0.0/8"]},),
    )

    async def dial():
        return await asyncio.open_connection("127.0.0.1", port)

    h.dialer.add("10.0.0.5", dial)
    h.resolver.answer["demo.internal"] = ["10.0.0.5"]
    try:
        async with connect_raw(h, "demo.internal:8080") as (reader, _):
            assert (await read_head(reader))[0] == 200
            with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError)):
                await asyncio.wait_for(reader.readexactly(1), timeout=3)
        await asyncio.wait_for(idle_seen.wait(), timeout=3)
        page = await h.storage.list_admissions()
        row = page["items"][0]
        assert row["status"] == "idle_timeout"
        assert row["close_reason"] == "idle_timeout"
    finally:
        await teardown_harness(h)
        server.close()
        await server.wait_closed()


async def test_rule_change_does_not_affect_existing_tunnel(harness):
    server, dial, _ = await echo_handler()
    harness.dialer.add("10.0.0.5", dial)
    harness.resolver.answer["demo.internal"] = ["10.0.0.5"]
    try:
        async with connect_raw(harness, "demo.internal:8080") as (reader, writer):
            assert (await read_head(reader))[0] == 200
            # Revoke every rule while the tunnel is live.
            await harness.storage.commit_rules([], note="revoke all")
            writer.write(b"still works")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(11), timeout=2) == b"still works"
    finally:
        server.close()
        await server.wait_closed()

    # A new connection is denied under the new revision.
    harness.resolver.answer["demo.internal"] = ["10.0.0.5"]
    async with connect_raw(harness, "demo.internal:8080") as (reader, _):
        assert (await read_head(reader))[0] == 403
    page = await harness.storage.list_admissions()
    revisions = [row["revision"] for row in page["items"]]
    assert page["items"][0]["decision"] == "denied"
    assert page["items"][0]["revision"] == 2


async def test_each_connection_uses_the_revision_at_its_decision(harness):
    server, dial, _ = await echo_handler()
    harness.dialer.add("10.0.0.5", dial)
    harness.resolver.answer["demo.internal"] = ["10.0.0.5"]

    gate = asyncio.Event()
    original_resolve = harness.resolver.resolve

    async def slow_resolve(host):
        addresses = await original_resolve(host)
        await gate.wait()
        return addresses

    harness.proxy.resolver.resolve = slow_resolve
    try:
        # Start a connection that reads its snapshot, then compiles rules.
        task = asyncio.create_task(
            asyncio.open_connection("127.0.0.1", harness.port)
        )
        reader, writer = await task
        writer.write(b"CONNECT demo.internal:8080 HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        # The connection has taken snapshot revision 1 and is now in resolve().
        await asyncio.sleep(0.1)
        await harness.storage.commit_rules([], note="revoke")
        harness.proxy.resolver.resolve = lambda host: original_resolve(host)
        gate.set()
        status, _, _ = await read_head(reader)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        assert status == 200
    finally:
        server.close()
        await server.wait_closed()
    page = await harness.storage.list_admissions()
    assert page["items"][0]["revision"] == 1


async def test_ip_literal_target_is_dialed_directly(tmp_path):
    server, dial, _ = await echo_handler()
    port = server.sockets[0].getsockname()[1]
    h = await make_harness(
        tmp_path,
        bootstrap_rules=({"host": "127.0.0.1", "ports": [port], "networks": ["127.0.0.0/8"]},),
    )
    h.dialer.add("127.0.0.1", dial)
    try:
        async with connect_raw(h, f"127.0.0.1:{port}") as (reader, writer):
            assert (await read_head(reader))[0] == 200
            writer.write(b"ping")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(4), timeout=2) == b"ping"
        assert h.resolver.calls == []  # literals need no lookup
    finally:
        await teardown_harness(h)
        server.close()
        await server.wait_closed()
