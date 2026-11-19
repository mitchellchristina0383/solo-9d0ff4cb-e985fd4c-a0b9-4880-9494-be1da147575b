from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field

import pytest

from app.config import Settings
from app.proxy import ConnectProxy, ProxyError
from app.rules import is_ipv4_literal
from app.storage import Storage


@dataclass
class FakeResolver:
    answer: dict[str, list[str]] = field(default_factory=dict)
    calls: list[tuple[str, list[str]]] = field(default_factory=list)
    error: ProxyError | None = None

    async def resolve(self, host: str) -> list[str]:
        if self.error is not None:
            raise self.error
        # Mirror SystemResolver: IP literals resolve to themselves with no
        # lookup, so they are not recorded as resolution calls.
        if is_ipv4_literal(host):
            return [host]
        addresses = list(self.answer.get(host, ["0.0.0.0"]))
        self.calls.append((host, addresses))
        return addresses


class RecordingDialer:
    """Points every dial at an in-process fake upstream keyed by address."""

    def __init__(self):
        self.dialed: list[tuple[str, int]] = []
        self.handlers: dict[str, object] = {}

    def add(self, address: str, handler) -> None:
        self.handlers[address] = handler

    async def dial(self, address, port, timeout):
        self.dialed.append((address, port))
        handler = self.handlers.get(address)
        if handler is None:
            raise ProxyError(502, "Bad Gateway", "dial_failed", f"nothing listening at {address}")
        return await handler()


async def make_settings(tmp_path, **overrides) -> Settings:
    base = dict(
        db_path=str(tmp_path / "proxy.db"),
        proxy_host="127.0.0.1",
        proxy_port=0,
        web_host="127.0.0.1",
        web_port=0,
        dns_timeout=1.0,
        connect_timeout=1.0,
        header_timeout=1.0,
        idle_timeout=5.0,
        max_header_bytes=8192,
        test_connect_timeout=2.0,
        demo_host="demo.internal",
        demo_port=8080,
        demo_cidr="10.0.0.0/8",
        bootstrap_rules=(
            {"host": "demo.internal", "ports": [8080], "networks": ["10.0.0.0/8"]},
        ),
    )
    base.update(overrides)
    return Settings(**base)


@dataclass
class Harness:
    settings: Settings
    storage: Storage
    proxy: ConnectProxy
    resolver: FakeResolver
    dialer: RecordingDialer

    @property
    def port(self) -> int:
        return self.proxy.sockets[0].getsockname()[1]


async def make_harness(tmp_path, **settings_overrides) -> Harness:
    settings = await make_settings(tmp_path, **settings_overrides)
    storage = Storage(settings.db_path)
    await storage.open()
    await storage.seed_if_empty(settings.bootstrap_rules)
    resolver = FakeResolver()
    dialer = RecordingDialer()
    proxy = ConnectProxy(settings, storage, resolver=resolver, dialer=dialer)
    await proxy.start()
    harness = Harness(settings, storage, proxy, resolver, dialer)
    return harness


async def teardown_harness(harness: Harness) -> None:
    await harness.proxy.stop()
    await harness.storage.close()


@contextlib.asynccontextmanager
async def connect_raw(harness: Harness, target: str, *, extra: bytes = b""):
    reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
    writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode() + extra)
    await writer.drain()
    try:
        yield reader, writer
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), timeout=1)


async def read_head(reader: asyncio.StreamReader) -> tuple[int, dict[str, str], bytes]:
    """Read a response head, returning status, headers and any leftover bytes."""

    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=3)
        if not chunk:
            break
        buffer += chunk
    head, _, rest = buffer.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ")[1]) if len(lines[0].split(" ")) > 1 else 0
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return status, headers, rest


async def wait_for_admission(storage: Storage, admission_id: int, **expected) -> dict:
    for _ in range(200):
        row = await storage.get_admission(admission_id)
        if row and all(row[key] == value for key, value in expected.items()):
            return row
        await asyncio.sleep(0.01)
    row = await storage.get_admission(admission_id)
    pytest.fail(f"admission {admission_id} did not reach {expected}: {row}")


@pytest.fixture
async def harness(tmp_path):
    h = await make_harness(tmp_path)
    try:
        yield h
    finally:
        await teardown_harness(h)
