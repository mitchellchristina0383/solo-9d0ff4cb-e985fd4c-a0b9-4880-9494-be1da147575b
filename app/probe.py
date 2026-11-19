"""Test-connect support: probe the bundled demo through the proxy.

The probe speaks CONNECT itself, then performs a tiny HTTP/1.1 request over
the established tunnel and reads the demo's reply. This exercises exactly the
path an operator cares about: policy decision, DNS, pinned dial and tunnel.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from .config import Settings
from .rules import normalize_target_host
from .storage import Storage


@dataclass
class ProbeResult:
    ok: bool
    target: str
    started_at: float = field(default_factory=time.monotonic)
    status_line: str = ""
    proxy_status: int | None = None
    proxy_headers: list[str] = field(default_factory=list)
    body: str = ""
    error: str = ""
    duration_ms: int = 0
    admission_id: int | None = None

    def to_api(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "target": self.target,
            "proxy_status": self.proxy_status,
            "proxy_headers": self.proxy_headers,
            "status_line": self.status_line,
            "body": self.body,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "admission_id": self.admission_id,
        }


class Probe:
    def __init__(self, settings: Settings, storage: Storage):
        self.settings = settings
        self.storage = storage

    async def run(self, host: str, port: int) -> ProbeResult:
        try:
            host = normalize_target_host(host, where="demo host")
        except ValueError as exc:
            return ProbeResult(ok=False, target=f"{host}:{port}", error=str(exc))
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return ProbeResult(ok=False, target=f"{host}:{port}", error="port must be between 1 and 65535")

        target = f"{host}:{port}"
        result = ProbeResult(ok=False, target=target)
        started = time.monotonic()
        writer: asyncio.StreamWriter | None = None
        try:
            proxy_host = self.settings.proxy_host
            if proxy_host in ("", "0.0.0.0", "::"):
                proxy_host = "127.0.0.1"
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy_host, self.settings.proxy_port),
                timeout=self.settings.test_connect_timeout,
            )
            writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
            await writer.drain()

            head = await asyncio.wait_for(
                self._read_head(reader), timeout=self.settings.test_connect_timeout
            )
            lines = head.split("\r\n")
            result.status_line = lines[0]
            result.proxy_headers = [line for line in lines[1:] if line]
            try:
                result.proxy_status = int(lines[0].split(" ")[1])
            except (IndexError, ValueError):
                result.proxy_status = None

            if result.proxy_status != 200:
                body = await self._read_rest(reader)
                result.error = body or lines[0]
                return result

            request = (
                f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
                f"User-Agent: controlled-egress-probe\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()
            raw = await asyncio.wait_for(
                self._read_rest(reader), timeout=self.settings.test_connect_timeout
            )
            header_blob, _, body = raw.partition("\r\n\r\n")
            status_line = header_blob.split("\r\n", 1)[0] if header_blob else ""
            result.status_line = status_line or result.status_line
            result.body = body
            result.ok = bool(status_line.startswith("HTTP/1."))
            if not result.ok:
                result.error = "demo service did not return an HTTP response"
            return result
        except asyncio.TimeoutError:
            result.error = "timed out talking to the proxy"
            return result
        except (ConnectionRefusedError, OSError) as exc:
            result.error = f"could not reach proxy: {exc}"
            return result
        except Exception as exc:  # pragma: no cover - defensive
            result.error = repr(exc)
            return result
        finally:
            result.duration_ms = int((time.monotonic() - started) * 1000)
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except Exception:
                    pass

    @staticmethod
    async def _read_head(reader: asyncio.StreamReader) -> str:
        data = await reader.readuntil(b"\r\n\r\n")
        return data.decode("iso-8859-1")

    @staticmethod
    async def _read_rest(reader: asyncio.StreamReader) -> str:
        chunks: list[bytes] = []
        total = 0
        while total < 64 * 1024:
            chunk = await reader.read(8192)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
