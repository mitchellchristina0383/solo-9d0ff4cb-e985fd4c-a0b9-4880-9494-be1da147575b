"""The CONNECT proxy engine.

Correctness properties this module is built around:

1. **Judge once, from one committed revision.** The rule snapshot is read
   exactly once per CONNECT request, before any DNS lookup or dial. Every
   later step of that connection uses that same ``RuleSetSnapshot`` object.
   Committing new rules cannot affect a connection already in flight, and
   tunnelled bytes are never re-checked.
2. **Dial the address that was validated.** Resolution happens once. The
   resulting IPv4 addresses are checked against the rule, and the dialer is
   then handed a literal address and uses ``sock_connect`` with
   ``AI_NUMERICHOST`` semantics, so no second lookup can return a different
   address. A DNS answer containing any address outside the rule's networks
   is rejected outright.
3. **No target contact for rejected requests.** Policy failures are answered
   before any socket to the target is created.
4. **Half-close is propagated, not treated as teardown.** When one side
   closes its write direction, the other direction keeps flowing until it
   reaches EOF too. The tunnel is released only after both directions have
   finished, or after the idle timeout, or on error/shutdown.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .config import Settings
from .rules import AdmissionDecision, RuleSetSnapshot, is_ipv4_literal, normalize_target_host
from .storage import Storage

BUFFER_SIZE = 64 * 1024


class ProxyError(Exception):
    """An error that maps to a status line sent back to the client."""

    def __init__(self, status: int, phrase: str, reason: str, detail: str = ""):
        self.status = status
        self.phrase = phrase
        self.reason = reason
        self.detail = detail
        super().__init__(detail or phrase)

    @property
    def status_line(self) -> str:
        return f"HTTP/1.1 {self.status} {self.phrase}"


class Resolver(Protocol):
    async def resolve(self, host: str) -> list[str]:
        """Return IPv4 addresses for ``host``, or raise :class:`ProxyError`."""


class Dialer(Protocol):
    async def dial(
        self, address: str, port: int, timeout: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        ...


class SystemResolver:
    def __init__(self, timeout: float):
        self.timeout = timeout

    async def resolve(self, host: str) -> list[str]:
        if is_ipv4_literal(host):
            return [host]
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(
                    host,
                    None,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                ),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ProxyError(504, "Gateway Timeout", "dns_timeout", f"DNS lookup for {host} timed out") from exc
        except socket.gaierror as exc:
            raise ProxyError(502, "Bad Gateway", "dns_failure", f"DNS lookup for {host} failed: {exc}") from exc
        except OSError as exc:
            raise ProxyError(502, "Bad Gateway", "dns_failure", f"DNS lookup for {host} failed: {exc}") from exc

        addresses: list[str] = []
        for family, _type, _proto, _canon, sockaddr in infos:
            if family != socket.AF_INET:
                continue
            address = str(ipaddress.IPv4Address(sockaddr[0]))
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise ProxyError(502, "Bad Gateway", "dns_no_ipv4", f"{host} has no IPv4 address")
        return addresses


class PinnedDialer:
    """Dial a literal IPv4 address, never a hostname.

    ``socket.AI_NUMERICHOST`` tells ``getaddrinfo`` to refuse to resolve a
    name, and constructing the socket address directly means the connect
    syscall targets exactly the validated address.
    """

    async def dial(
        self, address: str, port: int, timeout: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        loop = asyncio.get_running_loop()
        try:
            ip = ipaddress.IPv4Address(address)
        except ValueError as exc:  # pragma: no cover - guarded by the caller
            raise ProxyError(502, "Bad Gateway", "dial_invalid_address", str(exc)) from exc

        try:
            infos = await loop.getaddrinfo(
                str(ip),
                port,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
                flags=socket.AI_NUMERICHOST,
            )
        except socket.gaierror as exc:
            raise ProxyError(502, "Bad Gateway", "dial_invalid_address", str(exc)) from exc
        if not infos:
            raise ProxyError(502, "Bad Gateway", "dial_invalid_address", address)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, infos[0][4]), timeout=timeout)
        except asyncio.TimeoutError as exc:
            sock.close()
            raise ProxyError(
                504, "Gateway Timeout", "dial_timeout", f"connect to {address}:{port} timed out"
            ) from exc
        except OSError as exc:
            sock.close()
            raise ProxyError(
                502, "Bad Gateway", "dial_failed", f"connect to {address}:{port} failed: {exc}"
            ) from exc
        except BaseException:
            sock.close()
            raise

        reader, writer = await asyncio.open_connection(sock=sock)
        return reader, writer


@dataclass
class _ByteCounter:
    client_to_target: int = 0
    target_to_client: int = 0


@dataclass
class TunnelState:
    admission_id: int
    revision: int
    client: str
    target_host: str
    target_port: int
    server_reader: asyncio.StreamReader
    server_writer: asyncio.StreamWriter
    upstream_reader: asyncio.StreamReader
    upstream_writer: asyncio.StreamWriter
    started_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)
    counters: _ByteCounter = field(default_factory=_ByteCounter)
    close_reason: str = "closed"
    client_eof: bool = False
    upstream_eof: bool = False

    def touch(self) -> None:
        self.last_activity = time.monotonic()


@dataclass(frozen=True, slots=True)
class ConnectRequest:
    host: str
    port: int


STATUS_PHRASES = {
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    408: "Request Timeout",
    431: "Request Header Fields Too Large",
    502: "Bad Gateway",
    504: "Gateway Timeout",
}


class ConnectProxy:
    def __init__(
        self,
        settings: Settings,
        storage: Storage,
        *,
        resolver: Resolver | None = None,
        dialer: Dialer | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.settings = settings
        self.storage = storage
        self.resolver = resolver or SystemResolver(settings.dns_timeout)
        self.dialer = dialer or PinnedDialer()
        self.clock = clock
        self._server: asyncio.AbstractServer | None = None
        self._tunnels: dict[int, TunnelState] = {}
        self._background: set[asyncio.Task] = set()

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.settings.proxy_host,
            self.settings.proxy_port,
            limit=self.settings.max_header_bytes * 2,
            reuse_address=True,
        )

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._background.add(task)
        try:
            await self._on_client(reader, writer)
        finally:
            if task is not None:
                self._background.discard(task)

    @property
    def sockets(self):
        return self._server.sockets if self._server else ()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for tunnel in list(self._tunnels.values()):
            tunnel.close_reason = "shutdown"
            self._abort(tunnel)
        # Give tunnel handlers a moment to write their final admission rows.
        if self._background:
            await asyncio.wait(list(self._background), timeout=2)
        for task in list(self._background):
            if not task.done():
                task.cancel()
        if self._background:
            await asyncio.gather(*self._background, return_exceptions=True)
        self._tunnels.clear()

    def active_tunnel_count(self) -> int:
        return len(self._tunnels)

    # -- request handling --------------------------------------------------

    async def _on_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        client = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        tunnel: TunnelState | None = None
        admission_id: int | None = None
        upstream_writer: asyncio.StreamWriter | None = None
        request: ConnectRequest | None = None
        denial_recorded = False
        try:
            try:
                head = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), self.settings.header_timeout
                )
            except asyncio.TimeoutError as exc:
                raise ProxyError(408, "Request Timeout", "header_timeout", "CONNECT header timed out") from exc
            except asyncio.LimitOverrunError as exc:
                raise ProxyError(
                    431,
                    "Request Header Fields Too Large",
                    "header_too_large",
                    f"header exceeds {self.settings.max_header_bytes} bytes",
                ) from exc
            except asyncio.IncompleteReadError as exc:
                if not exc.partial.strip():
                    return  # client connected and left silently
                raise ProxyError(400, "Bad Request", "malformed_header", "incomplete header") from exc

            if len(head) > self.settings.max_header_bytes:
                raise ProxyError(
                    431,
                    "Request Header Fields Too Large",
                    "header_too_large",
                    f"header exceeds {self.settings.max_header_bytes} bytes",
                )

            request = self._parse_connect(head)

            # One snapshot per connection, read before resolution and dialing.
            snapshot = await self.storage.latest_snapshot()
            if snapshot is None:
                raise ProxyError(403, "Forbidden", "no_rules", "no committed rule revision exists")

            if not snapshot.candidates(request.host, request.port):
                # Reject without a DNS lookup: the target was never admissible.
                decision = snapshot.admit(request.host, request.port, [])
                await self._record_denial(
                    client, request, [], snapshot, decision, kind="connect"
                )
                denial_recorded = True
                raise ProxyError(403, "Forbidden", decision.reason, decision.detail)

            addresses = await self.resolver.resolve(request.host)
            decision = snapshot.admit(request.host, request.port, addresses)
            if not decision.allowed:
                await self._record_denial(
                    client, request, addresses, snapshot, decision, kind="connect"
                )
                denial_recorded = True
                raise ProxyError(403, "Forbidden", decision.reason, decision.detail)

            admission_id = await self.storage.begin_admission(
                kind="connect",
                client=client,
                target_host=request.host,
                target_port=request.port,
                resolved_addresses=addresses,
                revision=snapshot.revision,
                decision="allowed",
                reason=decision.reason,
                detail=decision.detail,
                rule_index=decision.rule.index if decision.rule else None,
                rule_host=decision.rule.host if decision.rule else None,
                status="connecting",
                finished=False,
            )

            upstream_reader, upstream_writer, dial_address = await self._dial_any(
                addresses, request.port
            )
            await self.storage.mark_connected(admission_id, dial_address, snapshot.revision)

            writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: controlled-egress\r\n\r\n")
            await writer.drain()

            tunnel = TunnelState(
                admission_id=admission_id,
                revision=snapshot.revision,
                client=client,
                target_host=request.host,
                target_port=request.port,
                server_reader=reader,
                server_writer=writer,
                upstream_reader=upstream_reader,
                upstream_writer=upstream_writer,
                started_at=self.clock(),
                last_activity=self.clock(),
            )
            self._tunnels[admission_id] = tunnel
            # Hand ownership of the upstream writer to the tunnel.
            upstream_writer = None
            try:
                await self._run_tunnel(tunnel)
            finally:
                self._tunnels.pop(admission_id, None)
        except ProxyError as exc:
            await self._send_error(writer, exc)
            if admission_id is not None:
                # Allowed but failed before the tunnel started (dial errors).
                await self.storage.finish_admission(
                    admission_id,
                    status="error",
                    close_reason="dial_failed",
                    bytes_client_to_target=0,
                    bytes_target_to_client=0,
                    duration_ms=0,
                    decision="error",
                    reason=exc.reason,
                    detail=exc.detail,
                )
            elif not denial_recorded:
                await self._record_error(
                    client,
                    exc,
                    kind="connect",
                    target_host=request.host if request else "",
                    target_port=request.port if request else 0,
                )
        except (ConnectionResetError, BrokenPipeError):
            if admission_id is not None and tunnel is None:
                # Reset while sending the 200 response or before the tunnel
                # started: close out the admission row so it is not stranded.
                with contextlib.suppress(Exception):
                    await self.storage.finish_admission(
                        admission_id,
                        status="error",
                        close_reason="client_reset",
                        bytes_client_to_target=0,
                        bytes_target_to_client=0,
                        duration_ms=0,
                        decision="error",
                        reason="client_reset",
                        detail="client reset the connection before the tunnel started",
                    )
        except asyncio.CancelledError:
            if tunnel is not None:
                tunnel.close_reason = "shutdown"
                self._abort(tunnel)
            raise
        except Exception as exc:  # pragma: no cover - defensive
            await self._send_error(
                writer, ProxyError(500, "Internal Server Error", "internal_error", repr(exc))
            )
            if admission_id is not None:
                await self.storage.finish_admission(
                    admission_id,
                    status="error",
                    close_reason="internal_error",
                    bytes_client_to_target=0,
                    bytes_target_to_client=0,
                    duration_ms=0,
                    decision="error",
                    reason="internal_error",
                    detail=repr(exc),
                )
            else:
                await self._record_error(
                    client,
                    exc,
                    kind="connect",
                    target_host=request.host if request else "",
                    target_port=request.port if request else 0,
                )
        finally:
            if upstream_writer is not None:
                # The upstream connection opened but the client vanished before
                # the tunnel could start; don't leak the socket.
                with contextlib.suppress(Exception):
                    upstream_writer.close()
                    await asyncio.wait_for(upstream_writer.wait_closed(), timeout=2)
            if admission_id is not None:
                self._tunnels.pop(admission_id, None)
            with contextlib.suppress(Exception):
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=2)

    def _parse_connect(self, head: bytes) -> ConnectRequest:
        try:
            text = head.decode("iso-8859-1")
        except UnicodeDecodeError as exc:  # pragma: no cover - iso-8859-1 never fails
            raise ProxyError(400, "Bad Request", "malformed_header", str(exc)) from exc
        lines = text.replace("\r\n", "\n").split("\n")
        if not lines or not lines[0]:
            raise ProxyError(400, "Bad Request", "malformed_header", "empty request line")
        parts = lines[0].split(" ")
        if len(parts) != 3:
            raise ProxyError(400, "Bad Request", "malformed_request_line", "expected 'CONNECT host:port HTTP/1.1'")
        method, target, version = parts
        if method.upper() != "CONNECT":
            raise ProxyError(405, "Method Not Allowed", "method_not_allowed", "only CONNECT is supported")
        if version not in ("HTTP/1.1", "HTTP/1.0"):
            raise ProxyError(400, "Bad Request", "bad_version", f"unsupported version {version!r}")

        authority = target
        if not authority or "@" in authority:
            raise ProxyError(400, "Bad Request", "malformed_authority", "invalid CONNECT authority")
        if authority.startswith("["):
            raise ProxyError(
                400, "Bad Request", "ipv6_unsupported", "only IPv4 targets are supported"
            )
        if authority.count(":") != 1:
            raise ProxyError(
                400, "Bad Request", "malformed_authority", "expected host:port in the CONNECT authority"
            )
        host_raw, port_raw = authority.rsplit(":", 1)
        if not port_raw.isdigit():
            raise ProxyError(400, "Bad Request", "bad_port", "port must be numeric")
        port = int(port_raw)
        if not 1 <= port <= 65535:
            raise ProxyError(400, "Bad Request", "bad_port", "port must be between 1 and 65535")
        try:
            host = normalize_target_host(host_raw)
        except ValueError as exc:
            raise ProxyError(400, "Bad Request", "bad_host", str(exc)) from exc
        return ConnectRequest(host=host, port=port)

    async def _dial_any(
        self, addresses: list[str], port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        last_error: ProxyError | None = None
        for address in addresses:
            try:
                reader, writer = await self.dialer.dial(address, port, self.settings.connect_timeout)
                return reader, writer, address
            except ProxyError as exc:
                last_error = exc
                continue
        if last_error is None:
            raise ProxyError(502, "Bad Gateway", "no_addresses", "resolver returned no addresses")
        raise last_error

    # -- tunnelling --------------------------------------------------------

    async def _run_tunnel(self, tunnel: TunnelState) -> None:
        async def pump(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            *,
            to_target: bool,
        ) -> None:
            try:
                while True:
                    data = await reader.read(BUFFER_SIZE)
                    if not data:
                        break
                    self._check_intact(tunnel)
                    writer.write(data)
                    await writer.drain()
                    if to_target:
                        tunnel.counters.client_to_target += len(data)
                    else:
                        tunnel.counters.target_to_client += len(data)
                    tunnel.touch()
            except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
                self._mark_error(tunnel)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._mark_error(tunnel)
            finally:
                if to_target:
                    tunnel.client_eof = True
                else:
                    tunnel.upstream_eof = True
                # Propagate the half-close so the peer's read side sees EOF.
                with contextlib.suppress(Exception):
                    if writer.can_write_eof():
                        writer.write_eof()

        client_to_target = asyncio.create_task(
            pump(tunnel.server_reader, tunnel.upstream_writer, to_target=True)
        )
        target_to_client = asyncio.create_task(
            pump(tunnel.upstream_reader, tunnel.server_writer, to_target=False)
        )
        watchdog = asyncio.create_task(self._watchdog(tunnel, client_to_target, target_to_client))

        try:
            await asyncio.wait(
                {client_to_target, target_to_client}, return_when=asyncio.ALL_COMPLETED
            )
        except asyncio.CancelledError:
            # Process shutdown or forced cancellation: abort both directions and
            # still write the final admission row before propagating.
            tunnel.close_reason = "shutdown"
            self._abort(tunnel)
            raise
        finally:
            watchdog.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watchdog
            for task in (client_to_target, target_to_client):
                if not task.done():
                    task.cancel()
            await asyncio.gather(client_to_target, target_to_client, return_exceptions=True)
            if tunnel.close_reason == "shutdown":
                with contextlib.suppress(Exception):
                    await asyncio.shield(self._finalise(tunnel))

        if client_to_target.cancelled() and target_to_client.cancelled():
            tunnel.close_reason = "shutdown"
            return
        if tunnel.close_reason in ("idle_timeout", "shutdown"):
            pass  # keep the reason that triggered teardown
        elif tunnel.client_eof and tunnel.upstream_eof:
            tunnel.close_reason = "both_closed"
        elif tunnel.client_eof:
            tunnel.close_reason = "client_closed"
        elif tunnel.upstream_eof:
            tunnel.close_reason = "target_closed"
        else:
            tunnel.close_reason = "closed"

        self._close_writers(tunnel)
        await self._finalise(tunnel)

    def _check_intact(self, tunnel: TunnelState) -> None:
        if tunnel.close_reason in ("idle_timeout", "shutdown", "error"):
            raise ConnectionResetError("tunnel is being torn down")

    @staticmethod
    def _mark_error(tunnel: TunnelState) -> None:
        # A teardown triggered by shutdown or the idle watchdog is not an error;
        # keep the reason that actually caused the close.
        if tunnel.close_reason not in ("idle_timeout", "shutdown"):
            tunnel.close_reason = "error"

    async def _watchdog(
        self,
        tunnel: TunnelState,
        client_to_target: asyncio.Task,
        target_to_client: asyncio.Task,
    ) -> None:
        interval = max(0.02, min(self.settings.idle_timeout / 4, 1.0))
        while True:
            await asyncio.sleep(interval)
            if client_to_target.done() and target_to_client.done():
                return
            idle_for = self.clock() - tunnel.last_activity
            if idle_for >= self.settings.idle_timeout:
                tunnel.close_reason = "idle_timeout"
                self._abort(tunnel)
                return

    @staticmethod
    def _close_writers(tunnel: TunnelState) -> None:
        for writer in (tunnel.server_writer, tunnel.upstream_writer):
            with contextlib.suppress(Exception):
                writer.close()

    @staticmethod
    def _abort(tunnel: TunnelState) -> None:
        # Aborting the transports unblocks both pumps, which then finish and
        # run the normal finalisation path.
        for writer in (tunnel.server_writer, tunnel.upstream_writer):
            with contextlib.suppress(Exception):
                transport = writer.transport
                if transport is not None:
                    transport.abort()
                else:  # pragma: no cover - transports are always present
                    writer.close()

    async def _finalise(self, tunnel: TunnelState) -> None:
        duration_ms = int((self.clock() - tunnel.started_at) * 1000)
        status = {
            "idle_timeout": "idle_timeout",
            "shutdown": "closed",
            "error": "error",
        }.get(tunnel.close_reason, "closed")
        try:
            await self.storage.finish_admission(
                tunnel.admission_id,
                status=status,
                close_reason=tunnel.close_reason,
                bytes_client_to_target=tunnel.counters.client_to_target,
                bytes_target_to_client=tunnel.counters.target_to_client,
                duration_ms=duration_ms,
            )
        except Exception:  # pragma: no cover - logging must not break teardown
            pass

    # -- admission recording ----------------------------------------------

    async def _record_denial(
        self,
        client: str,
        request: ConnectRequest,
        addresses: list[str],
        snapshot: RuleSetSnapshot,
        decision: AdmissionDecision,
        *,
        kind: str,
    ) -> None:
        await self.storage.begin_admission(
            kind=kind,
            client=client,
            target_host=request.host,
            target_port=request.port,
            resolved_addresses=addresses,
            revision=snapshot.revision,
            decision="denied",
            reason=decision.reason,
            detail=decision.detail,
            rule_index=decision.rule.index if decision.rule else None,
            rule_host=decision.rule.host if decision.rule else None,
            status="closed",
            close_reason="denied",
        )

    async def _record_error(
        self,
        client: str,
        exc: BaseException,
        *,
        kind: str,
        target_host: str = "",
        target_port: int = 0,
    ) -> None:
        if isinstance(exc, ProxyError):
            reason, detail = exc.reason, exc.detail
        else:
            reason, detail = "internal_error", repr(exc)
        try:
            await self.storage.begin_admission(
                kind=kind,
                client=client,
                target_host=target_host,
                target_port=target_port,
                resolved_addresses=[],
                revision=None,
                decision="error",
                reason=reason,
                detail=detail,
                status="closed",
                close_reason="error",
            )
        except Exception:  # pragma: no cover - storage failure should not mask the proxy error
            pass

    @staticmethod
    async def _send_error(writer: asyncio.StreamWriter, exc: ProxyError) -> None:
        payload = (exc.detail or exc.phrase).encode("utf-8", errors="replace")
        with contextlib.suppress(Exception):
            writer.write(
                exc.status_line.encode("ascii")
                + b"\r\nContent-Type: text/plain; charset=utf-8\r\n"
                + b"Content-Length: " + str(len(payload)).encode("ascii")
                + b"\r\nConnection: close\r\n\r\n"
                + payload
                + b"\n"
            )
            await asyncio.wait_for(writer.drain(), timeout=2)
