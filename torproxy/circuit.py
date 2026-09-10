from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import struct
from collections import deque
from collections.abc import AsyncGenerator
from typing import (
    TYPE_CHECKING,
)

from .cells import (
    BEGIN_FLAG_IPV4_OK,
    BEGIN_FLAG_IPV6_OK,
    CELL_CREATE2,
    CELL_CREATED2,
    CELL_DESTROY,
    CELL_PADDING,
    CELL_PAYLOAD_SIZE,
    CELL_RELAY,
    CELL_RELAY_EARLY,
    CELL_VPADDING,
    CIRCWINDOW_INCREMENT,
    CIRCWINDOW_START,
    LS_IPV4,
    LS_LEGACY_ID,
    ONION_HANDSHAKE_TYPE_NTOR,
    RELAY_COMMAND_BEGIN,
    RELAY_COMMAND_CONNECTED,
    RELAY_COMMAND_DATA,
    RELAY_COMMAND_END,
    RELAY_COMMAND_EXTEND2,
    RELAY_COMMAND_EXTENDED,
    RELAY_COMMAND_EXTENDED2,
    RELAY_COMMAND_SENDME,
    RELAY_HEADER_SIZE,
    RELAY_PAYLOAD_SIZE,
    STREAM_ID_FIRST,
    STREAM_ID_MASK,
    STREAM_QUEUE_MAX,
    STREAM_TIMEOUT,
    STREAM_WINDOW_START,
    STREAMWINDOW_INCREMENT,
    Cell,
    build_relay_payload,
)
from .consensus import RelayInfo
from .crypto import RelayCrypto, ntor_client_handshake, ntor_create
from .log import log

if TYPE_CHECKING:
    from .connection import TorConnection

MAX_BUFFERED_RESPONSE_BYTES = 10 * 1024 * 1024


class TorCircuit:
    def __init__(
        self,
        conn: TorConnection,
        circ_id: int,
        cell_queue: asyncio.Queue | None = None,
    ):
        self.conn = conn
        self.circ_id = circ_id
        self._cell_queue = cell_queue
        self.hop1: RelayCrypto | None = None
        self.hop2: RelayCrypto | None = None
        self.hop3: RelayCrypto | None = None
        self.built = False
        self._next_stream_id = STREAM_ID_FIRST
        self._stream_queues: dict[int, asyncio.Queue] = {}
        self.exit_info: RelayInfo | None = None
        self._dispatch_task: asyncio.Task | None = None
        self._send_lock = asyncio.Lock()
        self._pending_connected: dict[int, asyncio.Future] = {}
        self._dispatch_running = False
        self._active_streams = 0
        self._active_sids: set[int] = set()
        self._stream_deliver_windows: dict[int, int] = {}
        self._stream_package_windows: dict[int, int] = {}
        self._package_window = CIRCWINDOW_START
        self._deliver_window = CIRCWINDOW_START
        self._flow_cond = asyncio.Condition()
        self._sendme_digest_queue: deque = deque()
        self._circuit_failed = False

    async def recv_cell(self) -> Cell:
        if self._cell_queue is None:
            return await self.conn.recv_cell()
        cell = await self._cell_queue.get()
        if isinstance(cell, Exception):
            raise cell
        return cell

    def _encrypt_outbound(self, relay_payload: bytes) -> tuple[bytes, bytes]:
        data = bytearray(relay_payload)

        hops: list[RelayCrypto] = [
            hop for hop in (self.hop1, self.hop2, self.hop3) if hop is not None
        ]

        if not hops:
            return bytes(data), b"\x00\x00\x00\x00"

        farthest = hops[-1]
        d = farthest.set_forward_digest(bytes(data))
        data[5:9] = d[:4]

        for hop in reversed(hops):
            data = bytearray(hop.encrypt_forward(bytes(data)))

        return bytes(data), d

    def _decrypt_inbound(
        self, cell_payload: bytes
    ) -> tuple[int, int, bytes, int, bytes] | None:
        data = cell_payload

        d1 = self.hop1.decrypt_backward(data) if self.hop1 else data

        if self.hop1 and self._check_digest(self.hop1, d1):
            cmd, sid, _, rdata = self._parse_relay_payload(d1)
            if cmd is not None:
                return (cmd, sid, rdata, 1, self.hop1.b_digest.digest())

        if self.hop2:
            d2 = self.hop2.decrypt_backward(d1)
            if self._check_digest(self.hop2, d2):
                cmd, sid, _, rdata = self._parse_relay_payload(d2)
                if cmd is not None:
                    return (cmd, sid, rdata, 2, self.hop2.b_digest.digest())

        if self.hop3:
            d3 = self.hop3.decrypt_backward(d2)
            if self._check_digest(self.hop3, d3):
                cmd, sid, _, rdata = self._parse_relay_payload(d3)
                if cmd is not None:
                    return (cmd, sid, rdata, 3, self.hop3.b_digest.digest())

        return None

    def _check_digest(self, crypto: RelayCrypto, payload: bytes) -> bool:
        rh = payload[:RELAY_HEADER_SIZE]
        recognized = struct.unpack("!H", rh[1:3])[0]
        if recognized != 0:
            return False
        return crypto.check_backward_digest(payload)

    def _parse_relay_payload(
        self, payload: bytes
    ) -> tuple[int | None, int, int, bytes]:
        rh = payload[:RELAY_HEADER_SIZE]
        cmd = rh[0]
        sid = struct.unpack("!H", rh[3:5])[0]
        length = struct.unpack("!H", rh[9:11])[0]
        data = payload[
            RELAY_HEADER_SIZE : RELAY_HEADER_SIZE + min(length, RELAY_PAYLOAD_SIZE)
        ]
        return (cmd, sid, length, data)

    async def build(
        self, guard: RelayInfo, middle: RelayInfo, exit_relay: RelayInfo
    ) -> None:
        self.exit_info = exit_relay
        log.info(
            "Building circuit %d: %s -> %s -> %s",
            self.circ_id,
            guard.nickname,
            middle.nickname,
            exit_relay.nickname,
        )

        state1, skin1 = ntor_create(guard.identity, guard.ntor_onion_key)
        await self._send_create2(skin1)
        reply1 = await self._recv_created2()
        key1 = ntor_client_handshake(state1, reply1)
        if key1 is None:
            raise RuntimeError("Hop 1 ntor failed")
        self.hop1 = RelayCrypto(key1)
        log.debug("Hop 1 built: %s", guard.nickname)

        state2, skin2 = ntor_create(middle.identity, middle.ntor_onion_key)
        await self._send_extend2(middle, skin2)
        reply2 = await self._recv_extended2()
        key2 = ntor_client_handshake(state2, reply2)
        if key2 is None:
            raise RuntimeError("Hop 2 ntor failed")
        self.hop2 = RelayCrypto(key2)
        log.debug("Hop 2 built: %s", middle.nickname)

        state3, skin3 = ntor_create(exit_relay.identity, exit_relay.ntor_onion_key)
        await self._send_extend2(exit_relay, skin3)
        reply3 = await self._recv_extended2()
        key3 = ntor_client_handshake(state3, reply3)
        if key3 is None:
            raise RuntimeError("Hop 3 ntor failed")
        self.hop3 = RelayCrypto(key3)
        log.debug("Hop 3 built: %s", exit_relay.nickname)

        self.built = True
        log.info("Circuit %d built successfully", self.circ_id)

    async def _send_create2(self, ntor_skin: bytes) -> None:
        payload = (
            struct.pack("!HH", ONION_HANDSHAKE_TYPE_NTOR, len(ntor_skin)) + ntor_skin
        )
        await self.conn.send_fixed_cell(self.circ_id, CELL_CREATE2, payload)

    async def _recv_created2(self) -> bytes:
        while True:
            cell = await self.recv_cell()
            if (
                cell.is_fixed
                and cell.circ_id == self.circ_id
                and cell.command == CELL_CREATED2
            ):
                hlen = struct.unpack("!H", cell.payload[:2])[0]
                return cell.payload[2 : 2 + hlen]
            elif (
                cell.is_fixed
                and cell.circ_id == self.circ_id
                and cell.command == CELL_DESTROY
            ):
                raise RuntimeError("Circuit destroyed by relay")
            elif cell.command in (CELL_PADDING, CELL_VPADDING):
                continue

    def _build_extend2_payload(self, relay: RelayInfo, ntor_skin: bytes) -> bytes:
        n_spec = 2
        body = struct.pack("!B", n_spec)
        ip_bytes = socket.inet_aton(relay.ip)
        body += (
            struct.pack("!BB", LS_IPV4, 6) + ip_bytes + struct.pack("!H", relay.orport)
        )
        body += struct.pack("!BB", LS_LEGACY_ID, 20) + relay.identity
        body += (
            struct.pack("!HH", ONION_HANDSHAKE_TYPE_NTOR, len(ntor_skin)) + ntor_skin
        )
        return body

    async def _send_extend2(self, relay: RelayInfo, ntor_skin: bytes) -> None:
        await self._send_relay_cell(
            RELAY_COMMAND_EXTEND2,
            0,
            self._build_extend2_payload(relay, ntor_skin),
            CELL_RELAY_EARLY,
        )

    async def _recv_extended2(self) -> bytes:
        while True:
            cell = await self.recv_cell()
            if not cell.is_fixed or cell.circ_id != self.circ_id:
                continue
            if cell.command in (CELL_RELAY, CELL_RELAY_EARLY):
                result = self._decrypt_inbound(cell.payload)
                if result is None:
                    continue
                relay_cmd, _, data, _hop_index, _hop_ciphertext = result
                if relay_cmd == RELAY_COMMAND_EXTENDED2:
                    if len(data) >= 2:
                        hlen = struct.unpack("!H", data[:2])[0]
                        if hlen <= len(data) - 2:
                            return data[2 : 2 + hlen]
                elif relay_cmd == RELAY_COMMAND_EXTENDED:
                    return data[4:]
            elif cell.command == CELL_DESTROY:
                raise RuntimeError("Circuit destroyed during extend")
            elif cell.command in (CELL_PADDING, CELL_VPADDING):
                continue

    def _ensure_dispatch(self):
        if self._circuit_failed:
            raise RuntimeError("Circuit is failed")
        if self._dispatch_task and not self._dispatch_task.done():
            return
        self._dispatch_running = True
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())

    async def _dispatch_loop(self):
        try:
            while self._dispatch_running:
                cell = await self.recv_cell()
                if not cell.is_fixed or cell.circ_id != self.circ_id:
                    continue
                if cell.command == CELL_DESTROY:
                    self._circuit_failed = True
                    break
                if cell.command not in (CELL_RELAY, CELL_RELAY_EARLY):
                    continue

                result = self._decrypt_inbound(cell.payload)
                if result is None:
                    continue
                relay_cmd, rsid, data, _hop_index, running_digest = result
                log.debug(
                    "Circuit %d relay cmd=%d sid=%d len=%d",
                    self.circ_id,
                    relay_cmd,
                    rsid,
                    len(data),
                )

                if relay_cmd == RELAY_COMMAND_CONNECTED:
                    f = self._pending_connected.pop(rsid, None)
                    if f and not f.done():
                        f.set_result(True)
                elif relay_cmd == RELAY_COMMAND_DATA:
                    self._deliver_window -= 1
                    if self._deliver_window <= 900:
                        log.debug(
                            "Sending circuit SENDME with digest %s",
                            running_digest.hex(),
                        )
                        await self._send_relay_cell(
                            RELAY_COMMAND_SENDME, 0, b"\x01\x00\x14" + running_digest
                        )
                        self._deliver_window += CIRCWINDOW_INCREMENT

                    if rsid not in self._stream_deliver_windows:
                        self._stream_deliver_windows[rsid] = STREAM_WINDOW_START
                    self._stream_deliver_windows[rsid] -= 1
                    if self._stream_deliver_windows[rsid] <= 450:
                        log.debug("Sending stream SENDME for %d", rsid)
                        await self._send_relay_cell(RELAY_COMMAND_SENDME, rsid, b"")
                        self._stream_deliver_windows[rsid] += STREAMWINDOW_INCREMENT

                    q = self._stream_queues.get(rsid)
                    if q:
                        try:
                            q.put_nowait(data)
                        except asyncio.QueueFull:
                            log.debug("Stream %d queue full; dropping stream", rsid)
                            self._drop_stream(rsid)
                            async with self._flow_cond:
                                self._flow_cond.notify_all()
                elif relay_cmd == RELAY_COMMAND_SENDME:
                    await self._handle_sendme(rsid, data)
                elif relay_cmd == RELAY_COMMAND_END:
                    f = self._pending_connected.pop(rsid, None)
                    if f and not f.done():
                        f.set_exception(RuntimeError("Stream END"))
                    q = self._stream_queues.get(rsid)
                    if q:
                        try:
                            q.put_nowait(b"")
                        except asyncio.QueueFull:
                            self._drop_stream(rsid)
                            async with self._flow_cond:
                                self._flow_cond.notify_all()
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError):
            self._circuit_failed = True
        except Exception as exc:
            self._circuit_failed = True
            log.debug("Circuit %d dispatcher stopped: %s", self.circ_id, exc)
        finally:
            self._dispatch_running = False
            for f in list(self._pending_connected.values()):
                if not f.done():
                    f.set_exception(ConnectionError("Circuit dispatcher stopped"))
            self._pending_connected.clear()
            for q in list(self._stream_queues.values()):
                try:
                    q.put_nowait(b"")
                except asyncio.QueueFull:
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                    try:
                        q.put_nowait(b"")
                    except asyncio.QueueFull:
                        pass
            async with self._flow_cond:
                self._flow_cond.notify_all()

    def _drop_stream(self, sid: int) -> None:
        self._stream_queues.pop(sid, None)
        self._stream_deliver_windows.pop(sid, None)
        self._stream_package_windows.pop(sid, None)
        f = self._pending_connected.pop(sid, None)
        if f and not f.done():
            f.cancel()
        if sid in self._active_sids:
            self._active_sids.discard(sid)
            self._active_streams -= 1

    async def _handle_sendme(self, stream_id: int, data: bytes) -> None:
        if stream_id != 0:
            async with self._flow_cond:
                if stream_id in self._stream_package_windows:
                    self._stream_package_windows[stream_id] += STREAMWINDOW_INCREMENT
                    self._flow_cond.notify_all()
            return

        version = data[0] if data else 0
        if version == 0:
            if self._sendme_digest_queue:
                self._sendme_digest_queue.popleft()
        elif version == 1:
            if len(data) < 3:
                raise RuntimeError("Malformed authenticated SENDME")
            data_len = struct.unpack("!H", data[1:3])[0]
            digest = data[3 : 3 + data_len]
            expected = (
                self._sendme_digest_queue.popleft()
                if self._sendme_digest_queue
                else None
            )
            if expected is None or len(digest) < 20 or digest[:20] != expected:
                raise RuntimeError("Authenticated SENDME digest mismatch")
        else:
            raise RuntimeError(f"Unsupported SENDME version {version}")

        async with self._flow_cond:
            self._package_window += CIRCWINDOW_INCREMENT
            self._flow_cond.notify_all()

    async def _send_relay_cell(
        self,
        relay_cmd: int,
        stream_id: int,
        data: bytes,
        cell_command: int = CELL_RELAY,
    ) -> bytes | None:
        async with self._send_lock:
            relay_payload = build_relay_payload(relay_cmd, stream_id, data)
            encrypted, digest = self._encrypt_outbound(relay_payload)
            await self.conn.send_fixed_cell(self.circ_id, cell_command, encrypted)
            return digest

    async def begin_stream(self, host: str, port: int) -> int:
        self._ensure_dispatch()
        sid = self._next_stream_id
        self._advance_stream_id()
        while sid in self._stream_queues:
            sid = self._next_stream_id
            self._advance_stream_id()
        self._stream_queues[sid] = asyncio.Queue(maxsize=STREAM_QUEUE_MAX)
        self._stream_deliver_windows[sid] = STREAM_WINDOW_START
        self._stream_package_windows[sid] = STREAM_WINDOW_START
        future: asyncio.Future = asyncio.Future()
        self._pending_connected[sid] = future
        try:
            ip_addr = ipaddress.ip_address(host)
        except ValueError:
            flags = BEGIN_FLAG_IPV4_OK | BEGIN_FLAG_IPV6_OK
            addrport = f"{host}:{port}\x00".encode()
        else:
            if ip_addr.version == 6:
                flags = BEGIN_FLAG_IPV6_OK
                addrport = f"[{host}]:{port}\x00".encode()
            else:
                flags = BEGIN_FLAG_IPV4_OK
                addrport = f"{host}:{port}\x00".encode()
        begin_data = addrport + struct.pack("!I", flags)
        try:
            await self._send_relay_cell(RELAY_COMMAND_BEGIN, sid, begin_data)
            await asyncio.wait_for(future, timeout=STREAM_TIMEOUT)
            self._active_sids.add(sid)
            self._active_streams += 1
            return sid
        except asyncio.TimeoutError:
            self._drop_stream(sid)
            raise RuntimeError(f"Stream {sid} CONNECTED timeout") from None
        except Exception as exc:
            self._drop_stream(sid)
            if isinstance(exc, RuntimeError):
                raise RuntimeError(f"Stream {sid} END before CONNECTED") from exc
            raise

    def _advance_stream_id(self) -> None:
        self._next_stream_id = (
            (self._next_stream_id + 1) & STREAM_ID_MASK
        ) or STREAM_ID_FIRST

    async def send_data(self, sid: int, data: bytes) -> None:
        chunk_size = RELAY_PAYLOAD_SIZE
        for offset in range(0, len(data), chunk_size):
            chunk = data[offset : offset + chunk_size]
            async with self._flow_cond:
                while self._package_window <= 0:
                    if self._circuit_failed:
                        raise RuntimeError("Circuit failed while waiting for SENDME")
                    await self._flow_cond.wait()
                stream_window = self._stream_package_windows.get(sid)
                if stream_window is None:
                    raise RuntimeError(f"Stream {sid} is no longer open")
                while stream_window <= 0:
                    if self._circuit_failed:
                        raise RuntimeError(
                            "Circuit failed while waiting for stream SENDME"
                        )
                    await self._flow_cond.wait()
                    stream_window = self._stream_package_windows.get(sid)
                    if stream_window is None:
                        raise RuntimeError(f"Stream {sid} is no longer open")
                digest = await self._send_relay_cell(RELAY_COMMAND_DATA, sid, chunk)
                self._package_window -= 1
                if sid not in self._stream_package_windows:
                    raise RuntimeError(f"Stream {sid} closed while sending")
                self._stream_package_windows[sid] = stream_window - 1
                if self._package_window % CIRCWINDOW_INCREMENT == 0:
                    self._sendme_digest_queue.append(digest)

    async def recv_stream_data(self, sid: int, timeout: float | None = 30.0) -> bytes:
        q = self._stream_queues.get(sid)
        if q is None:
            raise RuntimeError(f"No queue for stream {sid}")
        if timeout is None:
            return await q.get()
        try:
            return await asyncio.wait_for(q.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError("Timeout waiting for stream data") from None

    async def http_request(self, host: str, port: int, http_data: bytes) -> bytes:
        sid = await self.begin_stream(host, port)
        try:
            log.debug("Stream %d connected to %s:%d", sid, host, port)
            await self.send_data(sid, http_data)
            response = b""
            while True:
                try:
                    chunk = await self.recv_stream_data(sid, timeout=30.0)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > MAX_BUFFERED_RESPONSE_BYTES:
                        break
                except (asyncio.TimeoutError, RuntimeError):
                    break
            return response
        finally:
            self._drop_stream(sid)

    async def stream_request(
        self, host: str, port: int, http_data: bytes, use_tls: bool = False
    ) -> AsyncGenerator[bytes, None]:
        sid = await self.begin_stream(host, port)
        log.debug("Stream %d connected to %s:%d", sid, host, port)

        try:
            if not use_tls:
                await self.send_data(sid, http_data)
                while True:
                    try:
                        chunk = await self.recv_stream_data(sid, timeout=60.0)
                        if not chunk:
                            break
                        yield chunk
                    except (asyncio.TimeoutError, RuntimeError):
                        break
                return

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            inc = ssl.MemoryBIO()
            out = ssl.MemoryBIO()
            ssl_obj = ctx.wrap_bio(inc, out, server_side=False, server_hostname=host)

            async def _flush():
                while out.pending:
                    data = out.read(65536)
                    if data:
                        await self.send_data(sid, data)

            async def _feed(timeout=30.0):
                raw = await self.recv_stream_data(sid, timeout=timeout)
                if raw:
                    inc.write(raw)
                    return True
                return False

            ok = False
            for _ in range(60):
                try:
                    ssl_obj.do_handshake()
                    ok = True
                    break
                except ssl.SSLWantReadError:
                    await _flush()
                    try:
                        if not await _feed(timeout=15.0):
                            break
                    except Exception:
                        break
                except ssl.SSLWantWriteError:
                    await _flush()
                    continue
                except Exception:
                    break

            if not ok:
                raise RuntimeError(f"TLS handshake failed for {host}")

            await _flush()

            pending = memoryview(http_data)
            while pending:
                try:
                    written = ssl_obj.write(pending)
                except ssl.SSLWantReadError:
                    try:
                        if not await _feed(timeout=15.0):
                            raise RuntimeError(
                                "TLS stream closed while writing request"
                            )
                    except RuntimeError:
                        raise
                    except Exception:
                        raise RuntimeError("TLS request write failed") from None
                except ssl.SSLWantWriteError:
                    await _flush()
                    continue
                if not written:
                    raise RuntimeError("TLS request write made no progress")
                pending = pending[written:]
                await _flush()

            while True:
                try:
                    plain = ssl_obj.read(65536)
                    if plain:
                        yield plain
                except ssl.SSLWantReadError:
                    pass
                except Exception:
                    break

                try:
                    if not await _feed(timeout=60.0):
                        break
                except Exception:
                    break
        finally:
            self._drop_stream(sid)

    async def close(self) -> None:
        self._dispatch_running = False
        if self._dispatch_task and not self._dispatch_task.done():
            self._dispatch_task.cancel()
            try:
                await asyncio.gather(self._dispatch_task, return_exceptions=True)
            except Exception:
                pass
        if self._cell_queue is not None and self.conn is not None:
            self.conn.unregister_circuit(self.circ_id)
        if self.conn and self.conn.writer and not self.conn.writer.is_closing():
            try:
                payload = b"\x00" * CELL_PAYLOAD_SIZE
                await self.conn.send_fixed_cell(self.circ_id, CELL_DESTROY, payload)
            except Exception:
                pass
