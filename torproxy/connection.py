import asyncio
import ssl
import struct

from .cells import (
    CELL_AUTH_CHALLENGE,
    CELL_CERTS,
    CELL_NETINFO,
    CELL_PADDING,
    CELL_PAYLOAD_SIZE,
    CELL_VERSIONS,
    CELL_VPADDING,
    MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS,
    Cell,
    get_circ_id_size,
    is_variable_length_cell,
    pack_fixed_cell,
    pack_var_cell,
)
from .log import log

MAX_VARIABLE_CELL_SIZE = 1024 * 1024


class TorConnection:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.link_proto = 0
        self._recv_buf = b""
        self._read_lock = asyncio.Lock()
        self._cell_queues: dict = {}
        self._router_task: asyncio.Task | None = None

    @property
    def wide(self) -> bool:
        return self.link_proto >= MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS

    async def connect(self, timeout: float = 10.0) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        log.info("Connecting TLS to %s:%d", self.host, self.port)
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, ssl=ctx), timeout=timeout
        )
        log.info("TLS connected to %s:%d", self.host, self.port)

    async def _read_exactly(self, n: int) -> bytes:
        while len(self._recv_buf) < n:
            chunk = await self.reader.read(65536)
            if not chunk:
                raise ConnectionError("TLS connection closed")
            self._recv_buf += chunk
        result = self._recv_buf[:n]
        self._recv_buf = self._recv_buf[n:]
        return result

    async def send_var_cell(self, circ_id: int, command: int, payload: bytes) -> None:
        data = pack_var_cell(circ_id, command, payload, self.wide)
        self.writer.write(data)
        await self.writer.drain()

    async def send_fixed_cell(self, circ_id: int, command: int, payload: bytes) -> None:
        data = pack_fixed_cell(circ_id, command, payload, self.wide)
        self.writer.write(data)
        await self.writer.drain()

    async def recv_cell(self) -> Cell:
        async with self._read_lock:
            link = self.link_proto
            ci_size = get_circ_id_size(link)
            circ_id_bytes = await self._read_exactly(ci_size)
            cmd_byte = await self._read_exactly(1)
            command = cmd_byte[0]

            if ci_size == 2:
                circ_id = struct.unpack("!H", circ_id_bytes)[0]
            else:
                circ_id = struct.unpack("!I", circ_id_bytes)[0]

            if is_variable_length_cell(command, link):
                len_bytes = await self._read_exactly(2)
                length = struct.unpack("!H", len_bytes)[0]
                if length > MAX_VARIABLE_CELL_SIZE:
                    raise ConnectionError(
                        f"Oversized variable cell from relay: {length} bytes"
                    )
                payload = await self._read_exactly(length)
                return Cell(
                    circ_id=circ_id, command=command, payload=payload, is_fixed=False
                )
            else:
                payload = await self._read_exactly(CELL_PAYLOAD_SIZE)
                return Cell(
                    circ_id=circ_id, command=command, payload=payload, is_fixed=True
                )

    def start_cell_router(self) -> None:
        if self._router_task is None or self._router_task.done():
            self._router_task = asyncio.create_task(self._router_loop())

    def register_circuit(self, circ_id: int) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._cell_queues[circ_id] = queue
        return queue

    def unregister_circuit(self, circ_id: int) -> None:
        self._cell_queues.pop(circ_id, None)

    async def _router_loop(self) -> None:
        try:
            while True:
                cell = await self.recv_cell()
                queue = self._cell_queues.get(cell.circ_id)
                if queue is not None:
                    await queue.put(cell)
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError):
            pass
        except Exception:
            pass
        finally:
            for queue in list(self._cell_queues.values()):
                queue.put_nowait(ConnectionError("Tor connection closed"))
            self._cell_queues.clear()

    async def close(self) -> None:
        if self._router_task and not self._router_task.done():
            self._router_task.cancel()
            try:
                await asyncio.gather(self._router_task, return_exceptions=True)
            except Exception:
                pass
        if self.writer:
            try:
                self.writer.close()
                await asyncio.wait_for(self.writer.wait_closed(), timeout=5)
            except Exception:
                pass
            self.writer = None
            self.reader = None


async def tor_link_handshake(conn: TorConnection) -> None:

    vers = [5, 4, 3]
    payload = b"".join(struct.pack("!H", v) for v in vers)
    await conn.send_var_cell(0, CELL_VERSIONS, payload)

    ci_size = 2
    while True:
        await conn._read_exactly(ci_size)
        cmd_byte = await conn._read_exactly(1)
        command = cmd_byte[0]
        if command == CELL_VERSIONS:
            len_bytes = await conn._read_exactly(2)
            length = struct.unpack("!H", len_bytes)[0]
            resp = await conn._read_exactly(length)
            break
        elif command >= 128:
            len_bytes = await conn._read_exactly(2)
            length = struct.unpack("!H", len_bytes)[0]
            await conn._read_exactly(length)
        else:
            await conn._read_exactly(CELL_PAYLOAD_SIZE)

    if length % 2 != 0:
        raise RuntimeError("Odd VERSIONS payload -- connection refused")

    remote_versions = set()
    for i in range(0, length, 2):
        v = struct.unpack("!H", resp[i : i + 2])[0]
        remote_versions.add(v)

    common = sorted(set(vers) & remote_versions, reverse=True)
    if not common:
        raise RuntimeError("No common link protocol version")
    conn.link_proto = common[0]
    log.info(
        "Negotiated link protocol v%d (remote: %s)",
        conn.link_proto,
        sorted(remote_versions),
    )

    cell = await conn.recv_cell()
    while cell.command in (CELL_PADDING, CELL_VPADDING):
        cell = await conn.recv_cell()
    if cell.command != CELL_CERTS:
        raise RuntimeError(f"Expected CERTS (129), got {cell.command}")
    log.debug("Received CERTS (%d bytes)", len(cell.payload))

    cell = await conn.recv_cell()
    while cell.command in (CELL_PADDING, CELL_VPADDING):
        cell = await conn.recv_cell()
    if cell.command != CELL_AUTH_CHALLENGE:
        raise RuntimeError(f"Expected AUTH_CHALLENGE (130), got {cell.command}")
    log.debug("Received AUTH_CHALLENGE (%d bytes)", len(cell.payload))

    netinfo = struct.pack("!I", 0)
    netinfo += b"\x04\x04\x00\x00\x00\x00"
    netinfo += b"\x00"
    await conn.send_fixed_cell(0, CELL_NETINFO, netinfo)

    cell = await conn.recv_cell()
    while cell.command in (CELL_PADDING, CELL_VPADDING):
        cell = await conn.recv_cell()
    if cell.command != CELL_NETINFO:
        raise RuntimeError(f"Expected NETINFO (8), got {cell.command}")
    log.info("Link handshake complete (proto v%d)", conn.link_proto)
