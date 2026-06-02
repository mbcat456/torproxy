import asyncio
import traceback
from typing import Any, Dict, Optional, Tuple

from .auth import AuthManager
from .circuit import TorCircuit
from .log import log
from .session import SessionManager


class HttpProxy:

    def __init__(self, listen_host: str, listen_port: int, pool: Any,
                 auth: AuthManager, sessions: SessionManager,
                 max_clients: int = 5000,
                 max_request_bytes: int = 2 * 1024 * 1024):
        self.host = listen_host
        self.port = listen_port
        self.pool = pool
        self.auth = auth
        self.sessions = sessions
        self._server: Optional[asyncio.AbstractServer] = None
        self._client_sem = asyncio.Semaphore(max_clients)
        self.max_request_bytes = max_request_bytes
        self.bytes_up = 0
        self.bytes_down = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self.host, self.port, backlog=16384)
        log.info("HTTP proxy listening on %s:%d", self.host, self.port)

    async def _get_circuit(self, headers: Dict[str, str]) -> TorCircuit:
        session_id = AuthManager.extract_session_id(headers)
        if session_id:
            return await self.sessions.get_circuit(session_id, self.pool)
        return self.pool.get_circuit()

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        async with self._client_sem:
            await self._handle_limited(reader, writer)

    async def _handle_limited(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not request_line:
                writer.close(); return

            parts = request_line.decode("utf-8", errors="replace").strip().split()
            if len(parts) < 3:
                writer.close(); return
            method, url = parts[0].upper(), parts[1]

            headers: Dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if not line or line.strip() == b"":
                    break
                s = line.decode("utf-8", errors="replace").strip()
                if ":" in s:
                    k, v = s.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            if not self.auth.authenticate(headers):
                try:
                    writer.write(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        b"Proxy-Authenticate: Basic realm=\"torproxy\"\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                except Exception:
                    pass
                return

            if method == "CONNECT":
                await self._handle_connect(writer, reader, url, headers)
            else:
                await self._handle_http(writer, reader, method, url, headers)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        except Exception:
            log.debug("Error handling %s: %s", peer, traceback.format_exc())
        finally:
            try: writer.close()
            except Exception: pass

    async def _handle_connect(self, writer: asyncio.StreamWriter,
                              reader: asyncio.StreamReader, url: str,
                              headers: Dict[str, str]) -> None:
        host, _, port_str = url.partition(":")
        port = int(port_str) if port_str else 443
        circ: Optional[TorCircuit] = None
        sid: Optional[int] = None

        is_sticky = bool(AuthManager.extract_session_id(headers))
        attempts = 1 if is_sticky else 4
        try:
            failed = set()
            for _ in range(attempts):
                circ = await self._get_circuit(headers)
                if id(circ) in failed:
                    continue
                try:
                    sid = await circ.begin_stream(host, port)
                    break
                except Exception:
                    failed.add(id(circ))
                    self.pool.note_502(circ)
            if sid is None or circ is None:
                raise RuntimeError("CONNECT failed on all circuit attempts")
        except Exception as e:
            log.debug("CONNECT begin_stream failed: %s", e)
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except Exception: pass
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        stop = asyncio.Event()

        async def upstream():
            try:
                while not stop.is_set():
                    read_task = asyncio.ensure_future(reader.read(32768))
                    stop_task = asyncio.ensure_future(
                        asyncio.wait_for(stop.wait(), timeout=300))
                    done, _ = await asyncio.wait(
                        [read_task, stop_task], return_when=asyncio.FIRST_COMPLETED)
                    for t in [read_task, stop_task]:
                        if not t.done(): t.cancel()
                    if stop_task in done:
                        break
                    chunk = read_task.result() if read_task in done else b""
                    if not chunk:
                        break
                    self.bytes_up += len(chunk)
                    await circ.send_data(sid, chunk)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                pass
            except Exception:
                pass
            finally:
                stop.set()

        async def downstream():
            try:
                while not stop.is_set():
                    chunk = await circ.recv_stream_data(sid, timeout=60.0)
                    if not chunk:
                        break
                    self.bytes_down += len(chunk)
                    writer.write(chunk)
                    await writer.drain()
            except (asyncio.TimeoutError, ConnectionError, OSError):
                pass
            except Exception:
                pass
            finally:
                stop.set()

        t_up = asyncio.create_task(upstream())
        t_down = asyncio.create_task(downstream())
        done, pending = await asyncio.wait(
            [t_up, t_down], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        try:
            circ._drop_stream(sid)
        except Exception:
            pass

    async def _handle_http(self, writer: asyncio.StreamWriter,
                           reader: asyncio.StreamReader,
                           method: str, url: str,
                           headers: Dict[str, str]) -> None:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        is_ssl = parsed.scheme == "https"
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        cl = headers.get("content-length", "")
        if cl:
            try:
                cl_int = int(cl)
                if cl_int < 0:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    await writer.drain()
                    return
                if cl_int > self.max_request_bytes:
                    writer.write(b"HTTP/1.1 413 Payload Too Large\r\n\r\n")
                    await writer.drain()
                    return
            except ValueError:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                return

        body = b""
        te = headers.get("transfer-encoding", "").lower()
        if cl:
            remaining = int(cl)
            while len(body) < remaining:
                chunk = await asyncio.wait_for(
                    reader.read(min(65536, remaining - len(body))), timeout=30)
                if not chunk:
                    break
                body += chunk
            if len(body) != remaining:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                return
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=30)
                line = line.strip()
                if not line:
                    break
                try:
                    chunk_size = int(line.split(b";")[0], 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    break
                chunk_data = await asyncio.wait_for(
                    reader.read(chunk_size + 2), timeout=30)
                body += chunk_data[:chunk_size]
                if len(body) > self.max_request_bytes:
                    writer.write(b"HTTP/1.1 413 Payload Too Large\r\n\r\n")
                    await writer.drain()
                    return

        out = [f"{method} {path} HTTP/1.1\r\n".encode()]
        hop_by_hop = {"host", "proxy-connection", "proxy-authorization",
                      "connection", "keep-alive",
                      "content-length", "transfer-encoding"}
        for k, v in headers.items():
            if k in hop_by_hop:
                continue
            out.append(f"{k}: {v}\r\n".encode())
        out.append(f"Host: {host}\r\n".encode())
        out.append(b"Connection: close\r\n")
        if body:
            out.append(f"Content-Length: {len(body)}\r\n".encode())
        out.append(b"\r\n")
        if body:
            out.append(body)

        request_data = b"".join(out)

        is_sticky = bool(AuthManager.extract_session_id(headers))
        attempts = 1 if is_sticky else 4

        failed = set()
        for attempt in range(attempts):
            circ = await self._get_circuit(headers)
            if id(circ) in failed:
                continue

            try:
                self.bytes_up += len(request_data)
                async for chunk in circ.stream_request(host, port, request_data, use_tls=is_ssl):
                    self.bytes_down += len(chunk)
                    writer.write(chunk)
                    await writer.drain()
                return
            except Exception:
                pass
            failed.add(id(circ))
            self.pool.note_502(circ)

        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await writer.drain()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
