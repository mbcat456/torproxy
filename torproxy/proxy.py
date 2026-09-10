import asyncio
import ipaddress
import traceback
from typing import Any
from urllib.parse import urlsplit

from .auth import AuthManager
from .circuit import TorCircuit
from .log import log
from .session import SessionManager

MAX_REQUEST_LINE = 16 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADERS = 200


class ProxyRequestError(Exception):
    def __init__(self, status: int, message: str = ""):
        super().__init__(message)
        self.status = status


def _format_host_port(host: str, port: int, scheme: str) -> str:
    default = 443 if scheme == "https" else 80
    try:
        if ipaddress.ip_address(host).version == 6:
            host = f"[{host}]"
    except ValueError:
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
    return host if port == default else f"{host}:{port}"


def _parse_authority(authority: str, default_port: int = 443) -> tuple[str, int]:
    authority = authority.strip()
    if not authority:
        raise ProxyRequestError(400)
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise ProxyRequestError(400)
        host = authority[1:end]
        rest = authority[end + 1 :]
        if rest.startswith(":"):
            rest = rest[1:]
        elif rest:
            raise ProxyRequestError(400)
        else:
            rest = ""
    else:
        if authority.count(":") > 1:
            raise ProxyRequestError(400)
        host, _, rest = authority.partition(":")

    host = host.strip()
    if not host:
        raise ProxyRequestError(400)
    if rest:
        try:
            port = int(rest)
        except ValueError as exc:
            raise ProxyRequestError(400) from exc
    else:
        port = default_port
    if not 1 <= port <= 65535:
        raise ProxyRequestError(400)
    return host, port


class HttpProxy:
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        pool: Any,
        auth: AuthManager,
        sessions: SessionManager,
        max_clients: int = 5000,
        max_request_bytes: int = 2 * 1024 * 1024,
    ):
        self.host = listen_host
        self.port = listen_port
        self.pool = pool
        self.auth = auth
        self.sessions = sessions
        self._server: asyncio.AbstractServer | None = None
        self._client_sem = asyncio.Semaphore(max(1, max_clients))
        self.max_request_bytes = max(1, max_request_bytes)
        self.bytes_up = 0
        self.bytes_down = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self.host, self.port, backlog=16384
        )
        log.info("HTTP proxy listening on %s:%d", self.host, self.port)

    async def _get_circuit(self, headers: dict[str, str]) -> TorCircuit:
        session_id = AuthManager.extract_session_id(headers)
        if session_id:
            ttl = AuthManager.extract_session_ttl(headers)
            return await self.sessions.get_circuit(
                session_id, self.pool, ttl_minutes=ttl
            )
        return self.pool.get_circuit()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        async with self._client_sem:
            await self._handle_limited(reader, writer)

    async def _handle_limited(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            request_line = await self._read_line(reader, MAX_REQUEST_LINE)
            if not request_line:
                return
            parts = request_line.decode("latin-1").split()
            if len(parts) != 3 or not parts[2].startswith("HTTP/"):
                await self._send_error(writer, 400)
                return
            method, target, version = parts
            method = method.upper()

            headers = await self._read_headers(reader)
            if headers is None:
                await self._send_error(writer, 431)
                return

            if not self.auth.authenticate(headers):
                await self._send_auth_required(writer)
                return

            if method == "CONNECT":
                await self._handle_connect(writer, reader, target, headers)
                return

            try:
                host, port, use_tls, path = self._parse_http_target(target, headers)
            except ProxyRequestError as exc:
                await self._send_error(writer, exc.status)
                return

            await self._handle_http(
                writer, reader, method, host, port, use_tls, path, headers, version
            )
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        except ProxyRequestError as exc:
            try:
                await self._send_error(writer, exc.status)
            except Exception:
                pass
        except Exception:
            log.debug("Error handling %s: %s", peer, traceback.format_exc())
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _read_line(
        self, reader: asyncio.StreamReader, limit: int, timeout: float = 30.0
    ) -> bytes:
        buffer = bytearray()
        while len(buffer) <= limit:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                return bytes(buffer)
            buffer.extend(chunk)
            if len(buffer) > limit:
                raise ProxyRequestError(431)
            pos = buffer.find(b"\n")
            if pos >= 0:
                line = bytes(buffer[:pos]).rstrip(b"\r")
                extra = bytes(buffer[pos + 1 :])
                if extra:
                    reader.feed_data(extra)
                return line
        raise ProxyRequestError(431)

    async def _read_headers(
        self, reader: asyncio.StreamReader
    ) -> dict[str, str] | None:
        headers: dict[str, str] = {}
        total = 0
        while True:
            line = await self._read_line(reader, MAX_HEADER_BYTES, timeout=10.0)
            if not line:
                return headers
            total += len(line)
            if total > MAX_HEADER_BYTES or len(headers) >= MAX_HEADERS:
                raise ProxyRequestError(431)
            text = line.decode("latin-1")
            if not text:
                return headers
            if text[:1] in (" ", "\t"):
                if headers:
                    previous = next(reversed(headers))
                    headers[previous] = f"{headers[previous]} {text.strip()}"
                continue
            if ":" not in text:
                raise ProxyRequestError(400)
            key, value = text.split(":", 1)
            key = key.strip().lower()
            if not key:
                raise ProxyRequestError(400)
            if key in headers:
                headers[key] = f"{headers[key]}, {value.strip()}"
            else:
                headers[key] = value.strip()

    def _parse_http_target(
        self, target: str, headers: dict[str, str]
    ) -> tuple[str, int, bool, str]:
        if target == "*":
            raise ProxyRequestError(400)
        if target.startswith("/"):
            host_header = headers.get("host", "")
            if not host_header:
                raise ProxyRequestError(400)
            host, port = _parse_authority(host_header, default_port=80)
            return host, port, False, target

        try:
            parsed = urlsplit(target)
        except ValueError as exc:
            raise ProxyRequestError(400) from exc
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ProxyRequestError(400)
        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise ProxyRequestError(400) from exc
        if parsed_port is not None and not 1 <= parsed_port <= 65535:
            raise ProxyRequestError(400)
        port = parsed_port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return parsed.hostname, port, parsed.scheme == "https", path

    async def _read_exact(self, reader: asyncio.StreamReader, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = await asyncio.wait_for(
                reader.read(min(65536, size - len(data))), timeout=30.0
            )
            if not chunk:
                raise ProxyRequestError(400)
            data.extend(chunk)
        return bytes(data)

    async def _read_chunked_body(self, reader: asyncio.StreamReader) -> bytes:
        body = bytearray()
        while True:
            line = await self._read_line(reader, 4096)
            if not line:
                raise ProxyRequestError(400)
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError as exc:
                raise ProxyRequestError(400) from exc
            if size < 0:
                raise ProxyRequestError(400)
            if size == 0:
                trailer_count = 0
                while True:
                    trailer = await self._read_line(reader, 8192)
                    if trailer == b"":
                        break
                    trailer_count += 1
                    if trailer_count >= 100:
                        raise ProxyRequestError(431)
                return bytes(body)
            if len(body) + size > self.max_request_bytes:
                raise ProxyRequestError(413)
            chunk = await self._read_exact(reader, size + 2)
            if not chunk.endswith(b"\r\n"):
                raise ProxyRequestError(400)
            body.extend(chunk[:-2])

    async def _read_body(
        self,
        writer: asyncio.StreamWriter,
        reader: asyncio.StreamReader,
        method: str,
        headers: dict[str, str],
    ) -> bytes:
        content_length = headers.get("content-length")
        transfer_encoding = headers.get("transfer-encoding", "").lower()

        if content_length is not None and transfer_encoding:
            raise ProxyRequestError(400)

        body = b""
        if transfer_encoding:
            encodings = [item.strip() for item in transfer_encoding.split(",")]
            if encodings != ["chunked"]:
                raise ProxyRequestError(501)
            if self._expects_continue(headers):
                await self._send_interim(writer, 100)
            body = await self._read_chunked_body(reader)
            return body

        if content_length is not None:
            try:
                size = int(content_length)
            except ValueError as exc:
                raise ProxyRequestError(400) from exc
            if size < 0:
                raise ProxyRequestError(400)
            if size > self.max_request_bytes:
                raise ProxyRequestError(413)
            if size and self._expects_continue(headers):
                await self._send_interim(writer, 100)
            body = await self._read_exact(reader, size) if size else b""
        elif self._expects_continue(headers) and method not in ("GET", "HEAD"):
            await self._send_interim(writer, 100)
        return body

    @staticmethod
    def _expects_continue(headers: dict[str, str]) -> bool:
        return "100-continue" in headers.get("expect", "").lower()

    async def _handle_connect(
        self,
        writer: asyncio.StreamWriter,
        reader: asyncio.StreamReader,
        target: str,
        headers: dict[str, str],
    ) -> None:
        try:
            host, port = _parse_authority(target, default_port=443)
        except ProxyRequestError as exc:
            await self._send_error(writer, exc.status)
            return

        circuit: TorCircuit | None = None
        sid: int | None = None
        session_id = AuthManager.extract_session_id(headers)
        attempts = 2 if session_id else 4
        failed_ids = set()
        for _ in range(attempts):
            try:
                circuit = await self._get_circuit(headers)
            except RuntimeError:
                await self._send_error(writer, 502)
                return
            if id(circuit) in failed_ids:
                continue
            try:
                sid = await circuit.begin_stream(host, port)
                break
            except Exception:
                failed_ids.add(id(circuit))
                self.pool.note_502(circuit)
                if session_id:
                    await self.sessions.release(session_id)
        if sid is None or circuit is None:
            await self._send_error(writer, 502)
            return

        try:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        except Exception:
            await circuit._drop_stream(sid)
            return

        stop = asyncio.Event()

        async def upstream():
            try:
                while not stop.is_set():
                    chunk = await reader.read(32768)
                    if not chunk:
                        break
                    self.bytes_up += len(chunk)
                    await circuit.send_data(sid, chunk)
            except (asyncio.CancelledError, ConnectionError, OSError):
                pass
            except Exception:
                log.debug("CONNECT upstream ended", exc_info=True)
            finally:
                stop.set()

        async def downstream():
            try:
                while not stop.is_set():
                    chunk = await circuit.recv_stream_data(sid, timeout=None)
                    if not chunk:
                        break
                    self.bytes_down += len(chunk)
                    writer.write(chunk)
                    await writer.drain()
            except (asyncio.CancelledError, ConnectionError, OSError):
                pass
            except Exception:
                log.debug("CONNECT downstream ended", exc_info=True)
            finally:
                stop.set()

        up_task = asyncio.create_task(upstream())
        down_task = asyncio.create_task(downstream())
        await asyncio.wait([up_task, down_task], return_when=asyncio.FIRST_COMPLETED)
        for task in (up_task, down_task):
            if not task.done():
                task.cancel()
        for task in (up_task, down_task):
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await circuit._drop_stream(sid)

    async def _handle_http(
        self,
        writer: asyncio.StreamWriter,
        reader: asyncio.StreamReader,
        method: str,
        host: str,
        port: int,
        use_tls: bool,
        path: str,
        headers: dict[str, str],
        version: str,
    ) -> None:
        try:
            body = await self._read_body(writer, reader, method, headers)
        except ProxyRequestError as exc:
            await self._send_error(writer, exc.status)
            return

        out = [f"{method} {path} HTTP/1.1\r\n".encode("latin-1")]
        hop_by_hop = {
            "host",
            "proxy-connection",
            "proxy-authorization",
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "expect",
            "content-length",
            "x-session-id",
            "x-session-ttl",
        }
        for key, value in headers.items():
            if key in hop_by_hop or key.startswith("proxy-"):
                continue
            out.append(f"{key}: {value}\r\n".encode("latin-1"))
        scheme = "https" if use_tls else "http"
        out.append(
            f"Host: {_format_host_port(host, port, scheme)}\r\n".encode("latin-1")
        )
        out.append(b"Connection: close\r\n")
        if body:
            out.append(f"Content-Length: {len(body)}\r\n".encode("ascii"))
        out.append(b"\r\n")
        if body:
            out.append(body)
        request_data = b"".join(out)

        session_id = AuthManager.extract_session_id(headers)
        sticky = bool(session_id)
        idempotent = method in ("GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE")
        attempts = (
            2 if sticky and idempotent else 1 if sticky else 4 if idempotent else 1
        )
        last_error: BaseException | None = None
        failed_ids = set()
        response_started = False

        for _ in range(attempts):
            try:
                circuit = await self._get_circuit(headers)
            except RuntimeError:
                await self._send_error(writer, 502)
                return
            if id(circuit) in failed_ids:
                continue
            got_response = False
            try:
                self.bytes_up += len(request_data)
                async for chunk in circuit.stream_request(
                    host, port, request_data, use_tls=use_tls
                ):
                    got_response = True
                    response_started = True
                    self.bytes_down += len(chunk)
                    writer.write(chunk)
                    await writer.drain()
                if got_response:
                    return
                raise RuntimeError("Empty response from origin")
            except Exception as exc:
                last_error = exc
                failed_ids.add(id(circuit))
                self.pool.note_502(circuit)
                if session_id and not got_response:
                    await self.sessions.release(session_id)
                if got_response:
                    return

        if last_error is not None:
            log.debug("Proxying %s %s failed: %s", method, path, last_error)
        if response_started:
            return
        await self._send_error(writer, 502)

    async def _send_error(self, writer: asyncio.StreamWriter, status: int) -> None:
        reason = {
            400: "Bad Request",
            407: "Proxy Authentication Required",
            408: "Request Timeout",
            413: "Payload Too Large",
            431: "Request Header Fields Too Large",
            501: "Not Implemented",
            502: "Bad Gateway",
        }.get(status, "Error")
        data = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Connection: close\r\nContent-Length: 0\r\n\r\n"
        ).encode("ascii")
        try:
            writer.write(data)
            await writer.drain()
        except Exception:
            pass

    async def _send_auth_required(self, writer: asyncio.StreamWriter) -> None:
        data = (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b'Proxy-Authenticate: Basic realm="torproxy"\r\n'
            b"Connection: close\r\nContent-Length: 0\r\n\r\n"
        )
        try:
            writer.write(data)
            await writer.drain()
        except Exception:
            pass

    async def _send_interim(self, writer: asyncio.StreamWriter, status: int) -> None:
        data = f"HTTP/1.1 {status} Continue\r\n\r\n".encode("ascii")
        writer.write(data)
        await writer.drain()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=5)
            except (asyncio.TimeoutError, Exception):
                pass
