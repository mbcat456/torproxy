import asyncio
import base64
import unittest
from types import SimpleNamespace

from torproxy.auth import AuthManager
from torproxy.proxy import HttpProxy
from torproxy.session import SessionManager


class FakeWriter:
    def is_closing(self):
        return False


class FakeCircuit:
    def __init__(self):
        self.conn = SimpleNamespace(writer=FakeWriter())
        self._dispatch_running = True
        self._circuit_failed = False
        self._502_count = 0
        self._active_streams = 0
        self.requests = []
        self.responses = []
        self.errors = []
        self.tunnel_response = b""
        self.stream_id = 1

    async def begin_stream(self, host, port):
        self.stream_id += 1
        return self.stream_id

    async def send_data(self, sid, data):
        return None

    async def recv_stream_data(self, sid, timeout=None):
        response = self.tunnel_response
        self.tunnel_response = b""
        return response

    async def _drop_stream(self, sid):
        return None

    async def stream_request(self, host, port, http_data, use_tls=False):
        self.requests.append((host, port, http_data, use_tls))
        if self.errors:
            raise self.errors.pop(0)
        if not self.responses:
            self.responses.append(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            )
        yield self.responses.pop(0)


class FakePool:
    def __init__(self, circuits=None):
        self.circuits = circuits or [FakeCircuit()]
        self.cursor = 0

    def get_circuit(self):
        circuit = self.circuits[self.cursor % len(self.circuits)]
        self.cursor += 1
        return circuit

    def note_502(self, circuit):
        circuit._502_count += 1


class ProxyFeatureTestCase(unittest.IsolatedAsyncioTestCase):
    authenticated = False

    async def asyncSetUp(self):
        if self.authenticated:
            self.auth = AuthManager(config_username="user", config_password="pass")
        else:
            self.auth = AuthManager(no_auth=True)
        self.sessions = SessionManager(default_ttl_minutes=30)
        self.pool = FakePool()
        self.proxy = HttpProxy(
            "127.0.0.1",
            0,
            self.pool,
            self.auth,
            self.sessions,
            max_request_bytes=1024,
        )
        await self.proxy.start()
        self.port = self.proxy._server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        await self.proxy.stop()

    def inject_auth(self, payload: bytes) -> bytes:
        if self.auth.no_auth:
            return payload
        token = base64.b64encode(b"user:pass").decode()
        head, separator, rest = payload.partition(b"\r\n")
        if not separator:
            return payload
        return (
            head + separator + f"Proxy-Authorization: Basic {token}\r\n".encode() + rest
        )

    async def exchange(self, payload, wait_for_close=True, with_auth=True):
        if with_auth:
            payload = self.inject_auth(payload)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(payload)
        await writer.drain()
        if wait_for_close:
            writer.write_eof()
        data = b""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), 2)
                if not chunk:
                    break
                data += chunk
        except asyncio.TimeoutError:
            pass
        writer.close()
        await writer.wait_closed()
        return data

    async def open_direct(self, payload):
        payload = self.inject_auth(payload)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(payload)
        await writer.drain()
        return reader, writer

    @staticmethod
    def parse_response(data):
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        version, status, _ = lines[0].decode().split(" ", 2)
        headers = {}
        for line in lines[1:]:
            key, _, value = line.decode().partition(":")
            headers[key.lower()] = value.strip()
        return int(status), headers, body

    async def test_absolute_get_strips_proxy_headers(self):
        response = await self.exchange(
            b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\n"
            b"Host: wrong.example\r\n"
            b"Proxy-Connection: keep-alive\r\n"
            b"Connection: keep-alive\r\n"
            b"X-Session-Id: secret\r\n\r\n"
        )
        status, _, body = self.parse_response(response)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"OK")
        host, port, request, tls = self.pool.circuits[0].requests[-1]
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 8080)
        self.assertFalse(tls)
        self.assertIn(b"GET /path?q=1 HTTP/1.1\r\n", request)
        self.assertIn(b"Host: example.com:8080\r\n", request)
        self.assertNotIn(b"proxy-connection", request.lower())
        self.assertNotIn(b"x-session-id", request.lower())
        self.assertIn(b"Connection: close\r\n", request)

    async def test_origin_form_uses_host_header(self):
        response = await self.exchange(
            b"GET /origin HTTP/1.1\r\nHost: origin.example:9000\r\n\r\n"
        )
        status, _, body = self.parse_response(response)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"OK")
        host, port, request, _ = self.pool.circuits[0].requests[-1]
        self.assertEqual((host, port), ("origin.example", 9000))
        self.assertIn(b"Host: origin.example:9000\r\n", request)

    async def test_content_length_post_forwarded(self):
        response = await self.exchange(
            b"POST http://example.com/upload HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 5\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"hello"
        )
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 200)
        request = self.pool.circuits[0].requests[-1][2]
        self.assertTrue(request.endswith(b"\r\n\r\nhello"))
        self.assertIn(b"Content-Length: 5\r\n", request)

    async def test_chunked_post_decoded(self):
        response = await self.exchange(
            b"POST http://example.com/upload HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: yes\r\n\r\n"
        )
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 200)
        request = self.pool.circuits[0].requests[-1][2]
        self.assertIn(b"Content-Length: 11\r\n", request)
        self.assertTrue(request.endswith(b"\r\n\r\nhello world"))
        self.assertNotIn(b"transfer-encoding", request.lower())

    async def test_content_length_and_chunked_rejected(self):
        response = await self.exchange(
            b"POST http://example.com/ HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 3\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 400)
        self.assertEqual(self.pool.circuits[0].requests, [])

    async def test_unsupported_transfer_encoding(self):
        response = await self.exchange(
            b"POST http://example.com/ HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Transfer-Encoding: gzip\r\n\r\n"
        )
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 501)

    async def test_negative_content_length(self):
        response = await self.exchange(
            b"POST http://example.com/ HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: -1\r\n\r\n"
        )
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 400)

    async def test_oversized_content_length(self):
        response = await self.exchange(
            b"POST http://example.com/ HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 2048\r\n\r\n"
        )
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 413)

    async def test_expect_100_continue(self):
        reader, writer = await self.open_direct(
            b"POST http://example.com/upload HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 4\r\n"
            b"Expect: 100-continue\r\n\r\n"
        )
        interim = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertTrue(interim.startswith(b"HTTP/1.1 100 Continue"))
        writer.write(b"data")
        writer.write_eof()
        await writer.drain()
        final = await asyncio.wait_for(reader.read(), 2)
        status, _, _ = self.parse_response(final)
        self.assertEqual(status, 200)
        request = self.pool.circuits[0].requests[-1][2]
        self.assertTrue(request.endswith(b"\r\n\r\ndata"))
        writer.close()
        await writer.wait_closed()

    async def test_https_absolute_form(self):
        response = await self.exchange(
            b"GET https://example.com/secure HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        status, _, body = self.parse_response(response)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"OK")
        host, port, request, tls = self.pool.circuits[0].requests[-1]
        self.assertEqual((host, port, tls), ("example.com", 443, True))
        self.assertIn(b"Host: example.com\r\n", request)

    async def test_https_nondefault_port(self):
        await self.exchange(
            b"GET https://example.com:8443/secure HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        request = self.pool.circuits[0].requests[-1][2]
        self.assertIn(b"Host: example.com:8443\r\n", request)

    async def test_ipv6_host_bracketed(self):
        await self.exchange(
            b"GET http://[::1]:8080/ipv6 HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n"
        )
        host, port, request, _ = self.pool.circuits[0].requests[-1]
        self.assertEqual((host, port), ("::1", 8080))
        self.assertIn(b"Host: [::1]:8080\r\n", request)

    async def test_connect_tunnel(self):
        self.pool.circuits[0].tunnel_response = b"tunnel-data"
        reader, writer = await self.open_direct(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        )
        established = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertTrue(established.startswith(b"HTTP/1.1 200"))
        writer.write(b"inside-tunnel")
        await writer.drain()
        downstream = await asyncio.wait_for(reader.read(11), 2)
        self.assertEqual(downstream, b"tunnel-data")
        writer.close()
        await writer.wait_closed()

    async def test_connect_ipv6_authority(self):
        reader, writer = await self.open_direct(
            b"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n"
        )
        established = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertTrue(established.startswith(b"HTTP/1.1 200"))
        writer.close()
        await writer.wait_closed()

    async def test_connect_bad_authority(self):
        response = await self.exchange(
            b"CONNECT example.com:abc HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 400)

    async def test_malformed_request_line(self):
        response = await self.exchange(b"NOT A REQUEST\r\n\r\n")
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 400)

    async def test_missing_host_for_origin_form(self):
        response = await self.exchange(b"GET /missing HTTP/1.1\r\n\r\n")
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 400)

    async def test_retry_after_empty_response(self):
        first = FakeCircuit()
        first.errors.append(RuntimeError("fail"))
        second = FakeCircuit()
        self.pool = FakePool([first, second])
        self.proxy.pool = self.pool
        response = await self.exchange(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 200)
        self.assertTrue(first.requests)
        self.assertTrue(second.requests)

    async def test_post_is_not_retried(self):
        first = FakeCircuit()
        first.errors.append(RuntimeError("fail"))
        self.pool = FakePool([first])
        self.proxy.pool = self.pool
        response = await self.exchange(
            b"POST http://example.com/ HTTP/1.1\r\n"
            b"Host: example.com\r\nContent-Length: 0\r\n\r\n"
        )
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 502)
        self.assertEqual(len(first.requests), 1)


class AuthenticatedProxyTestCase(ProxyFeatureTestCase):
    authenticated = True

    async def test_missing_auth(self):
        response = await self.exchange(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            with_auth=False,
        )
        status, headers, _ = self.parse_response(response)
        self.assertEqual(status, 407)
        self.assertIn("proxy-authenticate", headers)

    async def test_valid_auth_and_sticky_username(self):
        token = base64.b64encode(b"user-session-sid1-time-0:pass").decode()
        response = await self.exchange(
            b"GET http://example.com/ HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            + f"Proxy-Authorization: Basic {token}\r\n\r\n".encode(),
            with_auth=False,
        )
        status, _, _ = self.parse_response(response)
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
