import unittest

from torproxy.auth import AuthManager
from torproxy.config import load_config
from torproxy.proxy import ProxyRequestError, _parse_authority
from torproxy.session import SessionManager


class DummyWriter:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data):
        self.data += data

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    def is_closing(self):
        return False


class DummyCircuit:
    def __init__(self):
        self.conn = None
        self._dispatch_running = True
        self._circuit_failed = False
        self._502_count = 0
        self.circuits = None
        self._active_streams = 0
        self._stream_queues = {}
        self._stream_deliver_windows = {}
        self._stream_package_windows = {}

    def _ensure_dispatch(self):
        return None

    def _drop_stream(self, sid):
        self._stream_queues.pop(sid, None)


class DummyPool:
    def __init__(self, circuit=None):
        self.circuits = [circuit or DummyCircuit()]

    def get_circuit(self):
        return self.circuits[0]

    def note_502(self, circuit):
        circuit._502_count += 1


class TestAuthorityParsing(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(_parse_authority("example.com:8443"), ("example.com", 8443))

    def test_default_port(self):
        self.assertEqual(_parse_authority("example.com"), ("example.com", 443))

    def test_ipv6(self):
        self.assertEqual(_parse_authority("[::1]:8443"), ("::1", 8443))

    def test_invalid_port(self):
        with self.assertRaises(ProxyRequestError):
            _parse_authority("example.com:0")
        with self.assertRaises(ProxyRequestError):
            _parse_authority("example.com:65536")


class TestAuth(unittest.TestCase):
    def test_partial_credentials_keeps_supplied_value(self):
        auth = AuthManager(config_username="onlyuser", config_password=None)
        self.assertEqual(auth.credentials.username, "onlyuser")
        self.assertTrue(auth.credentials.password)

    def test_sticky_auth_and_ttl(self):
        auth = AuthManager(config_username="user", config_password="pass")
        import base64

        headers = {}
        headers["proxy-authorization"] = (
            "Basic " + base64.b64encode(b"user-session-abc-time-15:pass").decode()
        )
        self.assertTrue(auth.authenticate(headers))
        self.assertEqual(AuthManager.extract_session_id(headers), "abc")
        self.assertEqual(AuthManager.extract_session_ttl(headers), 15)


class TestConfig(unittest.TestCase):
    def test_cli_overrides_config(self):
        cfg = load_config(["--port", "9090", "--num-circuits", "3"])
        self.assertEqual(cfg.port, 9090)
        self.assertEqual(cfg.num_circuits, 3)

    def test_invalid_values_rejected(self):
        with self.assertRaises(SystemExit):
            load_config(["--port", "0"])
        with self.assertRaises(SystemExit):
            load_config(["--max-clients", "0"])


class TestSession(unittest.IsolatedAsyncioTestCase):
    async def test_ttl_override(self):
        pool = DummyPool()
        sessions = SessionManager(default_ttl_minutes=30)
        circuit = await sessions.get_circuit("sid", pool, ttl_minutes=0)
        self.assertIs(circuit, pool.circuits[0])
        self.assertEqual(sessions._sessions["sid"][1], float("inf"))


if __name__ == "__main__":
    unittest.main()
