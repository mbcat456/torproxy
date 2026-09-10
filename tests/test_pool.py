import unittest

from torproxy.cells import (
    CIRCUIT_ID_FIRST_NARROW,
    CIRCUIT_ID_FIRST_WIDE,
    CIRCUIT_ID_MASK_NARROW,
    CIRCUIT_ID_MASK_WIDE,
)
from torproxy.consensus import RelayInfo
from torproxy.pool import (
    advance_circuit_id,
    initial_circuit_id,
    is_healthy_response,
)


def usable_relay(flags: set[str]) -> RelayInfo:
    return RelayInfo(
        nickname="relay",
        identity=b"a" * 20,
        ip="1.2.3.4",
        orport=443,
        flags=flags,
        ntor_onion_key=b"k" * 32,
    )


class TestRelayCapabilities(unittest.TestCase):
    def test_usable_guard_and_exit(self):
        relay = usable_relay({"Running", "Valid", "Guard", "Exit"})
        self.assertTrue(relay.is_usable())
        self.assertTrue(relay.can_guard())
        self.assertTrue(relay.can_exit())

    def test_bad_exit_is_not_a_usable_exit(self):
        relay = usable_relay({"Running", "Valid", "Exit", "BadExit"})
        self.assertTrue(relay.is_usable())
        self.assertFalse(relay.can_exit())

    def test_unusable_relay_rejects_all_capabilities(self):
        relay = usable_relay({"Guard", "Exit"})
        self.assertFalse(relay.is_usable())
        self.assertFalse(relay.can_guard())
        self.assertFalse(relay.can_exit())


class TestCircuitIds(unittest.TestCase):
    def test_initial_ids_match_link_width(self):
        self.assertEqual(initial_circuit_id(False), CIRCUIT_ID_FIRST_NARROW)
        self.assertEqual(initial_circuit_id(True), CIRCUIT_ID_FIRST_WIDE)

    def test_advance_wraps_to_first_id(self):
        self.assertEqual(
            advance_circuit_id(CIRCUIT_ID_MASK_NARROW, False),
            CIRCUIT_ID_FIRST_NARROW,
        )
        self.assertEqual(
            advance_circuit_id(CIRCUIT_ID_MASK_WIDE, True),
            CIRCUIT_ID_FIRST_WIDE,
        )

    def test_advance_increments_within_range(self):
        self.assertEqual(advance_circuit_id(1000, False), 1001)
        self.assertEqual(advance_circuit_id(0x80000001, True), 0x80000002)


class TestHealthyResponse(unittest.TestCase):
    def test_accepts_success_status_with_body(self):
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n" + b"x" * 40
        self.assertTrue(is_healthy_response(response))

    def test_rejects_error_status(self):
        response = b"HTTP/1.1 502 Bad Gateway\r\n\r\n" + b"x" * 40
        self.assertFalse(is_healthy_response(response))

    def test_rejects_short_response(self):
        self.assertFalse(is_healthy_response(b"HTTP/1.1 200 OK\r\n\r\n"))


if __name__ == "__main__":
    unittest.main()
