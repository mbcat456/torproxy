import asyncio
import unittest

from torproxy.cells import (
    CPATH_KEY_MATERIAL_LEN,
    STREAMWINDOW_INCREMENT,
)
from torproxy.circuit import TorCircuit
from torproxy.crypto import RelayCrypto


class FakeWriter:
    def __init__(self):
        self.sent = []
        self.closed = False

    def is_closing(self):
        return self.closed


class FakeConn:
    def __init__(self):
        self.wide = True
        self.writer = FakeWriter()
        self.sent = []

    async def send_fixed_cell(self, circ_id, command, payload):
        self.sent.append((circ_id, command, payload))

    async def recv_cell(self):
        await asyncio.sleep(3600)

    async def close(self):
        self.writer.closed = True

    def unregister_circuit(self, circ_id):
        return None


def make_circuit():
    conn = FakeConn()
    circuit = TorCircuit(conn, 0x80000001)
    circuit.hop1 = RelayCrypto(bytes(range(CPATH_KEY_MATERIAL_LEN)))
    circuit.hop2 = RelayCrypto(bytes(range(1, CPATH_KEY_MATERIAL_LEN + 1)))
    circuit.hop3 = RelayCrypto(bytes(range(2, CPATH_KEY_MATERIAL_LEN + 2)))
    circuit.built = True
    return circuit


def add_stream(circuit):
    sid = circuit._next_stream_id
    circuit._next_stream_id = ((sid + 1) & 0xFFFF) or 0x8001
    circuit._stream_queues[sid] = asyncio.Queue(maxsize=512)
    circuit._stream_deliver_windows[sid] = 500
    circuit._stream_package_windows[sid] = 500
    circuit._active_sids.add(sid)
    circuit._active_streams += 1
    return sid


class TestCircuitFlowControl(unittest.IsolatedAsyncioTestCase):
    async def test_package_window_and_authenticated_sendme(self):
        circuit = make_circuit()
        sid = add_stream(circuit)
        await circuit.send_data(sid, b"x" * (498 * 100))
        self.assertEqual(circuit._package_window, 1000 - 100)
        self.assertEqual(len(circuit._sendme_digest_queue), 1)
        expected = circuit._sendme_digest_queue[0]

        await circuit._handle_sendme(0, b"\x01\x00\x14" + expected)
        self.assertEqual(circuit._package_window, 1000)
        self.assertEqual(len(circuit._sendme_digest_queue), 0)

    async def test_bad_sendme_digest_fails_circuit(self):
        circuit = make_circuit()
        sid = add_stream(circuit)
        await circuit.send_data(sid, b"x" * (498 * 100))
        with self.assertRaises(RuntimeError):
            await circuit._handle_sendme(0, b"\x01\x00\x14" + b"\x00" * 20)

    async def test_stream_sendme_increments_window(self):
        circuit = make_circuit()
        sid = add_stream(circuit)
        await circuit.send_data(sid, b"x" * (498 * 50))
        self.assertEqual(circuit._stream_package_windows[sid], 450)
        await circuit._handle_sendme(sid, b"")
        self.assertEqual(
            circuit._stream_package_windows[sid], 450 + STREAMWINDOW_INCREMENT
        )


if __name__ == "__main__":
    unittest.main()
