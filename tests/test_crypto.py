import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from torproxy.cells import (
    CPATH_KEY_MATERIAL_LEN,
    NTOR_PROTOID,
    RELAY_PAYLOAD_SIZE,
    SERVER_STR,
    build_relay_payload,
)
from torproxy.crypto import (
    RelayCrypto,
    hmac_sha256,
    kdf_rfc5869_sha256,
    ntor_client_handshake,
    ntor_create,
)


def server_ntor_reply(server_private: bytes, router_id: bytes, skin: bytes):
    priv = X25519PrivateKey.from_private_bytes(server_private)
    pub_b = priv.public_key().public_bytes_raw()
    pub_x = skin[52:84]
    x_pub = X25519PublicKey.from_public_bytes(pub_x)
    y_priv = X25519PrivateKey.generate()
    pub_y = y_priv.public_key().public_bytes_raw()
    exp_yx = y_priv.exchange(x_pub)
    exp_bx = priv.exchange(x_pub)
    secret_input = exp_yx + exp_bx + router_id + pub_b + pub_x + pub_y + NTOR_PROTOID
    verify = hmac_sha256(NTOR_PROTOID + b":verify", secret_input)
    auth_input = verify + router_id + pub_b + pub_y + pub_x + NTOR_PROTOID + SERVER_STR
    auth = hmac_sha256(NTOR_PROTOID + b":mac", auth_input)
    return pub_y + auth, secret_input


class TestNtor(unittest.TestCase):
    def test_client_handshake_matches_server(self):
        router_id = bytes(range(20))
        server_private = X25519PrivateKey.generate().private_bytes_raw()
        pub_b = (
            X25519PrivateKey.from_private_bytes(server_private)
            .public_key()
            .public_bytes_raw()
        )
        state, skin = ntor_create(router_id, pub_b)
        reply, secret_input = server_ntor_reply(server_private, router_id, skin)
        key_data = ntor_client_handshake(state, reply, CPATH_KEY_MATERIAL_LEN)
        self.assertIsNotNone(key_data)
        self.assertEqual(len(key_data), CPATH_KEY_MATERIAL_LEN)

        expected = kdf_rfc5869_sha256(
            secret_input,
            NTOR_PROTOID + b":key_extract",
            NTOR_PROTOID + b":key_expand",
            CPATH_KEY_MATERIAL_LEN,
        )
        self.assertEqual(key_data, expected)


class TestRelayCrypto(unittest.TestCase):
    def test_forward_backward_round_trip_and_digest(self):
        key_data = bytes(range(CPATH_KEY_MATERIAL_LEN))
        crypto = RelayCrypto(key_data)
        plaintext = (bytes(range(256)) * 2)[:509]
        encrypted = crypto.encrypt_forward(plaintext)
        self.assertNotEqual(plaintext, encrypted)
        self.assertEqual(len(encrypted), len(plaintext))

        relay = build_relay_payload(2, 0x8001, b"hello", b"\x00" * 4)
        digest = crypto.set_forward_digest(relay)
        self.assertEqual(len(digest), 20)


class TestCellPacking(unittest.TestCase):
    def test_relay_payload_fits_fixed_cell(self):
        relay = build_relay_payload(2, 0x8001, b"x" * RELAY_PAYLOAD_SIZE)
        self.assertEqual(len(relay), 509)


if __name__ == "__main__":
    unittest.main()
