import hashlib
import hmac as _hmac
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .cells import CPATH_KEY_MATERIAL_LEN, NTOR_ONIONSKIN_LEN, NTOR_REPLY_LEN, NTOR_PROTOID, SERVER_STR


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return _hmac.new(key, msg, "sha256").digest()


def h_tweak(tweak: bytes, data: bytes) -> bytes:
    return hmac_sha256(tweak, data)


def kdf_rfc5869_sha256(secret: bytes, salt: bytes, info: bytes, out_len: int) -> bytes:
    prk = hmac_sha256(salt, secret)
    out = b""
    last = b""
    i = 1
    while len(out) < out_len:
        m = last + info + bytes([i])
        last = hmac_sha256(prk, m)
        out += last
        i += 1
    return out[:out_len]


@dataclass
class NtorState:
    router_id: bytes
    pubkey_B: bytes
    seckey_x: bytes
    pubkey_X: bytes


def ntor_create(router_id: bytes, router_key: bytes) -> Tuple[NtorState, bytes]:
    priv = X25519PrivateKey.generate()
    pubkey_X = priv.public_key().public_bytes_raw()
    seckey_x = priv.private_bytes_raw()
    state = NtorState(router_id=router_id, pubkey_B=router_key,
                      seckey_x=seckey_x, pubkey_X=pubkey_X)
    skin = router_id + router_key + pubkey_X
    return state, skin


def ntor_client_handshake(state: NtorState, reply: bytes,
                          key_out_len: int = CPATH_KEY_MATERIAL_LEN) -> Optional[bytes]:
    if len(reply) != NTOR_REPLY_LEN:
        return None
    pubkey_Y = reply[:32]
    auth_rcvd = reply[32:]

    priv = X25519PrivateKey.from_private_bytes(state.seckey_x)
    peer_Y = X25519PublicKey.from_public_bytes(pubkey_Y)
    peer_B = X25519PublicKey.from_public_bytes(state.pubkey_B)
    exp_Yx = priv.exchange(peer_Y)
    exp_Bx = priv.exchange(peer_B)
    if exp_Yx == b"\x00" * 32 or exp_Bx == b"\x00" * 32:
        return None

    secret_input = (exp_Yx + exp_Bx + state.router_id +
                    state.pubkey_B + state.pubkey_X + pubkey_Y + NTOR_PROTOID)

    verify = h_tweak(NTOR_PROTOID + b":verify", secret_input)
    auth_input = (verify + state.router_id + state.pubkey_B + pubkey_Y +
                  state.pubkey_X + NTOR_PROTOID + SERVER_STR)
    auth_calc = h_tweak(NTOR_PROTOID + b":mac", auth_input)
    if auth_calc != auth_rcvd:
        return None

    return kdf_rfc5869_sha256(
        secret_input,
        NTOR_PROTOID + b":key_extract",
        NTOR_PROTOID + b":key_expand",
        key_out_len,
    )


class RelayCrypto:

    def __init__(self, key_data: bytes):
        assert len(key_data) == CPATH_KEY_MATERIAL_LEN
        self.f_digest = hashlib.sha1(key_data[:20])
        self.b_digest = hashlib.sha1(key_data[20:40])
        f_key = key_data[40:56]
        b_key = key_data[56:72]
        self._f_cipher = Cipher(algorithms.AES(f_key), modes.CTR(b"\x00" * 16),
                                backend=default_backend())
        self._b_cipher = Cipher(algorithms.AES(b_key), modes.CTR(b"\x00" * 16),
                                backend=default_backend())
        self._f_enc = self._f_cipher.encryptor()
        self._b_enc = self._b_cipher.encryptor()

    def encrypt_forward(self, data: bytes) -> bytes:
        return self._f_enc.update(data)

    def decrypt_backward(self, data: bytes) -> bytes:
        return self._b_enc.update(data)

    def set_forward_digest(self, payload: bytes) -> bytes:
        self.f_digest.update(payload)
        return self.f_digest.digest()[:4]

    def check_backward_digest(self, payload: bytes) -> bool:
        from .cells import RELAY_HEADER_SIZE
        rh = payload[:RELAY_HEADER_SIZE]
        received = rh[5:9]
        test_rh = rh[:5] + b"\x00\x00\x00\x00" + rh[9:]
        test_payload = test_rh + payload[RELAY_HEADER_SIZE:]
        saved = self.b_digest.copy()
        self.b_digest.update(test_payload)
        computed = self.b_digest.digest()[:4]
        if computed == received:
            return True
        self.b_digest = saved
        return False
