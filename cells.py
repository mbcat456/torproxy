import struct
from dataclasses import dataclass

CELL_PADDING = 0
CELL_CREATE2 = 10
CELL_CREATED2 = 11
CELL_RELAY = 3
CELL_DESTROY = 4
CELL_VERSIONS = 7
CELL_NETINFO = 8
CELL_RELAY_EARLY = 9
CELL_VPADDING = 128
CELL_CERTS = 129
CELL_AUTH_CHALLENGE = 130

RELAY_COMMAND_BEGIN = 1
RELAY_COMMAND_DATA = 2
RELAY_COMMAND_END = 3
RELAY_COMMAND_CONNECTED = 4
RELAY_COMMAND_SENDME = 5
RELAY_COMMAND_EXTENDED = 7
RELAY_COMMAND_EXTEND2 = 14
RELAY_COMMAND_EXTENDED2 = 15

CELL_PAYLOAD_SIZE = 509
RELAY_HEADER_SIZE = 11
RELAY_PAYLOAD_SIZE = CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE

NTOR_ONIONSKIN_LEN = 84
NTOR_REPLY_LEN = 64
CPATH_KEY_MATERIAL_LEN = 20 * 2 + 16 * 2
ONION_HANDSHAKE_TYPE_NTOR = 0x0002

LS_IPV4 = 0
LS_LEGACY_ID = 2

NTOR_PROTOID = b"ntor-curve25519-sha256-1"
SERVER_STR = b"Server"

MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS = 4

CIRCWINDOW_START = 1000
STREAM_TIMEOUT = 60
STREAM_QUEUE_MAX = 512
STREAM_WINDOW_START = 500
DEFAULT_MAX_CLIENTS = 5000
DEFAULT_MAX_REQUEST_BYTES = 2 * 1024 * 1024


@dataclass
class Cell:
    circ_id: int
    command: int
    payload: bytes
    is_fixed: bool


def pack_var_cell(circ_id: int, command: int, payload: bytes, wide: bool) -> bytes:
    if wide:
        return struct.pack("!IBH", circ_id, command, len(payload)) + payload
    else:
        return struct.pack("!HBH", circ_id & 0xFFFF, command, len(payload)) + payload


def pack_fixed_cell(circ_id: int, command: int, payload: bytes, wide: bool) -> bytes:
    pad = payload + b"\x00" * (CELL_PAYLOAD_SIZE - len(payload))
    if wide:
        return struct.pack("!IB", circ_id, command) + pad
    else:
        return struct.pack("!HB", circ_id & 0xFFFF, command) + pad


def build_relay_payload(relay_cmd: int, stream_id: int, data: bytes,
                        digest_bytes: bytes = b"\x00\x00\x00\x00") -> bytes:
    length = min(len(data), RELAY_PAYLOAD_SIZE)
    header = struct.pack("!BHH4sH", relay_cmd, 0, stream_id, digest_bytes, length)
    payload = header + data[:RELAY_PAYLOAD_SIZE]
    pad_len = CELL_PAYLOAD_SIZE - len(payload)
    if pad_len > 0:
        payload += b"\x00" * pad_len
    return payload


def is_variable_length_cell(command: int, link_proto: int) -> bool:
    if link_proto <= 2:
        return command == CELL_VERSIONS
    return command == CELL_VERSIONS or command >= 128


def get_circ_id_size(link_proto: int) -> int:
    return 4 if link_proto >= MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS else 2
