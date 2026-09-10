import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from torproxy.consensus import load_relays
from torproxy.log import setup_logging
from torproxy.pool import DirectPool


async def main() -> int:
    setup_logging(debug=False)
    relays = load_relays(
        "shared_cache/cached-microdesc-consensus",
        "shared_cache/cached-microdescs",
    )
    pool = DirectPool(relays, 1)
    await pool.build_all()
    if not pool.circuits:
        print("no circuits built")
        return 1

    circuit = pool.circuits[0]
    request = (
        b"GET /__down?bytes=2000000 HTTP/1.1\r\n"
        b"Host: speed.cloudflare.com\r\n"
        b"Connection: close\r\n\r\n"
    )
    total = 0
    async for chunk in circuit.stream_request(
        "speed.cloudflare.com", 443, request, use_tls=True
    ):
        total += len(chunk)
        if total > 4 * 1024 * 1024:
            break

    print("received", total, "bytes")
    await pool.close_all()
    return 0 if total >= 2_000_000 else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
