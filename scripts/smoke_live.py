import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from torproxy.consensus import load_relays
from torproxy.log import setup_logging
from torproxy.pool import DirectPool


async def main(circuit_count: int = 2) -> int:
    setup_logging(debug=True)
    relays = load_relays(
        "shared_cache/cached-microdesc-consensus",
        "shared_cache/cached-microdescs",
    )
    pool = DirectPool(relays, circuit_count)
    await pool.build_all()
    if not pool.circuits:
        print("no circuits built")
        return 1

    print(pool.get_stats())
    circuit = pool.circuits[0]
    response = await asyncio.wait_for(
        circuit.http_request(
            "checkip.amazonaws.com",
            80,
            b"GET / HTTP/1.1\r\n"
            b"Host: checkip.amazonaws.com\r\n"
            b"Connection: close\r\n\r\n",
        ),
        30,
    )
    print(response[:400])
    await pool.close_all()
    return 0


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    raise SystemExit(asyncio.run(main(count)))
