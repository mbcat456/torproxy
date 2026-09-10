import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from torproxy.consensus import load_relays
from torproxy.pool import DirectPool


async def main(count: int) -> int:
    relays = load_relays(
        "shared_cache/cached-microdesc-consensus",
        "shared_cache/cached-microdescs",
    )
    pool = DirectPool(relays, count)
    await pool.build_all()
    stats = pool.get_stats()
    print(stats)
    await pool.close_all()
    return 0 if stats["total"] == stats["unique_ips"] == count else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 8)))
