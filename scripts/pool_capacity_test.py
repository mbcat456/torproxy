import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from torproxy.consensus import load_relays
from torproxy.log import log, setup_logging
from torproxy.pool import DirectPool


async def record_loop(
    pool: DirectPool, path: str, interval: float, started: float
) -> None:
    with open(path, "a", encoding="utf-8") as out:
        first = pool.get_stats()
        first["elapsed"] = round(time.monotonic() - started, 1)
        first["audit"] = pool.audit_reservations()
        out.write(json.dumps(first) + "\n")
        out.flush()
        while not pool._shutting_down:
            await asyncio.sleep(interval)
            stats = pool.get_stats()
            stats["elapsed"] = round(time.monotonic() - started, 1)
            stats["audit"] = pool.audit_reservations()
            out.write(json.dumps(stats) + "\n")
            out.flush()
            log.info(
                "CAPACITY elapsed=%.0fs total=%d alive=%d unique=%d "
                "circuit_unique=%d ids=%d missing=%d dup_ips=%d dup_ids=%d "
                "dead=%d rebuilding=%d",
                stats["elapsed"],
                stats["total"],
                stats["alive"],
                stats["unique_ips"],
                stats["circuit_unique_ips"],
                stats["circuit_unique_ids"],
                stats["missing_exit_info"],
                stats["duplicate_exit_ips"],
                stats["duplicate_exit_ids"],
                stats["dead_entries"],
                stats["rebuilding"],
            )


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--duration", type=int, default=3600)
    parser.add_argument("--output", default="shared_cache/capacity.jsonl")
    parser.add_argument("--interval", type=float, default=60.0)
    args = parser.parse_args()

    setup_logging(debug=False)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    relays = load_relays(
        "shared_cache/cached-microdesc-consensus",
        "shared_cache/cached-microdescs",
    )

    pool = DirectPool(relays, args.count)
    build_started = time.monotonic()
    await pool.build_all()
    build_seconds = round(time.monotonic() - build_started, 1)
    log.info("CAPACITY build complete in %.1fs: %s", build_seconds, pool.get_stats())
    if pool.get_stats()["total"] < args.count:
        log.warning("CAPACITY short build: %s", pool.get_stats())

    started = time.monotonic()
    recorder = asyncio.create_task(
        record_loop(pool, args.output, args.interval, started)
    )
    maintainer = asyncio.create_task(
        pool.maintain(
            "shared_cache/cached-microdesc-consensus",
            "shared_cache/cached-microdescs",
            interval=60,
        )
    )

    try:
        await asyncio.sleep(args.duration)
    finally:
        pool._shutting_down = True
        maintainer.cancel()
        recorder.cancel()
        await asyncio.gather(maintainer, recorder, return_exceptions=True)
        await pool.close_all()

    stats = pool.get_stats()
    stats["build_seconds"] = build_seconds
    stats["duration"] = args.duration
    with open(args.output, "a", encoding="utf-8") as out:
        out.write(json.dumps({"type": "summary", **stats}) + "\n")
    log.info("CAPACITY finished: %s", stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
