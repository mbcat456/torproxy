import argparse
import asyncio
import json
import os
import time

import requests


def request_ip(
    proxy: str, sticky_id: str | None = None, tls: bool = False
) -> tuple[str, int, float]:
    target = (
        "https://api.ipify.org?format=json" if tls else "http://checkip.amazonaws.com/"
    )
    proxies = {"http": proxy, "https": proxy}
    headers = {"X-Session-Id": sticky_id} if sticky_id else {}
    started = time.monotonic()
    response = requests.get(target, proxies=proxies, headers=headers, timeout=60)
    elapsed = time.monotonic() - started
    text = response.text.strip()
    if tls:
        data = response.json()
        ip = str(data.get("ip", "")).strip()
    else:
        ip = text
    return ip, response.status_code, elapsed


def download_once(proxy: str, size: int) -> tuple[int, int, float]:
    url = f"https://speed.cloudflare.com/__down?bytes={size}"
    started = time.monotonic()
    response = requests.get(
        url,
        proxies={"http": proxy, "https": proxy},
        stream=True,
        timeout=90,
    )
    total = 0
    for chunk in response.iter_content(chunk_size=65536):
        total += len(chunk)
    return total, response.status_code, time.monotonic() - started


async def one_round(proxy: str, sticky_id: str) -> dict:
    record: dict = {"ts": time.time()}
    try:
        (
            record["http_ip"],
            record["http_status"],
            record["http_latency"],
        ) = await asyncio.to_thread(request_ip, proxy, None, False)
    except Exception as exc:
        record["http_error"] = f"{type(exc).__name__}: {exc}"

    try:
        (
            record["https_ip"],
            record["https_status"],
            record["https_latency"],
        ) = await asyncio.to_thread(request_ip, proxy, None, True)
    except Exception as exc:
        record["https_error"] = f"{type(exc).__name__}: {exc}"

    try:
        (
            record["sticky_ip"],
            record["sticky_status"],
            record["sticky_latency"],
        ) = await asyncio.to_thread(request_ip, proxy, sticky_id, False)
    except Exception as exc:
        record["sticky_error"] = f"{type(exc).__name__}: {exc}"
    return record


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", default="http://127.0.0.1:8899")
    parser.add_argument(
        "--duration", type=int, default=1800, help="run duration in seconds"
    )
    parser.add_argument("--interval", type=float, default=15.0)
    parser.add_argument("--download-every", type=int, default=120)
    parser.add_argument("--output", default="shared_cache/stability.jsonl")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    started = time.monotonic()
    sticky_epoch = int(time.time()) // 300
    sticky_id = f"monitor-{sticky_epoch}"
    sticky_first_ip: str | None = None
    rounds = 0
    errors = 0
    sticky_mismatches = 0
    downloads = 0
    unique_rotating: set[str] = set()

    with open(args.output, "a", encoding="utf-8") as out:
        while time.monotonic() - started < args.duration:
            rounds += 1
            current_epoch = int(time.time()) // 300
            if current_epoch != sticky_epoch:
                sticky_epoch = current_epoch
                sticky_id = f"monitor-{sticky_epoch}"
                sticky_first_ip = None

            record = await one_round(args.proxy, sticky_id)
            record["round"] = rounds
            record["elapsed"] = round(time.monotonic() - started, 2)
            record["sticky_id"] = sticky_id
            if record.get("sticky_ip"):
                if sticky_first_ip is None:
                    sticky_first_ip = record["sticky_ip"]
                record["sticky_consistent"] = record["sticky_ip"] == sticky_first_ip
                if not record["sticky_consistent"]:
                    sticky_mismatches += 1
            if record.get("http_ip"):
                unique_rotating.add(record["http_ip"])
                record["rotating_unique"] = len(unique_rotating)

            failed = (
                any(key.endswith("_error") for key in record)
                or record.get("http_status") != 200
                or record.get("https_status") != 200
                or record.get("sticky_status") != 200
            )
            errors += int(failed)
            out.write(json.dumps(record) + "\n")
            out.flush()

            if rounds % max(1, args.download_every // int(args.interval)) == 0:
                try:
                    size, status, latency = await asyncio.to_thread(
                        download_once, args.proxy, 1_000_000
                    )
                    download_record = {
                        "ts": time.time(),
                        "type": "download",
                        "round": rounds,
                        "size": size,
                        "status": status,
                        "latency": latency,
                    }
                    downloads += 1
                    if size != 1_000_000 or status != 200:
                        errors += 1
                        download_record["error"] = f"size={size} status={status}"
                    out.write(json.dumps(download_record) + "\n")
                    out.flush()
                except Exception as exc:
                    errors += 1
                    out.write(
                        json.dumps(
                            {
                                "ts": time.time(),
                                "type": "download",
                                "round": rounds,
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        )
                        + "\n"
                    )
                    out.flush()

            await asyncio.sleep(args.interval)

        summary = {
            "type": "summary",
            "duration": args.duration,
            "rounds": rounds,
            "errors": errors,
            "downloads": downloads,
            "rotating_unique_ips": len(unique_rotating),
            "sticky_mismatches": sticky_mismatches,
        }
        out.write(json.dumps(summary) + "\n")
        out.flush()


if __name__ == "__main__":
    asyncio.run(main())
