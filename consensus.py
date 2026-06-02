import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from .log import log


@dataclass
class RelayInfo:
    nickname: str = ""
    identity: bytes = b"\x00" * 20
    ip: str = ""
    orport: int = 0
    dirport: int = 0
    flags: Set[str] = field(default_factory=set)
    microdesc_hash: str = ""
    ntor_onion_key: Optional[bytes] = None

    def is_exit(self) -> bool:
        return "Exit" in self.flags and "BadExit" not in self.flags

    def is_guard(self) -> bool:
        return "Guard" in self.flags

    def is_running(self) -> bool:
        return "Running" in self.flags

    def is_valid(self) -> bool:
        return "Valid" in self.flags

    def has_ntor_key(self) -> bool:
        return self.ntor_onion_key is not None and len(self.ntor_onion_key) == 32


def parse_consensus(path: str) -> List[RelayInfo]:
    relays: List[RelayInfo] = []
    current: Optional[RelayInfo] = None

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n\r")
            if not line:
                continue
            if line.startswith("r "):
                if current is not None and current.microdesc_hash:
                    relays.append(current)
                current = RelayInfo()
                parts = line.split()
                if len(parts) >= 8:
                    current.nickname = parts[1]
                    try:
                        ident = parts[2] + "=" * (-len(parts[2]) % 4)
                        current.identity = base64.b64decode(ident)
                    except Exception:
                        current.identity = b"\x00" * 20
                    current.ip = parts[5]
                    current.orport = int(parts[6])
                    current.dirport = int(parts[7]) if len(parts) > 7 else 0
            elif line.startswith("m ") and current is not None:
                current.microdesc_hash = line[2:].strip()
            elif line.startswith("s ") and current is not None:
                current.flags = set(line[2:].strip().split())

    if current is not None and current.microdesc_hash:
        relays.append(current)

    log.info("Parsed %d relays from consensus", len(relays))
    return relays


def parse_microdescs(path: str) -> Dict[str, bytes]:
    with open(path, "rb") as f:
        raw = f.read()

    parts = raw.split(b"@last-listed ")
    result: Dict[str, bytes] = {}

    for entry in parts[1:]:
        nl = entry.find(b"\n")
        if nl < 0:
            continue
        body = entry[nl + 1:]
        h = hashlib.sha256(body).digest()
        hash_b64 = base64.b64encode(h).decode().rstrip("=")

        for line in body.split(b"\n"):
            if line.startswith(b"ntor-onion-key "):
                key_b64 = line.split(b" ", 1)[1].strip().decode()
                try:
                    key_bytes = base64.b64decode(
                        key_b64 + "=" * (-len(key_b64) % 4)
                    )
                    if len(key_bytes) == 32:
                        result[hash_b64] = key_bytes
                except Exception:
                    pass
                break

    log.info("Parsed %d ntor onion keys from microdescs", len(result))
    return result


def load_relays(consensus_path: str, microdescs_path: str) -> List[RelayInfo]:
    relays = parse_consensus(consensus_path)
    key_map = parse_microdescs(microdescs_path)

    matched = 0
    for r in relays:
        if r.microdesc_hash:
            h = r.microdesc_hash.rstrip("=")
            if h in key_map:
                r.ntor_onion_key = key_map[h]
                matched += 1

    usable = [r for r in relays if r.has_ntor_key()]
    n_exits = sum(1 for r in usable if r.is_exit())
    n_guards = sum(1 for r in usable if r.is_guard())
    log.info("Hash-matched %d/%d relays with ntor keys", matched, len(relays))
    log.info("Total usable: %d (exits: %d, guards: %d)", len(usable), n_exits, n_guards)
    return usable


def _check_consensus_fresh(path: str) -> bool:
    try:
        with open(path, "r") as f:
            for line in f:
                if line.startswith("valid-until "):
                    ts_str = line.split(" ", 1)[1].strip()
                    valid_until = datetime.strptime(
                        ts_str, "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    return now < valid_until
    except Exception:
        pass
    return False


def _get_dir_mirrors(path: str) -> List[Tuple[str, int]]:
    mirrors = []
    try:
        with open(path, "r") as f:
            for line in f:
                if line.startswith("dir-source "):
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[3]
                        try:
                            dport = int(parts[5])
                            mirrors.append((ip, dport))
                        except ValueError:
                            pass
    except Exception:
        pass
    return mirrors


def fetch_fresh_consensus(cache_consensus: str, cache_microdescs: str,
                          progress_callback=None) -> bool:
    import urllib.request

    def _progress(msg: str) -> None:
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    mirrors = _get_dir_mirrors(cache_consensus)
    if not mirrors:
        mirrors = [
            ("128.31.0.39", 9231), ("171.25.193.9", 443), ("193.23.244.244", 80),
            ("199.58.81.140", 80), ("204.13.164.118", 80), ("131.188.40.189", 80),
            ("217.196.147.77", 80), ("45.66.35.11", 80),
        ]

    UA = "tor-proxy/1.0"

    consensus_data = None
    working_ip = None
    working_port = None
    for ip, port in mirrors:
        url = f"http://{ip}:{port}/tor/status-vote/current/consensus-microdesc"
        try:
            _progress(f"connecting to {ip}:{port}")
            log.info("Fetching consensus: %s:%d", ip, port)
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            resp = urllib.request.urlopen(req, timeout=30)
            _progress(f"downloading consensus from {ip}...")
            consensus_data = resp.read()
            working_ip, working_port = ip, port
            log.info("Downloaded consensus (%d KB)", len(consensus_data) // 1024)
            _progress(f"consensus: {len(consensus_data) // 1024} KB")
            break
        except Exception as e:
            log.debug("Mirror %s:%d failed: %s", ip, port, e)
            _progress(f"mirror {ip} failed, trying next...")

    if not consensus_data:
        log.error("Failed to download consensus")
        _progress("failed: no mirrors reachable")
        return False

    os.makedirs(os.path.dirname(cache_consensus), exist_ok=True)
    with open(cache_consensus, "wb") as f:
        f.write(consensus_data)

    md_hashes = []
    for line in consensus_data.decode("utf-8", errors="replace").split("\n"):
        if line.startswith("m "):
            h = line[2:].strip()
            h_nopad = h.rstrip("=")
            if h_nopad:
                md_hashes.append(h_nopad)

    if not md_hashes:
        log.error("No microdescriptor hashes found in consensus")
        _progress("failed: no microdesc hashes in consensus")
        return False

    log.info("Found %d microdescriptor hashes to download", len(md_hashes))
    _progress(f"{len(md_hashes)} microdesc hashes to fetch")

    BATCH_SIZE = 90
    batches = [md_hashes[i:i + BATCH_SIZE]
               for i in range(0, len(md_hashes), BATCH_SIZE)]

    output_lines: List[bytes] = []
    fake_date = b"1970-01-01 00:00:00"

    for batch_idx, batch in enumerate(batches):
        hash_list = "-".join(batch)
        url = f"http://{working_ip}:{working_port}/tor/micro/d/{hash_list}"

        data = None
        for attempt in range(3):
            try:
                _progress(f"microdesc batch {batch_idx + 1}/{len(batches)}")
                log.info("Microdescs batch %d/%d: %d hashes",
                         batch_idx + 1, len(batches), len(batch))
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                resp = urllib.request.urlopen(req, timeout=60)
                data = resp.read()
                break
            except Exception as e:
                log.debug("Batch %d attempt %d failed: %s",
                          batch_idx + 1, attempt + 1, e)
                time.sleep(2)

        if data is None:
            log.warning("Batch %d/%d failed after 3 attempts",
                        batch_idx + 1, len(batches))
            continue

        parts = data.split(b"\nonion-key\n")
        if not parts:
            continue

        for part in parts:
            if not part.strip():
                continue
            body = b"onion-key\n" + part if not part.startswith(b"onion-key") else part
            body = body.rstrip(b"\n") + b"\n"
            output_lines.append(b"@last-listed " + fake_date + b"\n")
            output_lines.append(body)

    if not output_lines:
        log.error("Could not download any microdescriptors")
        _progress("failed: no microdescriptors downloaded")
        return False

    md_data = b"".join(output_lines)
    os.makedirs(os.path.dirname(cache_microdescs), exist_ok=True)
    with open(cache_microdescs, "wb") as f:
        f.write(md_data)

    entries = sum(1 for x in output_lines if x.startswith(b"@last-listed"))
    log.info("Saved %d KB microdescriptors (%d entries, %d batches)",
             len(md_data) // 1024, entries, len(batches))
    _progress(f"saved {len(md_data) // 1024} KB microdescriptors")
    return True


def load_relays_auto(consensus_path: str, microdescs_path: str) -> List[RelayInfo]:
    old_relays = []
    if os.path.exists(consensus_path) and os.path.exists(microdescs_path):
        old_relays = load_relays(consensus_path, microdescs_path)

    if not _check_consensus_fresh(consensus_path):
        log.info("Consensus is stale -- using cached, will refresh later")

    return old_relays
