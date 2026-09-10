import asyncio
import ipaddress
import random
import time

from .cells import (
    CIRCUIT_ID_FIRST_NARROW,
    CIRCUIT_ID_FIRST_WIDE,
    CIRCUIT_ID_MASK_NARROW,
    CIRCUIT_ID_MASK_WIDE,
)
from .circuit import TorCircuit
from .connection import TorConnection, tor_link_handshake
from .consensus import (
    RelayInfo,
    _check_consensus_fresh,
    fetch_fresh_consensus,
    load_relays,
)
from .log import log

DEAD_ENTRY_BACKOFF_SECONDS = 300.0
HEALTHY_STATUS_CODES = frozenset(
    {
        b"200",
        b"201",
        b"202",
        b"203",
        b"204",
        b"206",
        b"301",
        b"302",
        b"304",
        b"307",
        b"308",
    }
)
MIN_HEALTHY_RESPONSE_BYTES = 50
CHECKIP_HOST = "checkip.amazonaws.com"
CHECKIP_REQUEST = (
    b"GET / HTTP/1.1\r\nHost: checkip.amazonaws.com\r\nConnection: close\r\n\r\n"
)
ICANHAZIP_HOST = "icanhazip.com"
ICANHAZIP_REQUEST = (
    b"GET / HTTP/1.1\r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n"
)
IPIFY_HOST = "api.ipify.org"
IPIFY_REQUEST = b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n"
IFCONFIG_HOST = "ifconfig.me"
IFCONFIG_REQUEST = b"GET /ip HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n"
TRACE_HOST = "1.1.1.1"
TRACE_REQUEST = (
    b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n"
)
EXIT_HTTP_PROBES = (
    (CHECKIP_HOST, 80, CHECKIP_REQUEST),
    (ICANHAZIP_HOST, 80, ICANHAZIP_REQUEST),
    (IPIFY_HOST, 80, IPIFY_REQUEST),
    (IFCONFIG_HOST, 80, IFCONFIG_REQUEST),
    (TRACE_HOST, 80, TRACE_REQUEST),
)
EXIT_HTTPS_PROBES = (
    (IPIFY_HOST, 443, IPIFY_REQUEST),
    (ICANHAZIP_HOST, 443, ICANHAZIP_REQUEST),
    (TRACE_HOST, 443, TRACE_REQUEST),
)
EXIT_PROBE_TIMEOUT_SECONDS = 6.0


class ExitIpRegistry:
    def __init__(self) -> None:
        self._owners: dict[str, set[object]] = {}

    def claim(
        self,
        exit_ip: str,
        owner: object,
        previous_exit_ip: str | None = None,
        previous_owner: object | None = None,
    ) -> bool:
        if previous_exit_ip is not None and previous_owner is not None:
            self.release(previous_exit_ip, previous_owner)
        owners = self._owners.setdefault(exit_ip, set())
        owners.add(owner)
        return len(owners) == 1

    def release(self, exit_ip: str, owner: object) -> None:
        owners = self._owners.get(exit_ip)
        if owners is None:
            return
        owners.discard(owner)
        if not owners:
            del self._owners[exit_ip]

    def owners_for(self, exit_ip: str) -> set[object]:
        return set(self._owners.get(exit_ip, set()))

    def __len__(self) -> int:
        return len(self._owners)


def initial_circuit_id(wide: bool) -> int:
    return CIRCUIT_ID_FIRST_WIDE if wide else CIRCUIT_ID_FIRST_NARROW


def advance_circuit_id(current: int, wide: bool) -> int:
    if wide:
        return ((current + 1) & CIRCUIT_ID_MASK_WIDE) or CIRCUIT_ID_FIRST_WIDE
    return ((current + 1) & CIRCUIT_ID_MASK_NARROW) or CIRCUIT_ID_FIRST_NARROW


def is_live_circuit(circuit: TorCircuit) -> bool:
    if getattr(circuit, "_circuit_failed", False):
        return False
    if getattr(circuit, "_502_count", 0) >= 2:
        return False
    connection = getattr(circuit, "conn", None)
    writer = getattr(connection, "writer", None)
    return writer is not None and not writer.is_closing()


def is_healthy_response(response: bytes) -> bool:
    status_line = response.split(b"\r\n", 1)[0] if response else b""
    return (
        status_line.startswith(b"HTTP/")
        and len(status_line) >= 12
        and status_line[9:12] in HEALTHY_STATUS_CODES
        and len(response) > MIN_HEALTHY_RESPONSE_BYTES
    )


async def probe_exit_ip(
    circuit: TorCircuit, timeout: float = EXIT_PROBE_TIMEOUT_SECONDS
) -> str | None:
    for host, port, request in EXIT_HTTP_PROBES:
        try:
            response = await asyncio.wait_for(
                circuit.http_request(host, port, request),
                timeout=timeout,
            )
        except Exception:
            continue
        observed_ip = parse_exit_ip(response)
        if observed_ip is None:
            observed_ip = parse_trace_ip(response)
        if observed_ip is not None:
            return observed_ip
    for host, port, request in EXIT_HTTPS_PROBES:
        try:
            response = await asyncio.wait_for(
                collect_https_response(circuit, host, port, request),
                timeout=timeout,
            )
        except Exception:
            continue
        observed_ip = parse_exit_ip(response)
        if observed_ip is None:
            observed_ip = parse_trace_ip(response)
        if observed_ip is not None:
            return observed_ip
    return None


def parse_exit_ip(response: bytes) -> str | None:
    if not is_healthy_response(response):
        return None
    body = response.split(b"\r\n\r\n", 1)[-1].strip()
    try:
        return ipaddress.ip_address(body.decode("ascii")).compressed
    except (UnicodeDecodeError, ValueError):
        return None


def parse_trace_ip(response: bytes) -> str | None:
    if not is_healthy_response(response):
        return None
    body = response.split(b"\r\n\r\n", 1)[-1].decode("ascii", errors="replace")
    for line in body.splitlines():
        if not line.startswith("ip="):
            continue
        try:
            return ipaddress.ip_address(line[3:].strip()).compressed
        except ValueError:
            return None
    return None


async def collect_https_response(
    circuit: TorCircuit,
    host: str,
    port: int,
    request: bytes,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in circuit.stream_request(host, port, request, use_tls=True):
        chunks.append(chunk)
        total += len(chunk)
        if total > 4096:
            break
    return b"".join(chunks)


def select_least_loaded(circuits: list[TorCircuit]) -> TorCircuit:
    alive = [circuit for circuit in circuits if is_live_circuit(circuit)]
    if not alive:
        raise RuntimeError("No live circuits available")
    sample = random.sample(alive, min(len(alive), 32))
    return min(sample, key=lambda circuit: getattr(circuit, "_active_streams", 0))


async def _open_connection(
    relay: RelayInfo, connect_timeout: float = 8.0, handshake_timeout: float = 5.0
) -> TorConnection:
    connection = TorConnection(relay.ip, relay.orport)
    try:
        await asyncio.wait_for(connection.connect(), timeout=connect_timeout)
        await asyncio.wait_for(
            tor_link_handshake(connection), timeout=handshake_timeout
        )
        return connection
    except Exception:
        try:
            await asyncio.wait_for(connection.close(), timeout=5)
        except Exception:
            pass
        raise


async def _close_connection(connection: TorConnection | None) -> None:
    if connection is None:
        return
    try:
        await asyncio.wait_for(connection.close(), timeout=5)
    except Exception:
        pass


class CircuitPool:
    def __init__(
        self,
        conn: TorConnection,
        guard: RelayInfo,
        middles: list[RelayInfo],
        exits: list[RelayInfo],
        num_circuits: int = 10,
        all_relays: list[RelayInfo] | None = None,
    ):
        self.conn = conn
        self.guard = guard
        self.middles = middles
        self.exits = exits
        self.all = all_relays if all_relays is not None else middles + exits + [guard]
        self.num_circuits = num_circuits
        self.circuits: list[TorCircuit] = []
        self._idx = 0
        self._circ_id_next = initial_circuit_id(conn.wide)
        self._lock = asyncio.Lock()
        self._shutting_down = False
        self._observed_exits = ExitIpRegistry()
        self._duplicate_exit_ids: set[bytes] = set()

    async def _reserve_circuit_id(self) -> int:
        async with self._lock:
            circ_id = self._circ_id_next
            self._circ_id_next = advance_circuit_id(circ_id, self.conn.wide)
        return circ_id

    async def build_all(self) -> None:
        used_ips: set[str] = set()
        used_ids: set[bytes] = set()
        attempts = 0
        max_attempts = self.num_circuits * 3

        while len(self.circuits) < self.num_circuits and attempts < max_attempts:
            if not self.middles or not self.exits:
                break
            attempts += 1
            exits = [
                relay
                for relay in self.exits
                if relay.identity not in self._duplicate_exit_ids
                and relay.identity != self.guard.identity
                and relay.ip not in used_ips
                and relay.identity not in used_ids
            ]
            if not exits:
                exits = [
                    relay
                    for relay in self.exits
                    if relay.identity != self.guard.identity
                    and relay.ip not in used_ips
                    and relay.identity not in used_ids
                ]
            if not exits:
                break
            ex = random.choice(exits)
            middles = [
                relay
                for relay in self.middles
                if relay.identity not in (self.guard.identity, ex.identity)
            ]
            middle = random.choice(middles or self.middles)

            try:
                circ = await self._build_one(self.guard, middle, ex)
                self.circuits.append(circ)
                used_ips.add(ex.ip)
                used_ids.add(ex.identity)
                log.info(
                    "Circuit %d/%d built via %s (%s)",
                    len(self.circuits),
                    self.num_circuits,
                    ex.nickname,
                    ex.ip,
                )
            except Exception as exc:
                log.warning("Circuit build attempt %d failed: %s", attempts, exc)

        stats = self.get_stats()
        log.info(
            "Built %d/%d circuits (%d unique observed exit IPs, %d duplicate, %d unverified)",
            len(self.circuits),
            self.num_circuits,
            stats["unique_ips"],
            stats["duplicate_observed_ips"],
            stats["unverified_exits"],
        )
        if not self.circuits:
            raise RuntimeError("Failed to build any circuits")

    async def _build_one(
        self, guard: RelayInfo, middle: RelayInfo, ex: RelayInfo
    ) -> TorCircuit:
        cid = await self._reserve_circuit_id()
        queue = self.conn.register_circuit(cid)
        circ = TorCircuit(self.conn, cid, cell_queue=queue)
        try:
            await asyncio.wait_for(circ.build(guard, middle, ex), timeout=25)
            observed_ip = await probe_exit_ip(circ)
            if observed_ip is None:
                circ._exit_verified = False
            else:
                async with self._lock:
                    is_unique = self._observed_exits.claim(observed_ip, circ)
                    circ._exit_ip = observed_ip
                    circ._exit_verified = True
                    circ._exit_duplicate = not is_unique
                if not is_unique:
                    self._duplicate_exit_ids.add(ex.identity)
                    log.debug(
                        "Duplicate observed exit IP %s from %s",
                        observed_ip,
                        ex.nickname,
                    )
            return circ
        except (Exception, asyncio.CancelledError):
            await circ.close()
            raise

    def get_circuit(self) -> TorCircuit:
        if not self.circuits:
            raise RuntimeError("No circuits available")
        return select_least_loaded(self.circuits)

    def note_502(self, circ: TorCircuit) -> None:
        pass

    def get_stats(self) -> dict:
        alive = sum(
            1
            for c in self.circuits
            if c.conn and c.conn.writer and not c.conn.writer.is_closing()
        )
        observed_ips = [
            c._exit_ip for c in self.circuits if getattr(c, "_exit_ip", None)
        ]
        return {
            "total": len(self.circuits),
            "alive": alive,
            "unique_ips": len(set(observed_ips)),
            "observed_ips": len(observed_ips),
            "unverified_exits": len(self.circuits) - len(observed_ips),
            "duplicate_observed_ips": len(observed_ips) - len(set(observed_ips)),
            "duplicate_exit_relays": len(self._duplicate_exit_ids),
            "guard": self.guard.nickname,
        }

    async def close_all(self) -> None:
        self._shutting_down = True
        for c in self.circuits:
            try:
                await asyncio.wait_for(c.close(), timeout=5)
            except (asyncio.TimeoutError, Exception):
                pass
        if self.conn is not None:
            await self.conn.close()

    def _pick_exit(self) -> RelayInfo | None:
        used_ips = {c.exit_info.ip for c in self.circuits if c.exit_info}
        used_ids = {c.exit_info.identity for c in self.circuits if c.exit_info}
        fresh = [
            r
            for r in self.exits
            if r.identity not in self._duplicate_exit_ids
            and r.identity != self.guard.identity
            and r.ip not in used_ips
            and r.identity not in used_ids
        ]
        if fresh:
            return random.choice(fresh)
        fallback = [
            r
            for r in self.exits
            if r.identity != self.guard.identity and r.identity not in used_ids
        ]
        return random.choice(fallback) if fallback else None

    def _pick_middle(self, ex: RelayInfo) -> RelayInfo | None:
        candidates = [
            r
            for r in self.middles
            if r.identity not in (self.guard.identity, ex.identity) and not r.is_exit()
        ]
        return random.choice(candidates or self.middles) if self.middles else None

    async def _check_circuit(self, circ: TorCircuit) -> bool:
        if getattr(circ, "_circuit_failed", False):
            return False
        try:
            circ._ensure_dispatch()
        except Exception:
            return False
        if (
            circ.conn is None
            or circ.conn.writer is None
            or circ.conn.writer.is_closing()
        ):
            return False
        observed_ip = await probe_exit_ip(circ, timeout=10.0)
        if observed_ip is None:
            return False
        identity = circ.exit_info.identity if circ.exit_info else b""
        previous_exit_ip = getattr(circ, "_exit_ip", None)
        async with self._lock:
            is_unique = self._observed_exits.claim(
                observed_ip,
                circ,
                previous_exit_ip=previous_exit_ip,
                previous_owner=circ,
            )
        circ._exit_ip = observed_ip
        circ._exit_verified = True
        circ._exit_duplicate = not is_unique
        if not is_unique and identity not in self._duplicate_exit_ids:
            self._duplicate_exit_ids.add(identity)
        return True

    async def _replace_circuit(self, index: int, old_circ: TorCircuit) -> bool:
        ex = self._pick_exit()
        old_exit = old_circ.exit_info
        if ex is None and old_exit is not None and old_exit.has_ntor_key():
            ex = old_exit
        middle = self._pick_middle(ex) if ex else None
        if ex is None or middle is None:
            return False
        cid = await self._reserve_circuit_id()
        queue = self.conn.register_circuit(cid)
        circ = TorCircuit(self.conn, cid, cell_queue=queue)
        try:
            await asyncio.wait_for(circ.build(self.guard, middle, ex), timeout=25)
        except (Exception, asyncio.CancelledError) as exc:
            await circ.close()
            if isinstance(exc, asyncio.CancelledError):
                raise
            return False
        observed_ip = await probe_exit_ip(circ)
        if observed_ip is None:
            circ._exit_verified = False
        old_exit_ip = getattr(old_circ, "_exit_ip", None)
        async with self._lock:
            if observed_ip is None:
                if old_exit_ip is not None:
                    self._observed_exits.release(old_exit_ip, old_circ)
            else:
                claimed = self._observed_exits.claim(
                    observed_ip,
                    circ,
                    previous_exit_ip=old_exit_ip,
                    previous_owner=old_circ,
                )
                circ._exit_ip = observed_ip
                circ._exit_verified = True
                circ._exit_duplicate = not claimed
                if not claimed:
                    self._duplicate_exit_ids.add(ex.identity)
        self.circuits[index] = circ
        asyncio.create_task(self._delayed_close(old_circ))
        return True

    async def _delayed_close(self, circ: TorCircuit) -> None:
        await asyncio.sleep(10)
        await circ.close()

    async def _reconnect(self) -> bool:
        guards = [r for r in self.all if r.can_guard()]
        if not guards:
            guards = [r for r in self.all if r.is_usable()]
        random.shuffle(guards)
        for guard in guards[:10]:
            if guard.identity == self.guard.identity and len(guards) > 1:
                continue
            conn: TorConnection | None = None
            try:
                conn = await _open_connection(guard)
                conn.start_cell_router()
            except (Exception, asyncio.CancelledError) as exc:
                await _close_connection(conn)
                if isinstance(exc, asyncio.CancelledError):
                    raise
                continue

            old_conn = self.conn
            old_guard = self.guard
            old_circuits = list(self.circuits)
            self.conn = conn
            self.guard = guard
            self.circuits = []
            self._circ_id_next = initial_circuit_id(conn.wide)
            try:
                await self.build_all()
            except (Exception, asyncio.CancelledError) as exc:
                self.conn = old_conn
                self.guard = old_guard
                self.circuits = old_circuits
                self._circ_id_next = initial_circuit_id(
                    old_conn is not None and old_conn.wide
                )
                await _close_connection(conn)
                if isinstance(exc, asyncio.CancelledError):
                    raise
                return False
            if self.circuits:
                for circuit in old_circuits:
                    asyncio.create_task(self._delayed_close(circuit))
                if old_conn is not None:
                    asyncio.create_task(self._delayed_conn_close(old_conn))
                return True
            self.conn = old_conn
            self.circuits = old_circuits
            await _close_connection(conn)
        return False

    async def _delayed_conn_close(self, conn: TorConnection) -> None:
        await asyncio.sleep(10)
        await _close_connection(conn)

    async def maintain(
        self, consensus_path: str, microdescs_path: str, interval: int = 60
    ) -> None:
        last_refresh = -600.0
        while not self._shutting_down:
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            if self._shutting_down:
                break
            if time.monotonic() - last_refresh > 600:
                try:
                    if not _check_consensus_fresh(consensus_path):
                        log.info("Single-guard consensus stale, refreshing...")
                        await asyncio.to_thread(
                            fetch_fresh_consensus, consensus_path, microdescs_path
                        )
                    new_relays = load_relays(consensus_path, microdescs_path)
                    if new_relays and len(new_relays) >= len(self.all) // 2:
                        self.all = new_relays
                        self.guard = next(
                            (
                                r
                                for r in new_relays
                                if r.identity == self.guard.identity
                            ),
                            self.guard,
                        )
                        guard_ids = {r.identity for r in new_relays if r.is_guard()}
                        exit_ids = {r.identity for r in new_relays if r.is_exit()}
                        self.middles = [
                            r
                            for r in new_relays
                            if r.is_usable()
                            and r.identity not in guard_ids
                            and r.identity not in exit_ids
                        ]
                        self.exits = [r for r in new_relays if r.can_exit()]
                        last_refresh = time.monotonic()
                except Exception as exc:
                    log.warning("Single-guard consensus refresh failed: %s", exc)

            if (
                self.conn is None
                or self.conn.writer is None
                or self.conn.writer.is_closing()
            ):
                if await self._reconnect():
                    log.info(
                        "Single-guard pool reconnected via %s", self.guard.nickname
                    )
                continue

            indices = list(range(len(self.circuits)))
            random.shuffle(indices)
            sample_size = min(len(indices), max(10, len(indices) // 5))
            for index in indices[:sample_size]:
                circuit = self.circuits[index]
                if not await self._check_circuit(circuit):
                    if await self._replace_circuit(index, circuit):
                        log.info("Replaced dead single-guard circuit %d", index)


class DirectPool:
    def __init__(self, relays: list[RelayInfo], num_circuits: int = 10):
        self.all = relays
        self.num_circuits = num_circuits
        self.circuits: list[TorCircuit] = []
        self.connections: list[TorConnection] = []
        self._idx = 0
        self._used_ips: set[str] = set()
        self._used_ids: set[bytes] = set()
        self._dead_until: dict[bytes, float] = {}
        self._rebuilding: set[int] = set()
        self._shutting_down: bool = False
        self._lock = asyncio.Lock()
        self._observed_exits = ExitIpRegistry()
        self._duplicate_exit_ids: set[bytes] = set()

    def _entry_dead(self, ident: bytes) -> bool:
        until = self._dead_until.get(ident)
        if until is None:
            return False
        if time.monotonic() < until:
            return True
        del self._dead_until[ident]
        return False

    def _mark_entry_dead(
        self, ident: bytes, duration: float = DEAD_ENTRY_BACKOFF_SECONDS
    ) -> None:
        self._dead_until[ident] = time.monotonic() + duration

    def _mark_build_failed(
        self,
        entry: RelayInfo,
        middle: RelayInfo | None,
        exit_relay: RelayInfo | None,
    ) -> None:
        for relay in (entry, middle, exit_relay):
            if relay is not None:
                self._mark_entry_dead(relay.identity)

    def _reserve_exit_locked(self, exit_relay: RelayInfo) -> bool:
        if exit_relay.ip in self._used_ips or exit_relay.identity in self._used_ids:
            return False
        self._used_ips.add(exit_relay.ip)
        self._used_ids.add(exit_relay.identity)
        return True

    def _release_exit_reservation_locked(self, exit_relay: RelayInfo) -> None:
        self._used_ips.discard(exit_relay.ip)
        self._used_ids.discard(exit_relay.identity)

    def _expire_dead_entries(self) -> int:
        now = time.monotonic()
        expired = [k for k, v in self._dead_until.items() if now >= v]
        for k in expired:
            del self._dead_until[k]
        return len(expired)

    def audit_reservations(self) -> dict:
        assigned_ips = {c.exit_info.ip for c in self.circuits if c.exit_info}
        assigned_ids = {c.exit_info.identity for c in self.circuits if c.exit_info}
        ip_indices: dict = {}
        id_indices: dict = {}
        for index, circuit in enumerate(self.circuits):
            if not circuit.exit_info:
                continue
            ip_indices.setdefault(circuit.exit_info.ip, []).append(index)
            id_indices.setdefault(circuit.exit_info.identity, []).append(index)
        duplicate_ips = {ip: idx for ip, idx in ip_indices.items() if len(idx) > 1}
        duplicate_ids = {iid: idx for iid, idx in id_indices.items() if len(idx) > 1}
        report = {
            "missing_ips": sorted(assigned_ips - self._used_ips),
            "extra_ips": sorted(self._used_ips - assigned_ips),
            "missing_ids": len(assigned_ids - self._used_ids),
            "extra_ids": len(self._used_ids - assigned_ids),
            "duplicate_ips": duplicate_ips,
            "duplicate_ids": {iid.hex(): idx for iid, idx in duplicate_ids.items()},
        }
        if (
            report["missing_ips"]
            or report["extra_ips"]
            or duplicate_ips
            or duplicate_ids
        ):
            log.warning("RESERVATION AUDIT %s", report)
        return report

    def _pick_entry(self, exclude_ip: str | None = None) -> RelayInfo | None:
        candidates = [
            r
            for r in self.all
            if r.can_guard() and not self._entry_dead(r.identity) and r.ip != exclude_ip
        ]
        if not candidates:
            candidates = [
                r
                for r in self.all
                if r.is_usable()
                and not self._entry_dead(r.identity)
                and r.ip != exclude_ip
            ]
        return random.choice(candidates) if candidates else None

    def _pick_exit(self, entry: RelayInfo) -> RelayInfo | None:
        others = [
            r
            for r in self.all
            if r.identity != entry.identity
            and r.is_usable()
            and not self._entry_dead(r.identity)
        ]
        fresh = [
            r
            for r in others
            if r.can_exit()
            and r.identity not in self._duplicate_exit_ids
            and r.ip not in self._used_ips
            and r.identity not in self._used_ids
        ]
        if fresh:
            return random.choice(fresh)
        exits = [r for r in others if r.can_exit()]
        return random.choice(exits) if exits else None

    def _pick_middle(self, entry: RelayInfo, exit_relay: RelayInfo) -> RelayInfo | None:
        candidates = [
            r
            for r in self.all
            if r.identity not in (entry.identity, exit_relay.identity)
            and r.is_usable()
            and not r.is_exit()
            and not self._entry_dead(r.identity)
        ]
        if not candidates:
            candidates = [
                r
                for r in self.all
                if r.identity not in (entry.identity, exit_relay.identity)
                and r.is_usable()
                and not self._entry_dead(r.identity)
            ]
        return random.choice(candidates) if candidates else None

    async def build_seed(self, count: int = 50, deadline: float = 12.0) -> None:
        all_entries = [r for r in self.all if r.can_guard()]
        if not all_entries:
            all_entries = [r for r in self.all if r.is_usable()]
        entries = random.sample(all_entries, min(count, len(all_entries)))
        chosen = entries
        sem = asyncio.Semaphore(50)

        async def _limited(i, ex):
            async with sem:
                try:
                    return await asyncio.wait_for(
                        self._build_one(i, ex), timeout=deadline
                    )
                except asyncio.TimeoutError:
                    return RuntimeError("Seed circuit timed out")

        results = await asyncio.gather(
            *[_limited(i, ex) for i, ex in enumerate(chosen)], return_exceptions=True
        )
        for i, r in enumerate(results):
            if isinstance(r, BaseException):
                log.warning("Seed circuit %d failed: %s", i, r)
        log.info("Seed: %d circuits ready", len(self.circuits))

    async def build_all(self) -> None:
        total = self.num_circuits
        stalled_rounds = 0
        attempts = 0
        max_attempts = total * 4
        while (
            len(self.circuits) < total
            and stalled_rounds < 10
            and attempts < max_attempts
        ):
            needed = total - len(self.circuits)
            batch = min(needed, 200)
            entries = [
                r
                for r in self.all
                if r.can_guard() and not self._entry_dead(r.identity)
            ]
            if not entries:
                entries = [
                    r
                    for r in self.all
                    if r.is_usable() and not self._entry_dead(r.identity)
                ]
            if not entries:
                break
            chosen = random.sample(entries, min(batch, len(entries)))
            attempts += len(chosen)

            semaphore = asyncio.Semaphore(100)

            async def _limited(i, ex, sem):
                async with sem:
                    return await self._build_one(i, ex)

            tasks = [
                _limited(len(self.circuits) + j, ex, semaphore)
                for j, ex in enumerate(chosen)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            built = sum(1 for r in results if not isinstance(r, BaseException))
            failed = sum(1 for r in results if isinstance(r, BaseException))
            observed_ips = {
                getattr(circuit, "_exit_ip", None)
                for circuit in self.circuits
                if getattr(circuit, "_exit_ip", None)
            }
            log.info(
                "Batch: +%d circuits, %d failed (%d/%d total, %d observed exit IPs)",
                built,
                failed,
                len(self.circuits),
                total,
                len(observed_ips),
            )
            if built == 0:
                stalled_rounds += 1
                if stalled_rounds >= 3:
                    self._dead_until.clear()
            else:
                stalled_rounds = 0

        stats = self.get_stats()
        log.info(
            "Built %d/%d pooled circuits (%d unique observed exit IPs, %d duplicate, %d unverified)",
            len(self.circuits),
            self.num_circuits,
            stats["unique_ips"],
            stats["duplicate_observed_ips"],
            stats["unverified_exits"],
        )
        if not self.circuits:
            raise RuntimeError("Failed to build any circuits")

    async def _build_one(self, idx: int, entry: RelayInfo) -> None:
        conn: TorConnection | None = None
        ex: RelayInfo | None = None
        middle: RelayInfo | None = None
        circ: TorCircuit | None = None
        reserved_exit = False
        try:
            conn = await _open_connection(entry, connect_timeout=5)

            ex = self._pick_exit(entry)
            if ex is None:
                raise RuntimeError("No exit relays available")
            middle = self._pick_middle(entry, ex)
            if middle is None:
                raise RuntimeError("No middle relays available")

            async with self._lock:
                if not self._reserve_exit_locked(ex):
                    raise RuntimeError(f"Duplicate exit IP/identity: {ex.ip}")
                reserved_exit = True

            circ = TorCircuit(conn, initial_circuit_id(conn.wide))
            await asyncio.wait_for(circ.build(entry, middle, ex), timeout=25)
            circ._created_at = time.monotonic()

            observed_ip = await probe_exit_ip(circ)
            if observed_ip is None:
                circ._exit_verified = False
            else:
                async with self._lock:
                    is_unique = self._observed_exits.claim(observed_ip, circ)
                    circ._exit_ip = observed_ip
                    circ._exit_verified = True
                    circ._exit_duplicate = not is_unique
                if not is_unique:
                    self._duplicate_exit_ids.add(ex.identity)
                    log.debug(
                        "Duplicate observed exit IP %s from %s",
                        observed_ip,
                        ex.nickname,
                    )

            async with self._lock:
                self.connections.append(conn)
                self.circuits.append(circ)
            log.info(
                "Circuit %d via %s -> %s -> %s (%s)",
                idx,
                entry.nickname,
                middle.nickname,
                ex.nickname,
                observed_ip or "unverified",
            )
        except (Exception, asyncio.CancelledError):
            if ex is not None and reserved_exit:
                async with self._lock:
                    self._release_exit_reservation_locked(ex)
            self._mark_build_failed(entry, middle, ex)
            if circ is not None:
                await circ.close()
            await _close_connection(conn)
            raise

    def get_circuit(self) -> TorCircuit:
        if not self.circuits:
            raise RuntimeError("No circuits available")
        circ = select_least_loaded(self.circuits)
        if not getattr(circ, "_dispatch_running", False):
            circ._ensure_dispatch()
        return circ

    def note_502(self, circ: TorCircuit) -> None:
        count = getattr(circ, "_502_count", 0) + 1
        circ._502_count = count
        if count == 2:

            async def _safe_urgent():
                try:
                    await self._urgent_rebuild(circ)
                except Exception as e:
                    log.debug("_urgent_rebuild failed: %s", e)

            asyncio.create_task(_safe_urgent())

    async def _urgent_rebuild(self, circ: TorCircuit) -> None:
        if self._shutting_down:
            return
        try:
            idx = self.circuits.index(circ)
        except ValueError:
            return
        conn = self.connections[idx]
        if conn is None or conn.writer is None:
            return
        log.info(
            "Urgent rebuild circuit %d (%s)", idx, getattr(circ, "_exit_ip", "unknown")
        )
        if await self._rebuild_circuit(idx, circ, conn):
            circ._502_count = 0
            circ._health_fails = 0

    async def _check_circuit(self, circ: TorCircuit) -> bool:
        if getattr(circ, "_circuit_failed", False):
            return False
        if not getattr(circ, "_dispatch_running", False):
            try:
                circ._ensure_dispatch()
            except Exception:
                return False
        if (
            circ.conn is None
            or circ.conn.writer is None
            or circ.conn.writer.is_closing()
            or not getattr(circ, "_dispatch_running", False)
        ):
            return False

        observed_ip = await probe_exit_ip(circ, timeout=10.0)
        if observed_ip is None:
            circ._health_fails = getattr(circ, "_health_fails", 0) + 1
            return False
        identity = circ.exit_info.identity if circ.exit_info else b""
        previous_exit_ip = getattr(circ, "_exit_ip", None)
        async with self._lock:
            is_unique = self._observed_exits.claim(
                observed_ip,
                circ,
                previous_exit_ip=previous_exit_ip,
                previous_owner=circ,
            )
        circ._exit_ip = observed_ip
        circ._exit_verified = True
        circ._exit_duplicate = not is_unique
        if not is_unique and identity not in self._duplicate_exit_ids:
            self._duplicate_exit_ids.add(identity)
        circ._502_count = 0
        circ._health_fails = 0
        return True

    async def _rebuild_circuit(
        self, idx: int, old_circ: TorCircuit, old_conn: TorConnection
    ) -> bool:
        if self._shutting_down:
            return False
        if idx in self._rebuilding:
            return False
        self._rebuilding.add(idx)
        try:
            return await self._rebuild_circuit_inner(idx, old_circ, old_conn)
        finally:
            self._rebuilding.discard(idx)

    async def _rebuild_circuit_inner(
        self, idx: int, old_circ: TorCircuit, old_conn: TorConnection
    ) -> bool:
        old_entry_ip = old_conn.host if old_conn else None

        entry = self._pick_entry(exclude_ip=old_entry_ip)
        if entry is None:
            log.debug("Rebuild %d: no usable entry relays", idx)
            return False

        old_exit = old_circ.exit_info
        ex = self._pick_exit(entry)
        if ex is None and old_exit is not None and old_exit.has_ntor_key():
            ex = old_exit
        if ex is None:
            log.debug("Rebuild %d: no usable exit relays", idx)
            return False
        middle = self._pick_middle(entry, ex)
        if middle is None:
            log.debug("Rebuild %d: no usable middle relays", idx)
            return False

        async with self._lock:
            if old_exit is None:
                return False
            if ex.identity != old_exit.identity and not self._reserve_exit_locked(ex):
                return False

        conn: TorConnection | None = None
        try:
            conn = await _open_connection(entry)
        except (Exception, asyncio.CancelledError):
            async with self._lock:
                if ex.identity != old_exit.identity:
                    self._release_exit_reservation_locked(ex)
            self._mark_build_failed(entry, middle, ex)
            await _close_connection(conn)
            return False

        try:
            circ = TorCircuit(conn, initial_circuit_id(conn.wide))
            await asyncio.wait_for(circ.build(entry, middle, ex), timeout=25)
            circ._created_at = time.monotonic()
        except (Exception, asyncio.CancelledError):
            async with self._lock:
                if ex.identity != old_exit.identity:
                    self._release_exit_reservation_locked(ex)
            self._mark_build_failed(entry, middle, ex)
            await _close_connection(conn)
            return False

        observed_ip = await probe_exit_ip(circ)
        old_exit_ip = getattr(old_circ, "_exit_ip", None)
        async with self._lock:
            if observed_ip is None:
                if old_exit_ip is not None:
                    self._observed_exits.release(old_exit_ip, old_circ)
                circ._exit_verified = False
            else:
                claimed = self._observed_exits.claim(
                    observed_ip,
                    circ,
                    previous_exit_ip=old_exit_ip,
                    previous_owner=old_circ,
                )
                circ._exit_ip = observed_ip
                circ._exit_verified = True
                circ._exit_duplicate = not claimed
                if not claimed:
                    self._duplicate_exit_ids.add(ex.identity)
            if old_exit is not None and ex.identity != old_exit.identity:
                self._release_exit_reservation_locked(old_exit)
            self.circuits[idx] = circ
            self.connections[idx] = conn

        async def _safe_close():
            try:
                await self._delayed_close(old_circ, old_conn)
            except Exception as e:
                log.debug("_delayed_close failed: %s", e)

        asyncio.create_task(_safe_close())
        log.info(
            "Rebuilt circuit %d via %s -> %s -> %s (%s)",
            idx,
            entry.nickname,
            middle.nickname,
            ex.nickname,
            observed_ip or "unverified",
        )
        return True

    async def _delayed_close(self, circ: TorCircuit, conn: TorConnection) -> None:
        await asyncio.sleep(10)
        try:
            await circ.close()
        except Exception:
            pass
        try:
            await conn.close()
        except Exception:
            pass

    async def _refresh_consensus(
        self, consensus_path: str, microdescs_path: str, last_refresh: float
    ) -> float:
        if time.monotonic() - last_refresh <= 600:
            return last_refresh
        try:
            if not _check_consensus_fresh(consensus_path):
                log.info("Consensus stale -- fetching fresh from mirrors...")
                await asyncio.to_thread(
                    fetch_fresh_consensus, consensus_path, microdescs_path
                )
            new_relays = load_relays(consensus_path, microdescs_path)
            if not new_relays or len(new_relays) < len(self.all) // 2:
                return last_refresh
            added = len(new_relays) - len(self.all)
            self.all = new_relays
            self._dead_until.clear()
            n_unique = len({relay.ip for relay in new_relays if relay.can_exit()})
            log.info(
                "Consensus: %+d relays (%d exit IPs), blacklist cleared",
                added,
                n_unique,
            )
            new_exit_ips = {
                relay.ip
                for relay in new_relays
                if relay.can_exit() and relay.ip not in self._used_ips
            }
            room = max(0, self.num_circuits - len(self.circuits))
            can_add = min(len(new_exit_ips), 100, room)
            if can_add:
                log.info("Growing: up to %d new circuits", can_add)
                grow_sem = asyncio.Semaphore(20)
                grow_tasks = [
                    asyncio.create_task(self._grow_one(grow_sem))
                    for _ in range(can_add)
                ]
                results = await asyncio.gather(*grow_tasks, return_exceptions=True)
                grown = sum(1 for result in results if result is True)
                if grown:
                    log.info(
                        "Grew +%d circuits (%d total)",
                        grown,
                        len(self.circuits),
                    )
            return time.monotonic()
        except Exception as error:
            log.warning("Consensus refresh failed: %s", error)
            return last_refresh

    async def maintain(
        self, consensus_path: str, microdescs_path: str, interval: int = 60
    ) -> None:
        log.info("Maintainer: health every %ds, consensus every 600s", interval)
        last_refresh = -600.0

        while not self._shutting_down:
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            if self._shutting_down:
                break

            self._expire_dead_entries()

            total = len(self.circuits)
            if total > 0:
                s = self.get_stats()
                log.info(
                    "Pool stats: %d total, %d alive, %d unique IPs",
                    s["total"],
                    s["alive"],
                    s["unique_ips"],
                )
            if total == 0:
                continue

            sample_size = min(total, 200 if total >= 500 else total)
            indices = list(range(total))
            random.shuffle(indices)
            to_check = indices[:sample_size]

            quick_dead = []
            for index in range(total):
                if index in to_check:
                    continue
                conn = self.connections[index]
                if conn is None or conn.writer is None or conn.writer.is_closing():
                    quick_dead.append(index)

            check_sem = asyncio.Semaphore(50 if total >= 500 else 8)

            async def _check_one(i, sem):
                if i in self._rebuilding:
                    return None
                async with sem:
                    circ = self.circuits[i]
                    conn = self.connections[i]
                    if conn is None or conn.writer is None or conn.writer.is_closing():
                        return i
                    if not await self._check_circuit(circ):
                        if getattr(circ, "_health_fails", 0) >= 2:
                            return i
                    return None

            check_results = await asyncio.gather(
                *[_check_one(i, check_sem) for i in to_check], return_exceptions=True
            )
            dead = quick_dead + [i for i in check_results if isinstance(i, int)]
            dead = sorted(set(dead))

            if dead:
                log.info("Health: %d dead, rebuilding...", len(dead))
                rebuild_sem = asyncio.Semaphore(20 if total >= 200 else 5)

                async def _rebuild_one(i, sem):
                    async with sem:
                        try:
                            return await self._rebuild_circuit(
                                i, self.circuits[i], self.connections[i]
                            )
                        except Exception:
                            return False

                rebuild_results = await asyncio.gather(
                    *[_rebuild_one(i, rebuild_sem) for i in dead],
                    return_exceptions=True,
                )
                rebuilt = sum(1 for result in rebuild_results if result is True)
                if rebuilt == 0 and len(dead) >= total // 2:
                    log.warning(
                        "Mass rebuild failure (%d dead, 0 rebuilt) -- clearing blacklist",
                        len(dead),
                    )
                    self._dead_until.clear()
                log.info("Rebuilt %d/%d dead circuits", rebuilt, len(dead))

            last_refresh = await self._refresh_consensus(
                consensus_path, microdescs_path, last_refresh
            )

    async def _grow_one(self, sem: asyncio.Semaphore) -> bool:
        if self._shutting_down:
            return False
        async with sem:
            entry = self._pick_entry()
            if entry is None:
                return False
            ex = self._pick_exit(entry)
            if ex is None:
                return False
            middle = self._pick_middle(entry, ex)
            if middle is None:
                return False
            async with self._lock:
                if not self._reserve_exit_locked(ex):
                    return False
            conn: TorConnection | None = None
            try:
                conn = await _open_connection(entry)
            except (Exception, asyncio.CancelledError) as exc:
                async with self._lock:
                    self._release_exit_reservation_locked(ex)
                self._mark_build_failed(entry, middle, ex)
                await _close_connection(conn)
                if isinstance(exc, asyncio.CancelledError):
                    raise
                return False

            try:
                circ = TorCircuit(conn, initial_circuit_id(conn.wide))
                await asyncio.wait_for(circ.build(entry, middle, ex), timeout=25)
                circ._created_at = time.monotonic()
            except (Exception, asyncio.CancelledError) as exc:
                async with self._lock:
                    self._release_exit_reservation_locked(ex)
                self._mark_build_failed(entry, middle, ex)
                await _close_connection(conn)
                if isinstance(exc, asyncio.CancelledError):
                    raise
                return False

            observed_ip = await probe_exit_ip(circ)
            if observed_ip is None:
                circ._exit_verified = False
            else:
                async with self._lock:
                    claimed = self._observed_exits.claim(observed_ip, circ)
                    circ._exit_ip = observed_ip
                    circ._exit_verified = True
                    circ._exit_duplicate = not claimed
                    if not claimed:
                        self._duplicate_exit_ids.add(ex.identity)

            async with self._lock:
                self.circuits.append(circ)
                self.connections.append(conn)
            return True

    def get_stats(self) -> dict:
        alive = sum(
            1
            for c in self.circuits
            if c.conn and c.conn.writer and not c.conn.writer.is_closing()
        )
        exit_infos = [c.exit_info for c in self.circuits if c.exit_info]
        relay_ips = [info.ip for info in exit_infos]
        exit_ids = [info.identity for info in exit_infos]
        observed_ips = [
            c._exit_ip for c in self.circuits if getattr(c, "_exit_ip", None)
        ]
        return {
            "total": len(self.circuits),
            "alive": alive,
            "unique_ips": len(set(observed_ips)),
            "reserved_ips": len(self._used_ips),
            "observed_ips": len(observed_ips),
            "unverified_exits": len(self.circuits) - len(observed_ips),
            "duplicate_observed_ips": len(observed_ips) - len(set(observed_ips)),
            "duplicate_exit_relays": len(self._duplicate_exit_ids),
            "relay_unique_ips": len(set(relay_ips)),
            "circuit_unique_ips": len(set(relay_ips)),
            "circuit_unique_ids": len(set(exit_ids)),
            "missing_exit_info": len(self.circuits) - len(exit_infos),
            "duplicate_exit_ips": len(relay_ips) - len(set(relay_ips)),
            "duplicate_exit_ids": len(exit_ids) - len(set(exit_ids)),
            "dead_entries": len(self._dead_until),
            "rebuilding": len(self._rebuilding),
        }

    async def close_all(self) -> None:
        self._shutting_down = True
        for c in self.circuits:
            try:
                await asyncio.wait_for(c.close(), timeout=5)
            except (asyncio.TimeoutError, Exception):
                pass
        for c in self.connections:
            try:
                await asyncio.wait_for(c.close(), timeout=5)
            except (asyncio.TimeoutError, Exception):
                pass
