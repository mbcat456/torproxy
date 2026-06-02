import asyncio
import json
import random
import time
from typing import List, Optional, Set, Dict, Tuple

from .circuit import TorCircuit
from .connection import TorConnection, tor_link_handshake
from .consensus import (
    RelayInfo,
    _check_consensus_fresh,
    fetch_fresh_consensus,
    load_relays,
)
from .log import log


class CircuitPool:

    def __init__(self, conn: TorConnection, guard: RelayInfo,
                 middles: List[RelayInfo], exits: List[RelayInfo],
                 num_circuits: int = 10):
        self.conn = conn
        self.guard = guard
        self.middles = middles
        self.exits = exits
        self.num_circuits = num_circuits
        self.circuits: List[TorCircuit] = []
        self._idx = 0
        self._circ_id_next = 0x80000001
        self._lock = asyncio.Lock()

    async def build_all(self) -> None:
        used_ips: Set[str] = set()
        used_ids: Set[bytes] = set()
        attempts = 0
        max_attempts = self.num_circuits * 3

        while len(self.circuits) < self.num_circuits and attempts < max_attempts:
            attempts += 1
            middle = random.choice(self.middles)
            while middle.identity == self.guard.identity and len(self.middles) > 1:
                middle = random.choice(self.middles)
            ex = random.choice(self.exits)
            while (ex.identity == self.guard.identity or
                   ex.identity == middle.identity or
                   ex.ip in used_ips or
                   ex.identity in used_ids) and len(self.exits) > 1:
                ex = random.choice(self.exits)

            try:
                circ = await self._build_one(self.guard, middle, ex)
                self.circuits.append(circ)
                used_ips.add(ex.ip)
                used_ids.add(ex.identity)
                log.info("Circuit %d/%d built via %s (%s)",
                         len(self.circuits), self.num_circuits, ex.nickname, ex.ip)
            except Exception as exc:
                log.warning("Circuit build attempt %d failed: %s", attempts, exc)

        log.info("Built %d/%d circuits", len(self.circuits), self.num_circuits)
        if not self.circuits:
            raise RuntimeError("Failed to build any circuits")

    async def _build_one(self, guard: RelayInfo, middle: RelayInfo,
                         ex: RelayInfo) -> TorCircuit:
        async with self._lock:
            cid = self._circ_id_next
            self._circ_id_next += 1
        circ = TorCircuit(self.conn, cid)
        await circ.build(guard, middle, ex)
        return circ

    def get_circuit(self) -> TorCircuit:
        if not self.circuits:
            raise RuntimeError("No circuits available")
        sample = random.sample(self.circuits, min(len(self.circuits), 32))
        return min(sample, key=lambda c: getattr(c, '_active_streams', 0))

    def note_502(self, circ: TorCircuit) -> None:
        pass

    def get_stats(self) -> dict:
        alive = sum(1 for c in self.circuits
                    if c.conn and c.conn.writer and not c.conn.writer.is_closing())
        unique_ips = len(set(c.exit_info.ip for c in self.circuits if c.exit_info))
        return {
            "total": len(self.circuits),
            "alive": alive,
            "unique_ips": unique_ips,
            "guard": self.guard.nickname,
        }

    async def close_all(self) -> None:
        for c in self.circuits:
            await c.close()
        await self.conn.close()


class DirectPool:

    HEALTH_CHECKS = [
        (b'GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n',
         'httpbin.org', 80),
        (b'GET / HTTP/1.1\r\nHost: checkip.amazonaws.com\r\nConnection: close\r\n\r\n',
         'checkip.amazonaws.com', 80),
    ]

    def __init__(self, relays: List[RelayInfo], num_circuits: int = 10):
        self.all = relays
        self.num_circuits = num_circuits
        self.circuits: List[TorCircuit] = []
        self.connections: List[TorConnection] = []
        self._idx = 0
        self._used_ips: Set[str] = set()
        self._used_ids: Set[bytes] = set()
        self._dead_until: Dict[bytes, float] = {}
        self._rebuilding: Set[int] = set()
        self._shutting_down: bool = False
        self._lock = asyncio.Lock()

    def _entry_dead(self, ident: bytes) -> bool:
        until = self._dead_until.get(ident)
        if until is None:
            return False
        if time.monotonic() < until:
            return True
        del self._dead_until[ident]
        return False

    def _mark_entry_dead(self, ident: bytes, duration: float = 300.0) -> None:
        self._dead_until[ident] = time.monotonic() + duration

    def _expire_dead_entries(self) -> int:
        now = time.monotonic()
        expired = [k for k, v in self._dead_until.items() if now >= v]
        for k in expired:
            del self._dead_until[k]
        return len(expired)

    def _pick_entry(self, exclude_ip: Optional[str] = None) -> Optional[RelayInfo]:
        candidates = [r for r in self.all
                      if r.is_guard() and r.has_ntor_key()
                      and not self._entry_dead(r.identity)
                      and r.ip != exclude_ip]
        if not candidates:
            candidates = [r for r in self.all
                          if r.has_ntor_key()
                          and not self._entry_dead(r.identity)]
        return random.choice(candidates) if candidates else None

    def _pick_exit(self, entry: RelayInfo) -> Optional[RelayInfo]:
        others = [r for r in self.all
                  if r.identity != entry.identity and r.is_running()
                  and not self._entry_dead(r.identity)]
        fresh = [r for r in others if r.is_exit()
                 and r.ip not in self._used_ips
                 and r.identity not in self._used_ids]
        if fresh:
            return random.choice(fresh)
        exits = [r for r in others if r.is_exit()]
        return random.choice(exits) if exits else None

    def _pick_middle(self, entry: RelayInfo, exit_relay: RelayInfo) -> Optional[RelayInfo]:
        candidates = [r for r in self.all
                      if r.identity not in (entry.identity, exit_relay.identity)
                      and r.is_running()
                      and r.has_ntor_key()
                      and not self._entry_dead(r.identity)]
        if not candidates:
            candidates = [r for r in self.all
                          if r.identity not in (entry.identity, exit_relay.identity)
                          and r.has_ntor_key()
                          and not self._entry_dead(r.identity)]
        return random.choice(candidates) if candidates else None

    async def build_seed(self, count: int = 50, deadline: float = 12.0) -> None:
        entries = [r for r in self.all if r.is_guard() and r.has_ntor_key()][:count*2]
        if not entries:
            entries = [r for r in self.all if r.has_ntor_key()][:count*2]
        chosen = random.sample(entries, min(count, len(entries)))
        sem = asyncio.Semaphore(50)
        async def _limited(i, ex):
            async with sem:
                try:
                    return await asyncio.wait_for(self._build_one(i, ex), timeout=deadline)
                except asyncio.TimeoutError:
                    return RuntimeError("Seed circuit timed out")
        results = await asyncio.gather(
            *[_limited(i, ex) for i, ex in enumerate(chosen)],
            return_exceptions=True)
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                log.warning("Seed circuit %d failed: %s", i, r)
        log.info("Seed: %d circuits ready", len(self.circuits))

    async def build_all(self) -> None:
        total = self.num_circuits
        stalled_rounds = 0
        while len(self.circuits) < total and stalled_rounds < 5:
            needed = total - len(self.circuits)
            batch = min(needed, 200)
            entries = [r for r in self.all if r.is_guard() and r.has_ntor_key()
                       and not self._entry_dead(r.identity)]
            if not entries:
                entries = [r for r in self.all if r.has_ntor_key()
                           and not self._entry_dead(r.identity)]
            if not entries:
                break
            chosen = random.sample(entries, min(batch, len(entries)))

            sem = asyncio.Semaphore(100)
            async def _limited(i, ex):
                async with sem:
                    return await self._build_one(i, ex)
            tasks = [_limited(len(self.circuits) + j, ex)
                     for j, ex in enumerate(chosen)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            built = sum(1 for r in results if not isinstance(r, Exception))
            failed = sum(1 for r in results if isinstance(r, Exception))
            log.info("Batch: +%d circuits, %d failed (%d/%d total, %d unique exit IPs)",
                     built, failed, len(self.circuits), total, len(self._used_ips))
            stalled_rounds = stalled_rounds + 1 if built == 0 else 0

        log.info("Built %d/%d pooled circuits (%d unique exit IPs)",
                 len(self.circuits), self.num_circuits, len(self._used_ips))
        if not self.circuits:
            raise RuntimeError("Failed to build any circuits")

    async def _build_one(self, idx: int, entry: RelayInfo) -> None:
        conn = TorConnection(entry.ip, entry.orport)
        ex: Optional[RelayInfo] = None
        try:
            try:
                await asyncio.wait_for(conn.connect(), timeout=5)
                await asyncio.wait_for(tor_link_handshake(conn), timeout=5)
            except asyncio.TimeoutError:
                raise RuntimeError("Connect/handshake timeout")

            ex = self._pick_exit(entry)
            if ex is None:
                raise RuntimeError("No exit relays available")
            middle = self._pick_middle(entry, ex)
            if middle is None:
                raise RuntimeError("No middle relays available")

            async with self._lock:
                if ex.ip in self._used_ips or ex.identity in self._used_ids:
                    raise RuntimeError(f"Duplicate exit IP/identity: {ex.ip}")
                self._used_ips.add(ex.ip)
                self._used_ids.add(ex.identity)

            circ = TorCircuit(conn, 0x80000001)
            await asyncio.wait_for(circ.build(entry, middle, ex), timeout=25)
            circ._created_at = time.monotonic()

            async with self._lock:
                self.connections.append(conn)
                self.circuits.append(circ)
            log.info("Circuit %d via %s -> %s -> %s (%s)",
                     idx, entry.nickname, middle.nickname, ex.nickname, ex.ip)
        except Exception:
            if ex is not None:
                async with self._lock:
                    self._used_ips.discard(ex.ip)
                    self._used_ids.discard(ex.identity)
            self._mark_entry_dead(entry.identity, 300)
            try: await conn.close()
            except Exception: pass
            raise

    def get_circuit(self) -> TorCircuit:
        if not self.circuits:
            raise RuntimeError("No circuits available")
        alive = [c for c in self.circuits
                 if getattr(c, '_502_count', 0) < 2
                 and getattr(c, 'conn', None) is not None
                 and c.conn.writer is not None
                 and not c.conn.writer.is_closing()]
        if not alive:
            alive = self.circuits
        if not alive:
            raise RuntimeError("No circuits available")
        sample = random.sample(alive, min(len(alive), 32))
        circ = min(sample, key=lambda c: getattr(c, '_active_streams', 0))
        if not getattr(circ, '_dispatch_running', False):
            circ._ensure_dispatch()
        return circ

    def note_502(self, circ: TorCircuit) -> None:
        count = getattr(circ, '_502_count', 0) + 1
        circ._502_count = count
        if count == 2:
            async def _safe_urgent():
                try: await self._urgent_rebuild(circ)
                except Exception as e: log.debug("_urgent_rebuild failed: %s", e)
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
        log.info("Urgent rebuild circuit %d (%s)", idx,
                 getattr(circ, '_exit_ip', 'unknown'))
        if await self._rebuild_circuit(idx, circ, conn):
            circ._502_count = 0
            circ._health_fails = 0

    async def _check_circuit(self, circ: TorCircuit) -> bool:
        if (circ.conn is None or circ.conn.writer is None
                or circ.conn.writer.is_closing()
                or not getattr(circ, '_dispatch_running', False)):
            return False

        for req_data, host, port in self.HEALTH_CHECKS:
            try:
                resp = await asyncio.wait_for(
                    circ.http_request(host, port, req_data), timeout=10)
                if resp and len(resp) > 50:
                    circ._502_count = 0
                    circ._health_fails = 0
                    try:
                        body = resp.split(b'\r\n\r\n', 1)[1]
                        data = json.loads(body)
                        ip = data.get('origin', '')
                        if ip:
                            circ._exit_ip = ip
                    except Exception:
                        pass
                    return True
            except Exception:
                continue

        circ._health_fails = getattr(circ, '_health_fails', 0) + 1
        return False

    async def _rebuild_circuit(self, idx: int, old_circ: TorCircuit,
                                old_conn: TorConnection) -> bool:
        if self._shutting_down:
            return False
        if idx in self._rebuilding:
            return False
        self._rebuilding.add(idx)
        try:
            return await self._rebuild_circuit_inner(idx, old_circ, old_conn)
        finally:
            self._rebuilding.discard(idx)

    async def _rebuild_circuit_inner(self, idx: int, old_circ: TorCircuit,
                                     old_conn: TorConnection) -> bool:
        old_entry_ip = old_conn.host if old_conn else None

        entry = self._pick_entry(exclude_ip=old_entry_ip)
        if entry is None:
            log.debug("Rebuild %d: no usable entry relays", idx)
            return False

        ex = self._pick_exit(entry)
        if ex is None:
            log.debug("Rebuild %d: no usable exit relays", idx)
            return False
        middle = self._pick_middle(entry, ex)
        if middle is None:
            log.debug("Rebuild %d: no usable middle relays", idx)
            return False

        async with self._lock:
            if ex.ip in self._used_ips or ex.identity in self._used_ids:
                return False
            self._used_ips.add(ex.ip)
            self._used_ids.add(ex.identity)

        try:
            conn = TorConnection(entry.ip, entry.orport)
            await asyncio.wait_for(conn.connect(), timeout=8)
            await asyncio.wait_for(tor_link_handshake(conn), timeout=5)
        except Exception:
            async with self._lock:
                self._used_ips.discard(ex.ip)
                self._used_ids.discard(ex.identity)
            self._mark_entry_dead(entry.identity, 300)
            try: await conn.close()
            except Exception: pass
            return False

        try:
            circ = TorCircuit(conn, 0x80000001)
            await asyncio.wait_for(circ.build(entry, middle, ex), timeout=25)
            circ._created_at = time.monotonic()
        except Exception:
            async with self._lock:
                self._used_ips.discard(ex.ip)
                self._used_ids.discard(ex.identity)
            self._mark_entry_dead(entry.identity, 300)
            try: await conn.close()
            except Exception: pass
            return False

        async with self._lock:
            if old_circ.exit_info:
                self._used_ips.discard(old_circ.exit_info.ip)
                self._used_ids.discard(old_circ.exit_info.identity)
        self.circuits[idx] = circ
        self.connections[idx] = conn
        async def _safe_close():
            try: await self._delayed_close(old_circ, old_conn)
            except Exception as e: log.debug("_delayed_close failed: %s", e)
        asyncio.create_task(_safe_close())
        log.info("Rebuilt circuit %d via %s -> %s -> %s (%s)",
                 idx, entry.nickname, middle.nickname, ex.nickname, ex.ip)
        return True

    async def _delayed_close(self, circ: TorCircuit, conn: TorConnection) -> None:
        await asyncio.sleep(10)
        try: await circ.close()
        except Exception: pass
        try: await conn.close()
        except Exception: pass

    async def maintain(self, consensus_path: str, microdescs_path: str,
                       interval: int = 60) -> None:
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

            if time.monotonic() - last_refresh > 600:
                try:
                    if not _check_consensus_fresh(consensus_path):
                        log.info("Consensus stale -- fetching fresh from mirrors...")
                        await asyncio.to_thread(
                            fetch_fresh_consensus, consensus_path, microdescs_path)
                    new_relays = load_relays(consensus_path, microdescs_path)
                    if new_relays and len(new_relays) >= len(self.all) // 2:
                        added = len(new_relays) - len(self.all)
                        self.all = new_relays
                        self._dead_until.clear()
                        n_unique = len(set(r.ip for r in new_relays if r.is_exit()))
                        log.info("Consensus: %+d relays (%d exit IPs), blacklist cleared",
                                 added, n_unique)
                        new_exit_ips = set(
                            r.ip for r in new_relays
                            if r.is_exit() and r.ip not in self._used_ips)
                        room = max(0, self.num_circuits - len(self.circuits))
                        can_add = min(len(new_exit_ips), 100, room)
                        if can_add > 0:
                            log.info("Growing: up to %d new circuits", can_add)
                            grow_sem = asyncio.Semaphore(20)
                            grow_tasks = [
                                asyncio.create_task(self._grow_one(grow_sem))
                                for _ in range(can_add)]
                            results = await asyncio.gather(
                                *grow_tasks, return_exceptions=True)
                            grown = sum(1 for r in results if r is True)
                            if grown:
                                log.info("Grew +%d circuits (%d total)", grown,
                                         len(self.circuits))
                    last_refresh = time.monotonic()
                except Exception as e:
                    log.warning("Consensus refresh failed: %s", e)

            live_ips = set()
            live_ids = set()
            for c in self.circuits:
                if c.exit_info:
                    live_ips.add(c.exit_info.ip)
                    live_ids.add(c.exit_info.identity)
            leaked_ips = self._used_ips - live_ips
            leaked_ids = self._used_ids - live_ids
            if leaked_ips or leaked_ids:
                self._used_ips -= leaked_ips
                self._used_ids -= leaked_ids
                log.info("Cleaned %d leaked IPs, %d leaked IDs",
                         len(leaked_ips), len(leaked_ids))

            total = len(self.circuits)
            if total > 0:
                s = self.get_stats()
                log.info("Pool stats: %d total, %d alive, %d unique IPs",
                         s["total"], s["alive"], s["unique_ips"])
            if total == 0:
                continue

            sample_size = min(total, max(50, total // 10))
            indices = list(range(total))
            random.shuffle(indices)
            to_check = indices[:sample_size]

            dead = []
            for i in to_check:
                if i in self._rebuilding:
                    continue
                circ = self.circuits[i]
                conn = self.connections[i]
                if conn is None or conn.writer is None or conn.writer.is_closing():
                    dead.append(i)
                    continue
                if not await self._check_circuit(circ):
                    if getattr(circ, '_health_fails', 0) >= 2:
                        dead.append(i)

            if dead:
                log.info("Health: %d dead, rebuilding...", len(dead))
                rebuilt = 0
                for i in dead:
                    try:
                        if await self._rebuild_circuit(i, self.circuits[i],
                                                        self.connections[i]):
                            rebuilt += 1
                    except Exception:
                        pass
                if rebuilt == 0 and len(dead) >= total // 2:
                    log.warning("Mass rebuild failure (%d dead, 0 rebuilt) -- clearing blacklist",
                                len(dead))
                    self._dead_until.clear()
                log.info("Rebuilt %d/%d dead circuits", rebuilt, len(dead))

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
                if ex.ip in self._used_ips or ex.identity in self._used_ids:
                    return False
                self._used_ips.add(ex.ip)
                self._used_ids.add(ex.identity)
            try:
                conn = TorConnection(entry.ip, entry.orport)
                await asyncio.wait_for(conn.connect(), timeout=8)
                await asyncio.wait_for(tor_link_handshake(conn), timeout=5)
            except Exception:
                async with self._lock:
                    self._used_ips.discard(ex.ip)
                    self._used_ids.discard(ex.identity)
                try: await conn.close()
                except Exception: pass
                return False

            try:
                circ = TorCircuit(conn, 0x80000001)
                await asyncio.wait_for(circ.build(entry, middle, ex), timeout=25)
                circ._created_at = time.monotonic()
            except Exception:
                async with self._lock:
                    self._used_ips.discard(ex.ip)
                    self._used_ids.discard(ex.identity)
                try: await conn.close()
                except Exception: pass
                return False

            async with self._lock:
                self.circuits.append(circ)
                self.connections.append(conn)
            return True

    def get_stats(self) -> dict:
        alive = sum(1 for c in self.circuits
                    if c.conn and c.conn.writer and not c.conn.writer.is_closing())
        return {
            "total": len(self.circuits),
            "alive": alive,
            "unique_ips": len(self._used_ips),
            "dead_entries": len(self._dead_until),
            "rebuilding": len(self._rebuilding),
        }

    async def close_all(self) -> None:
        self._shutting_down = True
        for c in self.circuits:
            await c.close()
        for c in self.connections:
            await c.close()
