import asyncio
import math
import time
from typing import Any


class SessionManager:
    def __init__(self, default_ttl_minutes: int = 30):
        self._sessions: dict[str, tuple[int, float]] = {}
        self._lock = asyncio.Lock()
        self._ttl_seconds = (
            math.inf if default_ttl_minutes <= 0 else default_ttl_minutes * 60
        )
        self._last_purge = time.monotonic()
        self._max_sessions = 100_000

    async def get_circuit(
        self, session_id: str, pool: Any, ttl_minutes: int | None = None
    ) -> Any:
        async with self._lock:
            now = time.monotonic()

            if now - self._last_purge > 60:
                expired = [k for k, (_, exp) in self._sessions.items() if now >= exp]
                for k in expired:
                    del self._sessions[k]
                self._last_purge = now

            if session_id in self._sessions:
                idx, expiry = self._sessions[session_id]
                if now < expiry and idx < len(pool.circuits):
                    circ = pool.circuits[idx]
                    conn_alive = (
                        getattr(circ, "conn", None) is not None
                        and circ.conn.writer is not None
                        and not circ.conn.writer.is_closing()
                    )
                    if (
                        conn_alive
                        and not getattr(circ, "_circuit_failed", False)
                        and not getattr(circ, "_502_count", 0) >= 2
                    ):
                        if not getattr(circ, "_dispatch_running", False):
                            circ._ensure_dispatch()
                        return circ
                del self._sessions[session_id]

            circ = pool.get_circuit()
            idx = pool.circuits.index(circ)
            if ttl_minutes == 0:
                expiry = math.inf
            elif ttl_minutes is not None and ttl_minutes > 0:
                expiry = now + ttl_minutes * 60
            else:
                expiry = now + self._ttl_seconds
            if len(self._sessions) >= self._max_sessions:
                oldest = next(iter(self._sessions))
                del self._sessions[oldest]
            self._sessions[session_id] = (idx, expiry)
            return circ

    async def release(self, session_id: str) -> None:
        async with self._lock:
            self._sessions.pop(session_id, None)
