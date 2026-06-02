import asyncio
import time
from typing import Any, Dict, Tuple


class SessionManager:

    def __init__(self, default_ttl_minutes: int = 30):
        self._sessions: Dict[str, Tuple[int, float]] = {}
        self._lock = asyncio.Lock()
        self._ttl_seconds = default_ttl_minutes * 60
        self._last_purge = time.monotonic()

    async def get_circuit(self, session_id: str, pool: Any) -> Any:
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
                    conn_alive = (getattr(circ, 'conn', None) is not None
                                  and circ.conn.writer is not None
                                  and not circ.conn.writer.is_closing())
                    if conn_alive and not getattr(circ, '_502_count', 0) >= 2:
                        if not getattr(circ, '_dispatch_running', False):
                            circ._ensure_dispatch()
                        return circ
                del self._sessions[session_id]

            circ = pool.get_circuit()
            idx = pool.circuits.index(circ)
            expiry = now + self._ttl_seconds
            self._sessions[session_id] = (idx, expiry)
            return circ
