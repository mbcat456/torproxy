import asyncio
import os
import random
import signal
import sys

from .auth import AuthManager
from .config import load_config
from .connection import TorConnection, tor_link_handshake
from .consensus import load_relays_auto
from .log import log, setup_logging
from .pool import CircuitPool, DirectPool
from .proxy import HttpProxy
from .session import SessionManager


async def _build_direct_pool(all_relays, num_circuits):
    exits = [r for r in all_relays if r.is_exit()]
    if not exits:
        log.error("No exit relays found")
        return None

    unique_ips = len(set(r.ip for r in exits))
    if num_circuits <= 0:
        num_circuits = unique_ips
    log.info("Pool mode: %d exit relays, %d unique IPs available", len(exits), unique_ips)
    if num_circuits > unique_ips:
        log.info("Requested %d > %d unique IPs -- IPs will be reused after %d circuits",
                 num_circuits, unique_ips, unique_ips)
    log.info("Building %d circuits...", num_circuits)

    pool = DirectPool(all_relays, num_circuits)

    seed_count = min(50, num_circuits)
    await pool.build_seed(seed_count)
    if not pool.circuits:
        log.info("No seed circuits built; blocking until at least one circuit is ready")
        await pool.build_all()

    return pool


async def _build_guard_pool(all_relays, num_circuits):
    guards = [r for r in all_relays if r.is_guard()]
    if not guards:
        log.error("No guard relays found")
        return None, None, None

    exits = [r for r in all_relays if r.is_exit()]
    guard_ids = {r.identity for r in guards}
    exit_ids = {r.identity for r in exits}
    middles = [r for r in all_relays if r.identity not in guard_ids and r.identity not in exit_ids]
    if not middles:
        middles = all_relays.copy()

    if num_circuits <= 0:
        num_circuits = min(len(exits), 100)
    log.info("Relays: %d guards, %d middles, %d exits", len(guards), len(middles), len(exits))

    conn = None
    pool = None
    for guard in random.sample(guards, min(15, len(guards))):
        try:
            log.info("Connecting to guard: %s (%s:%d)", guard.nickname, guard.ip, guard.orport)
            conn = TorConnection(guard.ip, guard.orport)
            await conn.connect()
            await tor_link_handshake(conn)
            pool = CircuitPool(conn, guard, middles, exits, num_circuits)
            await pool.build_all()
            if pool.circuits:
                break
            await conn.close()
            conn = None
        except Exception as e:
            log.warning("Guard %s failed: %s", guard.nickname, e)
            if conn:
                try: await conn.close()
                except Exception: pass
                conn = None

    if not conn or not pool or not pool.circuits:
        log.error("No usable guard found.")
        return None, None, None

    return pool, conn, exits


async def _build_then_maintain(pool, num_circuits, consensus_path, microdescs_path):
    try:
        if len(pool.circuits) < num_circuits:
            await pool.build_all()
        s = pool.get_stats()
        log.info("Pool stats: %d total, %d alive, %d unique IPs",
                 s["total"], s["alive"], s["unique_ips"])
        await pool.maintain(consensus_path, microdescs_path, interval=60)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.error("Background builder/maintainer stopped: %s", exc)


async def _run_child(config) -> None:
    from .cli.state import write_state_file
    from .consensus import fetch_fresh_consensus, load_relays
    from .log import suppress_console, enable_file_log

    suppress_console()
    log_dir = os.path.dirname(config.consensus_path)
    os.makedirs(log_dir, exist_ok=True)
    enable_file_log(os.path.join(log_dir, "torproxy.log"))

    auth_manager = AuthManager(
        config_username=config.auth_username,
        config_password=config.auth_password,
        no_auth=config.no_auth,
    )

    log.info("Loading relays...")
    all_relays = load_relays_auto(config.consensus_path, config.microdescs_path)
    exits = [r for r in all_relays if r.is_exit()]
    if not exits:
        log.info("No exit relays in cache, fetching fresh consensus...")
        ok = fetch_fresh_consensus(config.consensus_path, config.microdescs_path)
        if not ok:
            log.error("Failed to fetch consensus")
            return
        all_relays = load_relays(config.consensus_path, config.microdescs_path)
        exits = [r for r in all_relays if r.is_exit()]
        if not exits:
            log.error("Still no exit relays after fetch")
            return

    num = config.num_circuits
    unique_ips = len(set(r.ip for r in exits))
    if num <= 0:
        num = unique_ips

    pool = DirectPool(all_relays, num)

    _proxy = [None]

    async def _update_state():
        while True:
            await asyncio.sleep(1)
            try:
                bu = _proxy[0].bytes_up if _proxy[0] else 0
                bd = _proxy[0].bytes_down if _proxy[0] else 0
                write_state_file(
                    pid=os.getpid(), port=config.port, host=config.listen,
                    username=auth_manager.credentials.username,
                    password=auth_manager.credentials.password,
                    no_auth=config.no_auth, config_path=config.config_path,
                    num_circuits=len(pool.circuits),
                    bytes_up=bu, bytes_down=bd,
                )
            except Exception:
                pass

    state_task = asyncio.create_task(_update_state())

    seed = min(50, num)
    await pool.build_seed(seed)
    if not pool.circuits:
        await pool.build_all()
    if not pool.circuits:
        log.error("Failed to build any circuits")
        state_task.cancel()
        return

    sessions = SessionManager(default_ttl_minutes=config.session_ttl_minutes)
    proxy = HttpProxy(config.listen, config.port, pool, auth_manager, sessions,
                      max_clients=config.max_clients,
                      max_request_bytes=config.max_request_bytes)
    await proxy.start()
    _proxy[0] = proxy

    bg_task = asyncio.create_task(
        _build_then_maintain(pool, num, config.consensus_path, config.microdescs_path))

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        bg_task.cancel()
        state_task.cancel()
        await proxy.stop()
        await pool.close_all()
        from .cli.state import delete_state_file
        delete_state_file()


async def run_headless(config) -> None:
    auth_manager = AuthManager(
        config_username=config.auth_username,
        config_password=config.auth_password,
        no_auth=config.no_auth,
    )
    auth_manager.print_credentials()

    log.info("Loading relays...")
    all_relays = load_relays_auto(config.consensus_path, config.microdescs_path)

    if not config.single_guard:
        exits = [r for r in all_relays if r.is_exit()]
        if not exits:
            log.error("No exit relays found")
            return

        num_circuits = config.num_circuits
        unique_ips = len(set(r.ip for r in exits))
        if num_circuits <= 0:
            num_circuits = unique_ips
        log.info("Pool mode: %d exit relays, %d unique IPs available", len(exits), unique_ips)
        if num_circuits > unique_ips:
            log.info("Requested %d > %d unique IPs -- IPs will be reused after %d circuits",
                     num_circuits, unique_ips, unique_ips)
        log.info("Building %d circuits...", num_circuits)

        pool = DirectPool(all_relays, num_circuits)
        seed_count = min(50, num_circuits)
        await pool.build_seed(seed_count)
        if not pool.circuits:
            log.info("No seed circuits built; blocking until at least one circuit is ready")
            await pool.build_all()

        sessions = SessionManager(default_ttl_minutes=config.session_ttl_minutes)
        proxy = HttpProxy(config.listen, config.port, pool,
                          auth_manager, sessions,
                          max_clients=config.max_clients,
                          max_request_bytes=config.max_request_bytes)
        await proxy.start()
        log.info("Proxy listening on %s:%d (%d seed circuits, %d unique exit IPs ready, "
                 "building %d more in background)",
                 config.listen, config.port, len(pool.circuits), len(pool._used_ips),
                 num_circuits - len(pool.circuits))

        bg_task = asyncio.create_task(
            _build_then_maintain(pool, num_circuits,
                                config.consensus_path, config.microdescs_path))
        try:
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            log.info("Shutting down...")
        finally:
            bg_task.cancel()
            await proxy.stop()
            await pool.close_all()
        return

    result = await _build_guard_pool(all_relays, config.num_circuits)
    if result[0] is None:
        return
    pool, conn, _ = result

    sessions = SessionManager(default_ttl_minutes=config.session_ttl_minutes)
    proxy = HttpProxy(config.listen, config.port, pool,
                      auth_manager, sessions,
                      max_clients=config.max_clients,
                      max_request_bytes=config.max_request_bytes)
    await proxy.start()
    log.info("Ready -- %d circuits, proxy on %s:%d",
             len(pool.circuits), config.listen, config.port)

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        await proxy.stop()
        for c in pool.circuits:
            await c.close()
        await conn.close()


async def main(sigint_event: asyncio.Event) -> None:
    config = load_config()
    setup_logging(config.verbose, config.debug)

    if config.headless:
        if config.child:
            await _run_child(config)
        else:
            await run_headless(config)
    else:
        from .cli.torproxy_ import run
        from .log import suppress_console
        suppress_console()
        await run()


def _entry() -> None:
    if sys.platform == "win32":
        try:
            from asyncio.proactor_events import _ProactorBasePipeTransport
            _orig_loop_writing = _ProactorBasePipeTransport._loop_writing
            def _patched_loop_writing(self, data=None):
                if getattr(self, '_sock', None) is None:
                    return
                try:
                    _orig_loop_writing(self, data)
                except AttributeError as e:
                    if "'NoneType' object has no attribute 'send'" not in str(e):
                        raise
            _ProactorBasePipeTransport._loop_writing = _patched_loop_writing
        except Exception:
            pass

    if sys.platform == "win32":
        from .cli.terminal import _enable_windows_ansi
        _enable_windows_ansi()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    sigint_event = asyncio.Event()
    sigint_count = 0

    def _on_sigint(*_):
        nonlocal sigint_count
        sigint_count += 1
        if sigint_count >= 2:
            import os as _os
            _os._exit(1)
        loop.call_soon_threadsafe(sigint_event.set)

    try:
        signal.signal(signal.SIGINT, _on_sigint)
    except ValueError:
        pass

    try:
        loop.run_until_complete(main(sigint_event))
    except KeyboardInterrupt:
        pass
    finally:
        try:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
        except Exception:
            pass
        loop.close()

        sys.stdout.write("\n")
        sys.stdout.flush()


if __name__ == "__main__":
    _entry()
