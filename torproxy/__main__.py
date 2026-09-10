import asyncio
import os
import random
import signal
import sys

from .auth import AuthManager
from .cli.state import delete_state_file, write_state_file
from .config import load_config
from .connection import TorConnection, tor_link_handshake
from .consensus import (
    RelayInfo,
    fetch_fresh_consensus,
    load_relays,
    load_relays_auto,
)
from .log import enable_file_log, log, setup_logging, suppress_console
from .pool import CircuitPool, DirectPool
from .proxy import HttpProxy
from .session import SessionManager


def _exit_relays(relays: list[RelayInfo]) -> list[RelayInfo]:
    return [relay for relay in relays if relay.can_exit()]


async def _load_relays_with_fallback(config) -> list[RelayInfo] | None:
    relays = load_relays_auto(config.consensus_path, config.microdescs_path)
    if relays and _exit_relays(relays):
        return relays
    log.info("No usable exit relays in cache, fetching fresh consensus...")
    if not fetch_fresh_consensus(config.consensus_path, config.microdescs_path):
        log.error("Failed to fetch consensus")
        return None
    relays = load_relays(config.consensus_path, config.microdescs_path)
    if not _exit_relays(relays):
        log.error("Still no exit relays after fetch")
        return None
    return relays


def _create_proxy(config, pool, auth_manager):
    sessions = SessionManager(default_ttl_minutes=config.session_ttl_minutes)
    return HttpProxy(
        config.listen,
        config.port,
        pool,
        auth_manager,
        sessions,
        max_clients=config.max_clients,
        max_request_bytes=config.max_request_bytes,
    )


async def _shutdown_runtime(
    pool: CircuitPool | DirectPool,
    proxy: HttpProxy,
    *tasks: asyncio.Task,
) -> None:
    log.info("Shutting down...")
    pool._shutting_down = True
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await proxy.stop()
    await pool.close_all()


async def _serve_pool(
    pool: CircuitPool | DirectPool,
    config,
    auth_manager: AuthManager,
    sigint_event: asyncio.Event,
    ready_message: str,
) -> None:
    proxy = _create_proxy(config, pool, auth_manager)
    await proxy.start()
    log.info(ready_message)
    background_task = asyncio.create_task(
        _build_then_maintain(
            pool, pool.num_circuits, config.consensus_path, config.microdescs_path
        )
    )
    try:
        await sigint_event.wait()
    finally:
        await _shutdown_runtime(pool, proxy, background_task)


async def _build_guard_pool(
    all_relays: list[RelayInfo], num_circuits: int
) -> CircuitPool | None:
    guards = [r for r in all_relays if r.can_guard()]
    if not guards:
        log.error("No guard relays found")
        return None

    exits = [r for r in all_relays if r.can_exit()]
    guard_ids = {r.identity for r in guards}
    exit_ids = {r.identity for r in exits}
    middles = [
        r
        for r in all_relays
        if r.is_usable() and r.identity not in guard_ids and r.identity not in exit_ids
    ]
    if not middles:
        middles = [r for r in all_relays if r.is_usable()]

    if num_circuits <= 0:
        num_circuits = min(len(exits), 100)
    log.info(
        "Relays: %d guards, %d middles, %d exits", len(guards), len(middles), len(exits)
    )

    conn = None
    pool = None
    for guard in random.sample(guards, min(15, len(guards))):
        try:
            log.info(
                "Connecting to guard: %s (%s:%d)",
                guard.nickname,
                guard.ip,
                guard.orport,
            )
            conn = TorConnection(guard.ip, guard.orport)
            await conn.connect()
            await tor_link_handshake(conn)
            conn.start_cell_router()
            pool = CircuitPool(
                conn, guard, middles, exits, num_circuits, all_relays=all_relays
            )
            await pool.build_all()
            if pool.circuits:
                break
            await conn.close()
            conn = None
        except Exception as e:
            log.warning("Guard %s failed: %s", guard.nickname, e)
            if conn:
                try:
                    await conn.close()
                except Exception:
                    pass
                conn = None

    if not conn or not pool or not pool.circuits:
        log.error("No usable guard found.")
        return None

    return pool


async def _build_pool(
    relays: list[RelayInfo], num_circuits: int, single_guard: bool
) -> CircuitPool | DirectPool | None:
    if single_guard:
        return await _build_guard_pool(relays, num_circuits)

    pool = DirectPool(relays, num_circuits)
    await pool.build_seed(min(50, num_circuits))
    if not pool.circuits:
        await pool.build_all()
    if not pool.circuits:
        log.error("Failed to build any circuits")
        return None
    return pool


async def _build_then_maintain(
    pool: CircuitPool | DirectPool,
    num_circuits: int,
    consensus_path: str,
    microdescs_path: str,
) -> None:
    while True:
        if getattr(pool, "_shutting_down", False):
            break
        try:
            if len(pool.circuits) < num_circuits:
                await pool.build_all()
            s = pool.get_stats()
            log.info(
                "Pool stats: %d total, %d alive, %d unique IPs",
                s["total"],
                s["alive"],
                s["unique_ips"],
            )
            await pool.maintain(consensus_path, microdescs_path, interval=60)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("Background builder/maintainer restarted after error: %s", exc)
            await asyncio.sleep(5)


async def _run_child(config, sigint_event: asyncio.Event) -> None:
    suppress_console()
    log_dir = os.path.dirname(os.path.abspath(config.consensus_path))
    os.makedirs(log_dir, exist_ok=True)
    enable_file_log(os.path.join(log_dir, "torproxy.log"))

    auth_manager = AuthManager(
        config_username=config.auth_username,
        config_password=config.auth_password,
        no_auth=config.no_auth,
    )

    log.info("Loading relays...")
    relays = await _load_relays_with_fallback(config)
    if relays is None:
        return
    num = config.num_circuits or len({relay.ip for relay in _exit_relays(relays)})
    pool = await _build_pool(relays, num, config.single_guard)
    if pool is None:
        return

    proxy = None

    async def _update_state():
        nonlocal proxy
        while True:
            await asyncio.sleep(1)
            try:
                bu = proxy.bytes_up if proxy else 0
                bd = proxy.bytes_down if proxy else 0
                write_state_file(
                    pid=os.getpid(),
                    port=config.port,
                    host=config.listen,
                    username=auth_manager.credentials.username,
                    password=auth_manager.credentials.password,
                    no_auth=config.no_auth,
                    config_path=config.config_path,
                    num_circuits=len(pool.circuits),
                    bytes_up=bu,
                    bytes_down=bd,
                )
            except Exception:
                pass

    state_task = asyncio.create_task(_update_state())

    proxy = _create_proxy(config, pool, auth_manager)
    await proxy.start()

    bg_task = asyncio.create_task(
        _build_then_maintain(
            pool, pool.num_circuits, config.consensus_path, config.microdescs_path
        )
    )

    try:
        await sigint_event.wait()
    finally:
        await _shutdown_runtime(pool, proxy, bg_task, state_task)
        delete_state_file()


async def run_headless(config, sigint_event: asyncio.Event) -> None:
    auth_manager = AuthManager(
        config_username=config.auth_username,
        config_password=config.auth_password,
        no_auth=config.no_auth,
    )
    auth_manager.print_credentials()

    log.info("Loading relays...")
    relays = await _load_relays_with_fallback(config)
    if relays is None:
        return

    if config.single_guard:
        pool = await _build_pool(relays, config.num_circuits, True)
        if pool is None:
            return
        ready_message = f"Ready -- {len(pool.circuits)} circuits, proxy on {config.listen}:{config.port}"
        await _serve_pool(pool, config, auth_manager, sigint_event, ready_message)
        return

    exits = _exit_relays(relays)
    unique_ips = len({relay.ip for relay in exits})
    num_circuits = config.num_circuits or unique_ips
    log.info(
        "Pool mode: %d exit relays, %d unique IPs available", len(exits), unique_ips
    )
    if num_circuits > unique_ips:
        log.info(
            "Requested %d > %d unique IPs -- IPs will be reused after %d circuits",
            num_circuits,
            unique_ips,
            unique_ips,
        )
    log.info("Building %d circuits...", num_circuits)
    pool = await _build_pool(relays, num_circuits, False)
    if pool is None:
        return
    stats = pool.get_stats()
    ready_message = (
        f"Proxy listening on {config.listen}:{config.port} "
        f"({len(pool.circuits)} seed circuits, {stats['reserved_ips']} unique exit IPs ready, "
        f"building {num_circuits - len(pool.circuits)} more in background)"
    )
    await _serve_pool(pool, config, auth_manager, sigint_event, ready_message)


async def main(sigint_event: asyncio.Event) -> None:
    config = load_config()
    setup_logging(config.verbose, config.debug)

    if config.headless:
        if config.child:
            await _run_child(config, sigint_event)
        else:
            await run_headless(config, sigint_event)
    else:
        from .cli.torproxy_ import run
        from .log import suppress_console

        suppress_console()
        await run(config)


def _patch_windows_proactor_transport() -> None:
    if sys.platform != "win32":
        return
    try:
        from asyncio.proactor_events import _ProactorBasePipeTransport

        original_loop_writing = _ProactorBasePipeTransport._loop_writing

        def patched_loop_writing(self, data=None):
            if getattr(self, "_sock", None) is None:
                return
            try:
                original_loop_writing(self, data)
            except AttributeError as error:
                if "'NoneType' object has no attribute 'send'" not in str(error):
                    raise

        _ProactorBasePipeTransport._loop_writing = patched_loop_writing
    except Exception:
        pass


def _entry() -> None:
    _patch_windows_proactor_transport()

    if sys.platform == "win32":
        from .cli.terminal import enable_windows_ansi

        enable_windows_ansi()

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
            os._exit(1)
        loop.call_soon_threadsafe(sigint_event.set)

    def _on_sigterm(*_):
        loop.call_soon_threadsafe(sigint_event.set)

    try:
        signal.signal(signal.SIGINT, _on_sigint)
    except ValueError:
        pass
    try:
        signal.signal(signal.SIGTERM, _on_sigterm)
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
        try:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
        except Exception:
            pass
        loop.close()

        sys.stdout.write("\n")
        sys.stdout.flush()


if __name__ == "__main__":
    _entry()
