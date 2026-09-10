import asyncio
import ctypes
import os
import re
import select
import signal
import subprocess
import sys
import threading
import time
import uuid
from urllib.parse import quote

from torproxy import __version__
from torproxy.consensus import fetch_fresh_consensus, load_relays

from .state import delete_state_file, read_state_file
from .terminal import enable_windows_terminal

ESC = "\033"
RESET = ESC + "[0m"
BOLD = ESC + "[1m"
DIM = ESC + "[2m"
CLEAR = ESC + "[2J" + ESC + "[3J" + ESC + "[H"
HIDE_CURSOR = ESC + "[?25l"
SHOW_CURSOR = ESC + "[?25h"

ANSI_PATTERN = re.compile(r"\033\[[0-9;]*[a-zA-Z]")


class ProgressReporter:
    def __init__(self, initial_message: str) -> None:
        self.message = initial_message

    def __call__(self, message: str) -> None:
        self.message = message


class SystemMetrics:
    def __init__(self) -> None:
        self._ram = (0, 0, 0)
        self._process_memory = -1
        self._cpu = -1.0
        self._last_ram_check = 0.0
        self._last_fast_check = 0.0

    def update(self, now: float) -> tuple[tuple[int, int, int], int, float]:
        if now - self._last_ram_check > 10:
            self._ram = system_ram()
            self._last_ram_check = now
        if now - self._last_fast_check > 1.0:
            self._process_memory = process_memory()
            self._cpu = cpu_percent()
            self._last_fast_check = now
        return self._ram, self._process_memory, self._cpu


class BandwidthTracker:
    def __init__(self) -> None:
        self._last_up = 0
        self._last_down = 0
        self._last_time: float | None = None
        self._up_label = "0 Kbps"
        self._down_label = "0 Kbps"

    @property
    def labels(self) -> tuple[str, str]:
        return self._up_label, self._down_label

    def update(self, now: float, bytes_up: int, bytes_down: int) -> tuple[str, str]:
        if self._last_time is None:
            self._last_up = bytes_up
            self._last_down = bytes_down
            self._last_time = now
        elif now - self._last_time > 0.8:
            elapsed = now - self._last_time
            self._up_label = format_bandwidth(
                max(0, (bytes_up - self._last_up) / elapsed * 8)
            )
            self._down_label = format_bandwidth(
                max(0, (bytes_down - self._last_down) / elapsed * 8)
            )
            self._last_up = bytes_up
            self._last_down = bytes_down
            self._last_time = now
        return self._up_label, self._down_label


def render_dashboard(
    state: dict | None,
    child_pid: int,
    target: int,
    uptime: float,
    ram_total: int,
    ram_available: int,
    process_bytes: int,
    cpu_value: float,
    bandwidth_up: str,
    bandwidth_down: str,
    launch_message: str,
    width: int,
    height: int,
) -> str:
    ram_used = ram_total - ram_available if ram_total else 0
    cpu_label = f"{cpu_value:.0f}%" if cpu_value >= 0 else "--%"
    cpu_line = dark(CPU_NAME.replace(" Processor", "").replace("processor", "")[:30])
    ram_line = (
        gray(format_size(ram_used))
        + dark("/")
        + gray(format_size(ram_total))
        + dark(" · ")
        + gray(f"{cpu_label} cpu usage")
    )
    title_line = BOLD + "TorProxy" + RESET + " " + dark("v" + __version__)
    left_width = min(visible_length(cpu_line) + 3, 35)
    right_width = visible_length(ram_line) + 2
    right_column = width - right_width
    middle_width = right_column - left_width - 1
    title_column = left_width + 1 + (middle_width - visible_length(title_line)) // 2
    output = [CLEAR]
    output.append(move(1, 1) + cpu_line)
    output.append(move(1, left_width) + dark(" │ "))
    output.append(move(1, title_column) + title_line)
    output.append(move(1, right_column) + dark(" │ "))
    output.append(move(1, right_column + 3) + ram_line)
    output.append(move(2, 0) + dark("─" * (width - 1)))
    middle = max(height // 2 - 3, 5)
    if state:
        dot = green("●") if state.get("num_circuits", 0) > 0 else yellow("○")
        host = state.get("host", "127.0.0.1")
        port = state.get("port", 8080)
        count = state.get("num_circuits", 0)
        no_auth = state.get("no_auth", False)
        username = state.get("username", "")
        password = state.get("password", "")
        process_label = str(child_pid or state.get("pid", 0))
        address = f"{dot}  {gray(f'{host}:{port}')}  {dark(f'PID {process_label}')}"
        output.append(move(middle, 0) + center(address, width))
        circuits = f"Circuits: {green(str(count))}"
        if target:
            circuits += f" {dark(f'/ {target}')}"
        output.append(move(middle + 1, 0) + center(circuits, width))
        bytes_up = state.get("bytes_up", 0)
        bytes_down = state.get("bytes_down", 0)
        traffic = (
            f"{dark('▲')} {cyan(bandwidth_up)} {dark('▼')} {cyan(bandwidth_down)}    "
            f"{dark('▲')} {gray(format_size(bytes_up))}  {dark('▼')} {gray(format_size(bytes_down))}"
        )
        output.append(move(middle + 2, 0) + center(traffic, width))
        if uptime > 0:
            output.append(
                move(middle + 3, 0)
                + center(f"Uptime: {dark(format_duration(uptime))}", width)
            )
        if not no_auth and username:
            output.append(
                move(middle + 4, 0)
                + center(f"{dark(username)} : {dark(password)}", width)
            )
        keys = (
            f"{dark('[G]')} Generate    {dark('[T]')} Terminate    {dark('[Q]')} Quit"
        )
        output.append(move(middle + 6, 0) + center(keys, width))
    else:
        output.append(move(middle, 0) + center(red("Proxy not running"), width))
        keys = f"{dark('[L]')} Launch    {dark('[G]')} Generate    {dark('[Q]')} Quit"
        output.append(move(middle + 2, 0) + center(keys, width))
    if launch_message:
        output.append(move(middle - 2, 0) + center(launch_message, width))
    memory_label = format_size(process_bytes) if process_bytes > 0 else "N/A"
    output.append(move(height, 1) + dark(f"PID {os.getpid()}  {memory_label}  Python"))
    output.append(move(height, width - 20) + dark(f"{CORE_COUNT} threads"))
    return "".join(output)


async def finish_in_background(
    height: int, width: int, background_pid: int, message: str
) -> None:
    sys.stdout.write(
        f"{CLEAR}{move(height // 2, width // 2 - 20)}"
        f"{green(message + ' PID ' + str(background_pid))}"
    )
    sys.stdout.flush()
    sys.stdout.write(move(height - 1, 0) + dark("Auto-closing in 5s..."))
    sys.stdout.flush()
    await asyncio.sleep(5)
    sys.stdout.write(SHOW_CURSOR)


def color(red: int, green: int, blue: int, text: str = "") -> str:
    return f"{ESC}[{text}38;2;{red};{green};{blue}m"


def move(row: int, column: int) -> str:
    return f"{ESC}[{row};{column}H"


def green(text: str) -> str:
    return color(100, 255, 100) + text + RESET


def yellow(text: str) -> str:
    return color(255, 205, 55) + text + RESET


def red(text: str) -> str:
    return color(255, 85, 85) + text + RESET


def cyan(text: str) -> str:
    return color(65, 205, 255) + text + RESET


def gray(text: str) -> str:
    return color(115, 115, 115) + text + RESET


def dark(text: str) -> str:
    return color(65, 65, 65) + text + RESET


def visible_length(text: str) -> int:
    return len(ANSI_PATTERN.sub("", text))


def center(text: str, width: int) -> str:
    padding = max(0, (width - visible_length(text)) // 2)
    return " " * padding + text


def cpu_name() -> str:
    if sys.platform == "win32":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as key:
                return winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        except Exception:
            return "Unknown CPU"
    try:
        with open("/proc/cpuinfo") as stream:
            for line in stream:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        return "Unknown CPU"
    return "Unknown CPU"


def system_ram() -> tuple[int, int, int]:
    if sys.platform == "win32":
        try:

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_uint32),
                    ("load", ctypes.c_uint32),
                    ("total", ctypes.c_uint64),
                    ("available", ctypes.c_uint64),
                    ("page_total", ctypes.c_uint64),
                    ("page_available", ctypes.c_uint64),
                    ("virtual_total", ctypes.c_uint64),
                    ("virtual_available", ctypes.c_uint64),
                    ("extended_available", ctypes.c_uint64),
                ]

            status = MemoryStatus()
            status.length = ctypes.sizeof(MemoryStatus)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
            return status.total, status.available, status.load
        except Exception:
            return 0, 0, 0
    try:
        total = 0
        available = 0
        with open("/proc/meminfo") as stream:
            for line in stream:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    available = int(line.split()[1]) * 1024
                if total and available:
                    break
        if total:
            load = int((1 - available / total) * 100)
            return total, available, load
    except Exception:
        pass
    return 0, 0, 0


def process_memory() -> int:
    try:
        import psutil

        return psutil.Process().memory_info().rss
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            import ctypes.wintypes

            class ProcessMemory(ctypes.Structure):
                _fields_ = [
                    ("count", ctypes.wintypes.DWORD),
                    ("page_faults", ctypes.wintypes.DWORD),
                    ("peak_working_set", ctypes.c_size_t),
                    ("working_set", ctypes.c_size_t),
                    ("quota_peak_paged", ctypes.c_size_t),
                    ("quota_paged", ctypes.c_size_t),
                    ("quota_peak_non_paged", ctypes.c_size_t),
                    ("quota_non_paged", ctypes.c_size_t),
                    ("pagefile_usage", ctypes.c_size_t),
                    ("peak_pagefile_usage", ctypes.c_size_t),
                ]

            memory = ProcessMemory()
            memory.count = ctypes.sizeof(ProcessMemory)
            try:
                ctypes.windll.kernel32.K32GetProcessMemoryInfo(
                    ctypes.windll.kernel32.GetCurrentProcess(),
                    ctypes.byref(memory),
                    memory.count,
                )
            except Exception:
                ctypes.windll.psapi.GetProcessMemoryInfo(
                    ctypes.windll.kernel32.GetCurrentProcess(),
                    ctypes.byref(memory),
                    memory.count,
                )
            return memory.working_set
        except Exception:
            return -1
    try:
        with open("/proc/self/status") as stream:
            for line in stream:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        return -1
    return -1


_cpu_previous = None


def cpu_percent() -> float:
    global _cpu_previous
    try:
        import psutil

        return psutil.cpu_percent(interval=0)
    except Exception:
        pass
    try:
        current = read_cpu_times()
    except Exception:
        return -1.0
    if current is None:
        return -1.0
    if _cpu_previous is None:
        _cpu_previous = current
        return -1.0
    idle_delta = current[0] - _cpu_previous[0]
    total_delta = current[1] - _cpu_previous[1]
    _cpu_previous = current
    if total_delta > 0:
        return (1.0 - idle_delta / total_delta) * 100.0
    return -1.0


def read_cpu_times() -> tuple[int, int] | None:
    if sys.platform == "win32":

        class FileTime(ctypes.Structure):
            _fields_ = [
                ("low", ctypes.c_uint32),
                ("high", ctypes.c_uint32),
            ]

        class SystemTimes(ctypes.Structure):
            _fields_ = [("idle", FileTime), ("kernel", FileTime), ("user", FileTime)]

        times = SystemTimes()
        ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(times.idle),
            ctypes.byref(times.kernel),
            ctypes.byref(times.user),
        )
        idle = (times.idle.high << 32) | times.idle.low
        kernel = (times.kernel.high << 32) | times.kernel.low
        user = (times.user.high << 32) | times.user.low
        return idle, kernel + user + idle
    with open("/proc/stat") as stream:
        fields = stream.readline().split()
    if fields[0] != "cpu":
        return None
    values = [int(value) for value in fields[1:]]
    total = sum(values)
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return idle, total


CPU_NAME = cpu_name()
CORE_COUNT = os.cpu_count() or 1


def format_size(value: int) -> str:
    if value >= 1 << 30:
        return f"{value / (1 << 30):.1f} GB"
    if value >= 1 << 20:
        return f"{value / (1 << 20):.0f} MB"
    return f"{value >> 10} KB"


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"


def format_bandwidth(bits_per_second: float) -> str:
    if bits_per_second >= 1e9:
        return f"{bits_per_second / 1e9:.1f} Gbps"
    if bits_per_second >= 1e6:
        return f"{bits_per_second / 1e6:.1f} Mbps"
    if bits_per_second >= 1e3:
        return f"{bits_per_second / 1e3:.0f} Kbps"
    return f"{bits_per_second:.0f} bps"


def pid_alive(pid: int | str) -> bool:
    try:
        process_id = int(pid)
    except (TypeError, ValueError):
        return False
    if process_id <= 0:
        return False
    if sys.platform == "win32":
        handle = ctypes.windll.kernel32.OpenProcess(0x00100000, False, process_id)
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(process_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def terminate_process(pid: int | str) -> None:
    try:
        process_id = int(pid)
    except (TypeError, ValueError):
        return
    if process_id <= 0:
        return
    if sys.platform == "win32":
        handle = ctypes.windll.kernel32.OpenProcess(0x0001, False, process_id)
        if handle:
            ctypes.windll.kernel32.TerminateProcess(handle, 1)
            ctypes.windll.kernel32.CloseHandle(handle)
        return
    try:
        os.kill(process_id, signal.SIGTERM)
    except OSError:
        pass


_key_queue: asyncio.Queue | None = None


if sys.platform == "win32":
    import msvcrt

    def start_key_reader() -> None:
        global _key_queue
        loop = asyncio.get_running_loop()
        _key_queue = asyncio.Queue()

        def read_keys() -> None:
            while True:
                try:
                    character = msvcrt.getwch()
                except Exception:
                    break
                if character == "\x1b":
                    loop.call_soon_threadsafe(_key_queue.put_nowait, "esc")
                elif character in "\r\n":
                    loop.call_soon_threadsafe(_key_queue.put_nowait, "enter")
                elif character == "\x08":
                    loop.call_soon_threadsafe(_key_queue.put_nowait, "bs")
                elif character in ("\xe0", "\x00"):
                    second = msvcrt.getwch()
                    arrows = {"H": "up", "P": "down", "K": "left", "M": "right"}
                    loop.call_soon_threadsafe(
                        _key_queue.put_nowait, arrows.get(second, second)
                    )
                elif character.isprintable():
                    loop.call_soon_threadsafe(_key_queue.put_nowait, character)

        threading.Thread(target=read_keys, daemon=True).start()

else:
    import termios
    import tty

    def start_key_reader() -> None:
        global _key_queue
        loop = asyncio.get_running_loop()
        _key_queue = asyncio.Queue()
        descriptor = sys.stdin.fileno()
        original_attributes = termios.tcgetattr(descriptor)
        tty.setraw(descriptor)

        def read_keys() -> None:
            try:
                while True:
                    try:
                        ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                        if not ready:
                            continue
                        character = sys.stdin.read(1)
                    except Exception:
                        break
                    if character == "\x1b":
                        loop.call_soon_threadsafe(
                            _key_queue.put_nowait, read_escape_sequence()
                        )
                    elif character in "\r\n":
                        loop.call_soon_threadsafe(_key_queue.put_nowait, "enter")
                    elif character in ("\x7f", "\x08"):
                        loop.call_soon_threadsafe(_key_queue.put_nowait, "bs")
                    elif character.isprintable():
                        loop.call_soon_threadsafe(_key_queue.put_nowait, character)
            finally:
                termios.tcsetattr(descriptor, termios.TCSADRAIN, original_attributes)

        threading.Thread(target=read_keys, daemon=True).start()

    def read_escape_sequence() -> str:
        ready, _, _ = select.select([sys.stdin], [], [], 0.0)
        if not ready:
            return "esc"
        next_character = sys.stdin.read(1)
        if next_character != "[":
            return "esc"
        sequence = ""
        while True:
            ready, _, _ = select.select([sys.stdin], [], [], 0.0)
            if not ready:
                break
            character = sys.stdin.read(1)
            sequence += character
            if character.isalpha() or character == "~":
                break
        names = {
            "A": "up",
            "B": "down",
            "C": "right",
            "D": "left",
            "H": "home",
            "F": "end",
        }
        return names.get(sequence, "esc")


async def read_key(timeout: float | None = None) -> str | None:
    if _key_queue is None:
        start_key_reader()
    key_task = asyncio.ensure_future(_key_queue.get())
    if timeout is None:
        return await key_task
    sleep_task = asyncio.ensure_future(asyncio.sleep(timeout))
    done, pending = await asyncio.wait(
        [key_task, sleep_task], return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()
    return key_task.result() if key_task in done else None


def build_child_args(config) -> list[str]:
    arguments = [sys.executable, "-m", "torproxy", "--headless", "--child"]
    if config is None:
        return arguments
    arguments += [
        "--port",
        str(config.port),
        "--listen",
        config.listen,
        "--num-circuits",
        str(config.num_circuits),
        "--session-ttl",
        str(config.session_ttl_minutes),
        "--max-clients",
        str(config.max_clients),
        "--max-request-bytes",
        str(config.max_request_bytes),
        "--consensus",
        config.consensus_path,
        "--microdescs",
        config.microdescs_path,
        "--config",
        config.config_path,
    ]
    if config.no_auth:
        arguments.append("--no-auth")
    if config.auth_username is not None:
        arguments += ["--username", config.auth_username]
    if config.auth_password is not None:
        arguments += ["--password", config.auth_password]
    if config.single_guard:
        arguments.append("--single-guard")
    return arguments


def fetch_consensus_counts(config, progress_callback=None) -> tuple[bool, int | None]:
    if config is not None:
        consensus_path = config.consensus_path
        microdescs_path = config.microdescs_path
    else:
        root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        consensus_path = os.path.join(
            root, "shared_cache", "cached-microdesc-consensus"
        )
        microdescs_path = os.path.join(root, "shared_cache", "cached-microdescs")
    if not fetch_fresh_consensus(
        consensus_path, microdescs_path, progress_callback=progress_callback
    ):
        return False, None
    relays = load_relays(consensus_path, microdescs_path)
    exits = [relay for relay in relays if relay.is_exit()]
    return True, len({relay.ip for relay in exits})


def stop_child(child: subprocess.Popen) -> None:
    child.terminate()
    try:
        child.wait(timeout=5)
    except Exception:
        try:
            child.kill()
        except Exception:
            pass


def stop_running_proxy(child, state) -> None:
    if child is not None:
        stop_child(child)
    elif state is not None:
        terminate_process(state["pid"])


def open_save_dialog(filename: str) -> str:
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = filedialog.asksaveasfilename(
            initialfile=filename,
            title="Save Proxy List",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        root.destroy()
        return path if path else ""
    except Exception:
        return ""


def fallback_download_path(filename: str) -> str:
    downloads = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.isdir(downloads):
        downloads = os.getcwd()
    return os.path.join(downloads, filename)


async def choose_generation_mode(height: int, width: int) -> str | None:
    prompt = f"{gray('[R]')} Rotating (new IP each request)    {gray('[S]')} Sticky (same IP per session)"
    sys.stdout.write(move(height // 2, 0) + center(prompt, width))
    sys.stdout.flush()
    while True:
        key = await read_key()
        if key in ("r", "s", "esc"):
            return key


async def choose_ttl(height: int, width: int) -> int | None:
    prompt = f"{gray('Session TTL in minutes? [30] (0 = unlimited)')}"
    sys.stdout.write(move(height // 2 + 1, 0) + center(prompt, width))
    sys.stdout.write(move(height // 2 + 2, 0) + "\033[2K")
    sys.stdout.flush()
    raw_value = ""
    while True:
        key = await read_key()
        if key == "enter":
            return int(raw_value) if raw_value else 30
        if key == "esc":
            return None
        if key == "bs":
            raw_value = raw_value[:-1]
        elif isinstance(key, str) and key.isdigit():
            raw_value += key
        displayed = raw_value or "30"
        sys.stdout.write(
            move(height // 2 + 2, 0) + "\033[2K" + center(displayed, width)
        )
        sys.stdout.flush()


async def choose_count(height: int, width: int, sticky: bool) -> int | None:
    prompt = f"{gray('How many? [100]')}"
    row = height // 2 + (3 if sticky else 1)
    sys.stdout.write(move(row, 0) + center(prompt, width))
    sys.stdout.write(move(row + 1, 0) + "\033[2K")
    sys.stdout.flush()
    raw_value = ""
    while True:
        key = await read_key()
        if key == "enter":
            return int(raw_value) if raw_value else 100
        if key == "esc":
            return None
        if key == "bs":
            raw_value = raw_value[:-1]
        elif isinstance(key, str) and key.isdigit():
            raw_value += key
        displayed = raw_value or "100"
        sys.stdout.write(move(row + 1, 0) + "\033[2K" + center(displayed, width))
        sys.stdout.flush()


def build_proxy_lines(state: dict, mode: str, ttl: int, count: int) -> list[str]:
    host = state.get("host", "127.0.0.1")
    port = state.get("port", 8080)
    username = state.get("username", "")
    password = state.get("password", "")
    no_auth = bool(state.get("no_auth", False))
    proxy_host = host
    if ":" in host and not host.startswith("["):
        proxy_host = f"[{host}]"
    auth_part = (
        ""
        if no_auth or not username
        else f"{quote(username, safe='')}:{quote(password, safe='')}@"
    )
    lines = []
    for _ in range(count):
        if mode == "sticky":
            session_id = uuid.uuid4().hex[:12]
            if no_auth:
                lines.append(
                    f"http://session-{session_id}-time-{ttl}:@{proxy_host}:{port}"
                )
            else:
                sticky_user = f"{username}-session-{session_id}-time-{ttl}"
                lines.append(
                    f"http://{quote(sticky_user, safe='')}:"
                    f"{quote(password, safe='')}@{proxy_host}:{port}"
                )
        else:
            lines.append(f"http://{auth_part}{proxy_host}:{port}")
    return lines


async def generate_proxy_list(state: dict, height: int, width: int) -> str:
    mode = await choose_generation_mode(height, width)
    if mode == "esc":
        return ""
    sticky = mode == "s"
    ttl = 30
    if sticky:
        ttl = await choose_ttl(height, width)
        if ttl is None:
            return ""
    count = await choose_count(height, width, sticky)
    if count is None:
        return ""
    lines = build_proxy_lines(state, mode, ttl, count)
    filename = f"proxies_{uuid.uuid4().hex[:8]}.txt"
    path = await asyncio.get_running_loop().run_in_executor(
        None, open_save_dialog, filename
    )
    if not path:
        path = fallback_download_path(filename)
    with open(path, "w") as stream:
        stream.write("\n".join(lines) + "\n")
    return path


async def run(config=None) -> None:
    enable_windows_terminal()
    sys.stdout.write(HIDE_CURSOR)
    child = None
    child_pid = 0
    started_at = 0.0
    target = 0
    keep_background = False
    launch_message = ""
    metrics = SystemMetrics()
    bandwidth = BandwidthTracker()
    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def request_shutdown(*_) -> None:
        loop.call_soon_threadsafe(shutdown_event.set)

    signal.signal(signal.SIGINT, request_shutdown)
    try:
        signal.signal(signal.SIGTERM, request_shutdown)
    except ValueError:
        pass

    try:
        while True:
            terminal = os.get_terminal_size()
            width = max(terminal.columns, 20)
            height = max(terminal.lines, 10)
            state = read_state_file()
            if state and child is None and not pid_alive(state.get("pid", 0)):
                delete_state_file()
                state = None
            if child is not None and child.poll() is not None:
                child = None
                child_pid = 0
                started_at = 0
                delete_state_file()
                state = None
            now = time.monotonic()
            uptime = now - started_at if started_at else 0
            (ram_total, ram_available, _), process_bytes, cpu_value = metrics.update(
                now
            )
            if state:
                bandwidth_up, bandwidth_down = bandwidth.update(
                    now,
                    state.get("bytes_up", 0),
                    state.get("bytes_down", 0),
                )
            else:
                bandwidth_up, bandwidth_down = bandwidth.labels
            middle = max(height // 2 - 3, 5)
            sys.stdout.write(
                render_dashboard(
                    state,
                    child_pid,
                    target,
                    uptime,
                    ram_total,
                    ram_available,
                    process_bytes,
                    cpu_value,
                    bandwidth_up,
                    bandwidth_down,
                    launch_message,
                    width,
                    height,
                )
            )
            sys.stdout.flush()
            launch_message = ""
            key = await read_key(timeout=1.0)
            if key in (None, "esc"):
                continue
            running = state is not None
            if shutdown_event.is_set():
                shutdown_event.clear()
                if running:
                    shutdown_action = await confirm_shutdown(
                        height, width, "Stop proxy?", "Keep in bg"
                    )
                    if shutdown_action == "stop":
                        stop_running_proxy(child, state)
                        delete_state_file()
                        sys.stdout.write(SHOW_CURSOR)
                        return
                    if shutdown_action == "background":
                        keep_background = True
                        background_pid = child_pid or state.get("pid", 0)
                        await finish_in_background(
                            height, width, background_pid, "Proxy running in bg."
                        )
                        return
                    continue
                break
            if key == "q":
                if running:
                    shutdown_action = await confirm_shutdown(
                        height, width, "Stop proxy and quit?", "Keep in bg"
                    )
                    if shutdown_action == "stop":
                        stop_running_proxy(child, state)
                        delete_state_file()
                        sys.stdout.write(SHOW_CURSOR)
                        return
                    if shutdown_action == "background":
                        keep_background = True
                        background_pid = child_pid or state.get("pid", 0)
                        await finish_in_background(
                            height,
                            width,
                            background_pid,
                            "Proxy running in background.",
                        )
                        return
                    continue
                break
            if key == "l" and not running:
                if target == 0:
                    fetch_started = time.monotonic()
                    progress = ProgressReporter("Fetching consensus...")
                    future = loop.run_in_executor(
                        None, fetch_consensus_counts, config, progress
                    )
                    while not future.done():
                        elapsed = time.monotonic() - fetch_started
                        spinner = "|/-\\"[int(elapsed * 4) % 4]
                        display = cyan(f"{spinner}  {progress.message}")
                        sys.stdout.write(
                            move(middle - 2, 0) + center(display, width) + "\033[K"
                        )
                        sys.stdout.flush()
                        await asyncio.sleep(0.15)
                    try:
                        success, unique_ips = future.result()
                        if success:
                            target = unique_ips
                            launch_message = green(f"Fetched: {target} unique exit IPs")
                        else:
                            launch_message = yellow(
                                "Consensus fetch failed, launching anyway..."
                            )
                    except Exception as error:
                        launch_message = yellow(
                            f"Fetch error: {str(error)[:40]}, launching anyway..."
                        )
                    sys.stdout.write(
                        move(middle - 2, 0) + center(launch_message, width)
                    )
                    sys.stdout.flush()
                    await asyncio.sleep(0.8)
                launch_message = cyan("Building circuits...")
                sys.stdout.write(move(middle - 2, 0) + center(launch_message, width))
                sys.stdout.flush()
                child = subprocess.Popen(
                    build_child_args(config),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                child_pid = child.pid
                started_at = time.monotonic()
                for _ in range(40):
                    await asyncio.sleep(0.5)
                    if child.poll() is not None:
                        launch_message = red("Child process died")
                        child = None
                        child_pid = 0
                        started_at = 0
                        break
                    child_state = read_state_file()
                    if child_state and child_state.get("num_circuits", 0) > 0:
                        break
                else:
                    launch_message = yellow("Still building...")
            if key == "g":
                if state is None:
                    launch_message = red("Launch the proxy before generating a list")
                    continue
                saved_path = await generate_proxy_list(state, height, width)
                if saved_path:
                    launch_message = green(f"Saved: {saved_path}")
            if key == "t" and running:
                stop_running_proxy(child, state)
                child = None
                child_pid = 0
                started_at = 0
                target = 0
                delete_state_file()
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write(SHOW_CURSOR + "\n")
        if child and not keep_background:
            stop_child(child)
        if not keep_background:
            delete_state_file()
        sys.stdout.write("\n")
        sys.stdout.flush()


async def confirm_shutdown(
    height: int, width: int, question: str, background_label: str
) -> str | None:
    prompt = (
        f"{yellow(question)}  {dark('[Y]')} Stop   {dark('[N]')} {background_label}   "
        f"{dark('[Esc]')} Cancel"
    )
    sys.stdout.write(move(height // 2, 0) + center(prompt, width))
    sys.stdout.flush()
    for _ in range(8):
        key = await read_key()
        if key in ("esc", None):
            return "cancel"
        if key == "y":
            return "stop"
        if key == "n":
            return "background"
    return "cancel"


if __name__ == "__main__":
    asyncio.run(run())
