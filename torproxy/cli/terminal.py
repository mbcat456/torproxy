import ctypes
import sys

VIRTUAL_TERMINAL_PROCESSING = 0x0004
QUICK_EDIT_MODE = 0x0040
STANDARD_OUTPUT_HANDLE = -11


def enable_windows_ansi() -> None:
    if sys.platform != "win32":
        return
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(STANDARD_OUTPUT_HANDLE)
    mode = ctypes.c_ulong()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        kernel32.SetConsoleMode(handle, mode.value | VIRTUAL_TERMINAL_PROCESSING)


def enable_windows_terminal() -> None:
    if sys.platform != "win32":
        return
    enable_windows_ansi()
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(STANDARD_OUTPUT_HANDLE)
    mode = ctypes.c_ulong()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        kernel32.SetConsoleMode(
            handle,
            (mode.value | VIRTUAL_TERMINAL_PROCESSING) & ~QUICK_EDIT_MODE,
        )


enable_windows_ansi()

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
