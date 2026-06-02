import logging
import sys

log = logging.getLogger("torproxy")

_GREY = "\033[90m"
_RESET = "\033[0m"


class _ColorFormatter(logging.Formatter):

    def format(self, record: logging.LogRecord) -> str:
        ts = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        level = record.levelname
        msg = record.getMessage()
        return f"{_GREY}{ts} [{level}] {record.name}:{_RESET} {msg}"


_console_handler: logging.Handler = None
_file_handler: logging.Handler = None


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    global _console_handler
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    root.handlers.clear()

    _console_handler = logging.StreamHandler(sys.stdout)
    _console_handler.setLevel(logging.DEBUG if debug else (logging.DEBUG if verbose else logging.INFO))
    _console_handler.setFormatter(_ColorFormatter())
    root.addHandler(_console_handler)


def enable_file_log(path: str) -> None:
    global _file_handler
    _file_handler = logging.FileHandler(path, encoding="utf-8")
    _file_handler.setLevel(logging.DEBUG)
    _file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    logging.getLogger().addHandler(_file_handler)


def suppress_console() -> None:
    if _console_handler:
        _console_handler.setLevel(logging.WARNING)


