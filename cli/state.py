import datetime
import json
import os
import tempfile


def _state_file_path() -> str:
    return os.path.join(tempfile.gettempdir(), "torproxy_state.json")


def write_state_file(
    pid: int,
    port: int,
    host: str,
    username: str,
    password: str,
    no_auth: bool,
    config_path: str,
    num_circuits: int,
    bytes_up: int = 0,
    bytes_down: int = 0,
) -> str:
    state = {
        "pid": pid,
        "port": port,
        "host": host,
        "username": username,
        "password": password,
        "no_auth": no_auth,
        "config_path": config_path,
        "started_at": datetime.datetime.now().isoformat(),
        "num_circuits": num_circuits,
        "bytes_up": bytes_up,
        "bytes_down": bytes_down,
    }
    path = _state_file_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    return path


def delete_state_file() -> None:
    path = _state_file_path()
    try:
        os.remove(path)
    except OSError:
        pass
