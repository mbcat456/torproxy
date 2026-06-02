import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Optional

from .cells import DEFAULT_MAX_CLIENTS, DEFAULT_MAX_REQUEST_BYTES

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_PACKAGE_DIR)
DEFAULT_CONSENSUS_PATH = os.path.join(_PROJECT_DIR, "shared_cache", "cached-microdesc-consensus")
DEFAULT_MICRODESCS_PATH = os.path.join(_PROJECT_DIR, "shared_cache", "cached-microdescs")
DEFAULT_CONFIG_PATH = os.path.join(os.getcwd(), "config.json")


@dataclass
class Config:
    port: int = 8080
    listen: str = "127.0.0.1"
    max_clients: int = DEFAULT_MAX_CLIENTS
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES

    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    no_auth: bool = False

    headless: bool = False
    child: bool = False

    num_circuits: int = 0
    single_guard: bool = False
    consensus_path: str = DEFAULT_CONSENSUS_PATH
    microdescs_path: str = DEFAULT_MICRODESCS_PATH

    session_ttl_minutes: int = 30

    verbose: bool = False
    debug: bool = False

    config_path: str = DEFAULT_CONFIG_PATH


def _load_config_file(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except (json.JSONDecodeError, IOError):
        return {}


def _apply_config_file(cfg: Config, data: dict) -> None:
    proxy = data.get("proxy", {})
    if isinstance(proxy, dict):
        if "port" in proxy: cfg.port = proxy["port"]
        if "listen" in proxy: cfg.listen = proxy["listen"]
        if "max_clients" in proxy: cfg.max_clients = proxy["max_clients"]
        if "max_request_bytes" in proxy: cfg.max_request_bytes = proxy["max_request_bytes"]

    auth = data.get("auth", {})
    if isinstance(auth, dict):
        if "username" in auth and auth["username"] is not None:
            cfg.auth_username = auth["username"]
        if "password" in auth and auth["password"] is not None:
            cfg.auth_password = auth["password"]
        if "no_auth" in auth:
            cfg.no_auth = auth["no_auth"]

    tor = data.get("tor", {})
    if isinstance(tor, dict):
        if "num_circuits" in tor: cfg.num_circuits = tor["num_circuits"]
        if "single_guard" in tor: cfg.single_guard = tor["single_guard"]
        if tor.get("consensus_path") is not None:
            cfg.consensus_path = tor["consensus_path"]
        if tor.get("microdescs_path") is not None:
            cfg.microdescs_path = tor["microdescs_path"]

    session = data.get("session", {})
    if isinstance(session, dict):
        if "default_ttl_minutes" in session:
            try:
                ttl = int(session["default_ttl_minutes"])
                if ttl > 0:
                    cfg.session_ttl_minutes = ttl
            except (ValueError, TypeError):
                pass


def load_config(argv: Optional[list] = None) -> Config:
    if argv is None:
        argv = sys.argv[1:]

    cfg = Config()

    p = argparse.ArgumentParser(
        prog="torproxy",
        description="Pure-Python Tor HTTP forward proxy",
    )
    p.add_argument("-n", "--num-circuits", type=int, default=0,
                   help="Circuits to build (0 = all available exit IPs, no cap)")
    p.add_argument("--port", type=int, default=8080,
                   help="Proxy listen port (default: 8080)")
    p.add_argument("--listen", type=str, default="127.0.0.1",
                   help="Proxy listen address (default: 127.0.0.1)")
    p.add_argument("--max-clients", type=int, default=DEFAULT_MAX_CLIENTS,
                   help="Max concurrent client connections")
    p.add_argument("--max-request-bytes", type=int, default=DEFAULT_MAX_REQUEST_BYTES,
                   help="Max HTTP request body size in bytes")
    p.add_argument("--consensus", type=str, default=DEFAULT_CONSENSUS_PATH,
                   help="Path to Tor cached-microdesc-consensus file")
    p.add_argument("--microdescs", type=str, default=DEFAULT_MICRODESCS_PATH,
                   help="Path to Tor cached-microdescs file")
    p.add_argument("--config", type=str, default=DEFAULT_CONFIG_PATH,
                   help="Path to config.json (default: ./config.json)")
    p.add_argument("--session-ttl", type=int, default=None,
                   help="Session TTL in minutes (default: 30)")
    p.add_argument("--username", type=str, default=None,
                   help="Proxy auth username (generated if not set)")
    p.add_argument("--password", type=str, default=None,
                   help="Proxy auth password (generated if not set)")
    p.add_argument("--no-auth", action="store_true",
                   help="Disable proxy authentication (open proxy)")
    p.add_argument("--headless", action="store_true",
                   help="Run proxy directly without the interactive CLI")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug logging for torproxy")
    p.add_argument("--debug", action="store_true",
                   help="Enable debug logging for all modules")
    p.add_argument("--single-guard", action="store_true",
                   help="Use one guard connection for all circuits")
    p.add_argument("--child", action="store_true",
                   help=argparse.SUPPRESS)

    args = p.parse_args(argv)

    config_data = _load_config_file(args.config)
    if config_data:
        _apply_config_file(cfg, config_data)

    if args.port != 8080: cfg.port = args.port
    if args.listen != "127.0.0.1": cfg.listen = args.listen
    if args.max_clients != DEFAULT_MAX_CLIENTS: cfg.max_clients = args.max_clients
    if args.max_request_bytes != DEFAULT_MAX_REQUEST_BYTES: cfg.max_request_bytes = args.max_request_bytes
    if args.num_circuits != 0: cfg.num_circuits = args.num_circuits
    if args.single_guard: cfg.single_guard = True
    if args.headless: cfg.headless = True
    if args.child: cfg.child = True
    if args.verbose: cfg.verbose = True
    if args.debug: cfg.debug = True
    if args.no_auth: cfg.no_auth = True
    if args.username is not None: cfg.auth_username = args.username
    if args.password is not None: cfg.auth_password = args.password
    if args.session_ttl is not None: cfg.session_ttl_minutes = args.session_ttl
    if args.consensus != DEFAULT_CONSENSUS_PATH: cfg.consensus_path = args.consensus
    if args.microdescs != DEFAULT_MICRODESCS_PATH: cfg.microdescs_path = args.microdescs
    if args.config != DEFAULT_CONFIG_PATH: cfg.config_path = args.config

    return cfg
