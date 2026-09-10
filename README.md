# TorProxy

A lightweight pure Python Tor HTTP forward proxy that builds circuits through the Tor network and exposes them as an HTTP proxy on your machine. Every request exits through a different Tor circuit, giving each connection a fresh IP address (on a best effort basis when using rotating proxy mode, as the tor exit ip pool is of around 1.1k-1.2k ip addresses).

## How it works

TorProxy connects to Tor guard relays directly over TLS, performs the full Tor link handshake (VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO), then builds 3 hop circuits (guard, middle, exit) using the ntor handshake. Each circuit tunnels HTTP and HTTPS traffic through RELAY cells encrypted in AES 128 CTR with per hop key material.

The proxy pool maintains hundreds of independent circuits, each with its own TLS connection to a different guard relay. A background maintainer health checks circuits every 60 seconds, replaces dead ones, and refreshes the consensus every 10 minutes.

## Installation

```
git clone https://github.com/mbcat456/torproxy
cd torproxy
python -m pip install -r requirements.txt
```

## Usage

Launch the interactive terminal UI:

```
python -m torproxy
```

This opens a full screen heads up display showing CPU usage, RAM, circuit count, traffic bandwidth, and uptime. From here you can launch the proxy pool, generate proxy lists, and terminate circuits.

### Headless mode

Run without the interactive UI, useful for servers or background use:

```
python -m torproxy --headless
```

Prints credentials to stdout and runs indefinitely. Press Ctrl+C to stop.

### Configuration

Optionally create a `config.json` in the folder you run torproxy from (your current working directory):

```json
{
  "proxy": {
    "port": 8080,
    "listen": "127.0.0.1",
    "max_clients": 5000,
    "max_request_bytes": 2097152
  },
  "auth": {
    "username": "myuser",
    "password": "mypass",
    "no_auth": false
  },
  "tor": {
    "num_circuits": 0,
    "single_guard": false,
    "consensus_path": "shared_cache/cached-microdesc-consensus",
    "microdescs_path": "shared_cache/cached-microdescs"
  },
  "session": {
    "default_ttl_minutes": 30
  }
}
```

Set `num_circuits` to 0 to build one circuit per available unique exit IP. All config values can be overridden by CLI arguments. Run `python -m torproxy --help` for the full list.

### Command line arguments

| Flag | Default | Description |
|---|---|---|
| `-n`, `--num-circuits` | 0 | Circuits to build (0 = all available exit IPs) |
| `--port` | 8080 | Proxy listen port |
| `--listen` | 127.0.0.1 | Proxy listen address |
| `--max-clients` | 5000 | Maximum concurrent client connections |
| `--max-request-bytes` | 2097152 | Maximum HTTP request body size in bytes |
| `--session-ttl` | 30 | Default sticky session TTL in minutes (0 = unlimited) |
| `--consensus` | shared cache | Path to the Tor consensus file |
| `--microdescs` | shared cache | Path to the Tor microdescriptors file |
| `--config` | ./config.json | Path to the JSON configuration file |
| `--username` | auto | Proxy auth username |
| `--password` | auto | Proxy auth password |
| `--no-auth` | false | Disable proxy authentication |
| `--headless` | false | Run without interactive TUI |
| `--single-guard` | false | Reuse one guard connection for all circuits |
| `-v`, `--verbose` | false | Enable verbose logging |
| `--debug` | false | Enable debug logging for all modules |

## Using the proxy

Press G in the TUI to generate a proxy list. Each line is a ready to use proxy URL.

Rotating mode: every line is identical. Each request gets a new Tor exit IP.

```
http://username:password@127.0.0.1:8080
```

Sticky mode: each line has a unique session ID and time (in minutes) that that session should last baked into the username. The proxy binds that session to a dedicated circuit, so every request using that line exits through the same IP.

```
http://username-session-a1b2c3-time-30:password@127.0.0.1:8080
http://username-session-d4e5f6-time-30:password@127.0.0.1:8080
```

Plug any line directly into your HTTP client as the proxy setting. The credentials are printed on launch.

## How the TUI works

The terminal UI uses raw ANSI escape codes with cross platform keyboard input (msvcrt on Windows, termios on Linux). The interface lives in `torproxy/cli/torproxy_.py`.

Keys in the TUI:

| Key | Action |
|---|---|
| L | Launch the proxy pool |
| G | Generate a proxy list file |
| T | Terminate the running proxy |
| Q | Quit |

On launch, TorProxy fetches a fresh Tor consensus from directory mirrors, counts the available unique exit IPs, then spawns a child process that builds circuits in the background. The parent process reads circuit count, bandwidth, and uptime from a shared state file.

## Project structure

```
torproxy/
  torproxy/
    __init__.py       Package init, version string
    __main__.py       Entry point, CLI argument routing, child process management
    auth.py           Basic auth credential generation and validation
    cells.py          Tor cell protocol constants and packing helpers
    circuit.py        3 hop circuit construction, stream dispatch, TLS tunneling
    config.py         CLI argument parsing and config.json merging
    connection.py     TLS connection to Tor relays with cell level I/O
    consensus.py      Tor consensus and microdescriptor parsing and fetching
    crypto.py         ntor handshake, HKDF, AES 128 CTR per hop relay crypto
    log.py            Colored console and file logging
    pool.py           Circuit pool with health checking and background maintenance
    proxy.py          HTTP forward proxy handler (CONNECT tunnel and HTTP)
    session.py        Session ID to circuit binding with TTL expiry
    cli/
      __init__.py
      state.py        State file reader and writer for the background proxy process
      terminal.py     Windows ANSI escape code enable
      torproxy_.py    Full screen heads up display terminal interface
  tests/
    test_circuit.py
    test_cli.py
    test_crypto.py
    test_http_proxy_features.py
    test_pool.py
    test_proxy.py
  scripts/
    check_pool.py
    pool_capacity_test.py
    smoke_large.py
    smoke_live.py
    stability_monitor.py
  pyproject.toml
  requirements.txt
  README.md
```

The package lives in the nested `torproxy/` directory. Run the proxy from the
repository root with `python -m torproxy`.

## Requirements

Python 3.10 or later. The only required packages are `cryptography` (for X25519 key exchange and AES CTR) and `psutil` (for system resource monitoring). Everything else is standard library.

## Development

Install the optional development tools:

```
python -m pip install pytest ruff
```

Run the test suite and static checks from the repository root:

```
python -m pytest -q
python -m ruff check torproxy tests scripts
python -m ruff format --check torproxy tests scripts
```
