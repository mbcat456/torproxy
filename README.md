# TorProxy

A pure Python Tor HTTP forward proxy that builds circuits through the Tor network and exposes them as an HTTP proxy on your machine. Every request exits through a different Tor circuit, giving each connection a fresh IP address.

## How it works

TorProxy connects to Tor guard relays directly over TLS, performs the full Tor link handshake (VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO), then builds 3 hop circuits (guard, middle, exit) using the ntor handshake. Each circuit tunnels HTTP and HTTPS traffic through RELAY cells encrypted in AES 128 CTR with per hop key material.

The proxy pool maintains hundreds of independent circuits, each with its own TLS connection to a different guard relay. A background maintainer health checks circuits every 60 seconds, replaces dead ones, and refreshes the consensus every 10 minutes.

## Installation

```
pip install cryptography psutil
git clone https://github.com/mbcat456/tor-proxy
cd torproxy
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
    "listen": "127.0.0.1"
  },
  "auth": {
    "username": "myuser",
    "password": "mypass"
  },
  "tor": {
    "num_circuits": 0
  }
}
```

Set `num_circuits` to 0 for no cap (one circuit per unique exit IP). All config values can be overridden by CLI arguments. Run `python -m torproxy --help` for the full list.

### Command line arguments

| Flag | Default | Description |
|---|---|---|
| `--port` | 8080 | Proxy listen port |
| `--listen` | 127.0.0.1 | Proxy listen address |
| `--username` | auto | Proxy auth username |
| `--password` | auto | Proxy auth password |
| `--no-auth` | false | Disable proxy authentication |
| `-n`, `--num-circuits` | 0 | Circuits to build (0 = all available exit IPs, no cap) |
| `--headless` | false | Run without interactive TUI |

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

The terminal UI uses raw ANSI escape codes with cross platform keyboard input (msvcrt on Windows, termios on Linux). The entire interface lives in `cli/torproxy_.py`.

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
    state.py        State file writer for background proxy process
    terminal.py     Windows ANSI escape code enable
    torproxy_.py    Full screen heads up display terminal interface
```

## Requirements

Python 3.10 or later. The only required packages are `cryptography` (for X25519 key exchange and AES CTR) and `psutil` (for system resource monitoring). Everything else is standard library.
