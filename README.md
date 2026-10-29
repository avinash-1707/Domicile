<p align="center">
  <img src=".github/assets/banner.webp" alt="A server in a datacenter sends most traffic straight to websites, while one route runs through a tunnel to a small device in a house and reaches its website from there." width="100%">
</p>

<h1 align="center">domicile</h1>

<p align="center">
  Give your VPS agents a home-network exit. domicile sends the domains you choose through your own residential connection and checks what sites see on the other end.
</p>

<p align="center">
  <a href="https://github.com/avinash-1707/Domicile/releases/latest"><img src="https://img.shields.io/github/v/release/avinash-1707/Domicile" alt="Latest release"></a>
  <a href="https://github.com/avinash-1707/Domicile/actions/workflows/ci.yml"><img src="https://github.com/avinash-1707/Domicile/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/avinash-1707/Domicile" alt="Go version">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey" alt="Platforms: Linux and macOS">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/avinash-1707/Domicile" alt="License: Apache-2.0"></a>
</p>

## Why

Agents that run around the clock on a VPS browse from a datacenter IP. Many sites score the IP's network before they look at the browser, so a script that works on your laptop gets CAPTCHAs, 403s or refused logins from the VPS. Patching the browser fingerprint does not help when the decision is made at the network layer.

domicile lets the agent use a connection you already have. A small agent on a device at home (a Raspberry Pi, an old laptop, a machine at a relative's place, with their consent) dials out to your VPS. A proxy on the VPS sends only the domains you choose through that device. Everything else, including LLM API calls, git and SSH, goes out directly as before.

```
agent browser → domicile on the VPS → rule matches? → tunnel → your home device → site
                                    → no match      → direct from the VPS
```

## How it works

The home agent opens a QUIC connection to the VPS and pins the server's certificate fingerprint from the join code. On the VPS, a local proxy port speaks SOCKS5 and HTTP CONNECT and also forwards plain HTTP. It is bound to `127.0.0.1` and requires a credential. Each connection's destination is matched against your rules. A matched connection becomes a stream on the tunnel, and the home agent resolves the name and connects to the site, so DNS for routed domains is resolved at home too. Unmatched connections are dialled directly from the VPS.

domicile does not intercept TLS. It sees the hostnames you connect to and never the page content.

## Who this is for

domicile is free for solo developers who already have a device on a residential connection. It does not create IPs.

It works well when your agent uses your own accounts at low volume (reading pages, logging in, scheduled checks) and one stable IP is enough. A personal home IP is often cleaner than a shared proxy pool.

You still need a paid proxy for rotating IPs, high volume or IPs in countries where you have no device, or if you have no residential connection. domicile will not add rotation or pooling.

## Limitations

- A residential IP fixes IP reputation only. Browser fingerprint, TLS fingerprint, behavior and per-account rate limits are separate problems.
- Your home IP becomes associated with your agent's activity.
- Results depend on your ISP and your IP's history.
- Hosted cloud browsers (Browser Use Cloud, Browserbase and similar) are not supported in v1.
- Windows is not supported.

Use your own connection for your own agents. domicile is not meant for large-scale scraping, account creation or getting around a platform's rules.

## Requirements

- A VPS running Linux or macOS, where your agent runs. Exits reach it on UDP port 443 by default, so open that port in its firewall or security group.
- A device at home running Linux or macOS that stays on, such as a Raspberry Pi or an old laptop. It dials out, so you open no ports at home.
- Both machines on amd64 or arm64.

## Install

Run this on both the VPS and the home device:

```sh
curl -fsSL https://raw.githubusercontent.com/avinash-1707/domicile/main/install.sh | sh
```

The script downloads the latest release binary, checks it against the release's `SHA256SUMS` and installs it to `/usr/local/bin`. It asks before using sudo, and on Linux it offers to raise the UDP buffer limits that QUIC needs.

| Variable | Effect |
|---|---|
| `DOMICILE_BIN_DIR` | Install somewhere other than `/usr/local/bin` |
| `DOMICILE_YES=1` | Answer yes to every question, for unattended installs |

With Go 1.26.5 or later you can install it with `go install` instead:

```sh
go install github.com/avinash-1707/domicile/cmd/domicile@latest
```

domicile follows semantic versioning. Before 1.0, a minor release may change flags or file formats.

## Quick start

### 1. Set up the VPS

Create the server state, pair a device, add a rule and start the server:

```sh
domicile init -public-addr vps.example.com:443   # prints your proxy URL and password, once
domicile add home                                # prints a one-time join code
domicile rule add reddit.com -via home
domicile server
```

### 2. Pair the home device

Paste the join code that `add` printed:

```sh
domicile agent join dj1.…
```

You can also install and pair in one step. The script then offers to set the agent up as a service:

```sh
curl -fsSL https://raw.githubusercontent.com/avinash-1707/domicile/main/install.sh | sh -s -- join dj1.…
```

### 3. Check the exit

Back on the VPS, confirm the device is connected and see what sites see through it:

```sh
domicile status
domicile verify
```

### 4. Point your agent at the proxy

Use the proxy URL `init` printed (`socks5h://agent:…@127.0.0.1:1080`, or the same with `http://`), or let `domicile connect` configure your tools (see below). Requests to reddit.com now leave through your home connection, and everything else leaves from the VPS.

## Run as a service

To keep both sides running across reboots, install them as services:

```sh
sudo domicile service install server     # on the VPS
domicile service install agent           # on the home device (sudo on Linux)
```

On Linux this writes a hardened systemd unit that runs domicile as your user, never as root. Only the server gets an extra permission, the one it needs to bind port 443. On macOS it writes a launchd agent in `~/Library/LaunchAgents`.

`-print` shows the unit and the commands without changing anything, and `domicile service uninstall server|agent` removes it. If the server revokes a device, the agent stops instead of retrying in a loop.

## Connect your agent's tools

Most agent browser tools already accept a proxy. `domicile connect` writes the setting for you, gives each tool its own proxy credential, and can undo the change.

| Tool | Command | What it does |
|---|---|---|
| Playwright MCP | `domicile connect playwright-mcp` | Writes a Playwright config with the proxy and prints the `claude mcp add` command; `-file .mcp.json` edits an MCP client file instead |
| agent-browser | `domicile connect agent-browser` | Sets the proxy in `~/.agent-browser/config.json` |
| curl, Python, Go, most CLIs | `domicile connect shell` | Prints `ALL_PROXY` / `HTTPS_PROXY` exports |
| Anything else | `domicile run -- <command>` | Runs the command with the proxy in its environment, including Node's built-in `fetch` (Node 22.21+ or 24+) |

`domicile connect <tool> -undo` restores the tool's file byte for byte and revokes its credential.

### MCP server

`domicile mcp` is a stdio MCP server with four read-only tools. Through it an agent can check which exit it is on, run `verify`, list blocked hosts and report a site that blocked it. A report becomes a suggested `domicile rule add` command for you to run; the agent itself cannot change routing. To add it to Claude Code on the VPS:

```sh
claude mcp add domicile -- domicile mcp
```

## Rules

A rule sends a domain and its subdomains through an exit. The first matching rule wins, and a domain with no rule goes direct from the VPS.

```sh
domicile rule add reddit.com -via home                  # reddit.com and *.reddit.com
domicile rule add login.example.com -via home -exact    # only this name
domicile rule add example.org -via home -fallback-direct -note "public pages only"
domicile rule list
domicile rule remove reddit.com
```

When the exit is offline, matched traffic is refused by default so it never leaves from the datacenter IP by accident. `-fallback-direct` lets that rule go direct instead.

Rules live in `domicile.json` in the state directory. A running server picks up changes within a second. If the file becomes unreadable or names an exit that does not exist, the server keeps the last good rules and `status` shows the error.

## Checking the exit

Run `domicile verify` on the VPS while the server is running. For each exit it reports:

- the public IP sites see, compared with the VPS's own IP
- whether that IP's network is listed as residential, hosting or proxy (a best-effort hint from ip-api.com)
- whether DNS for routed domains is resolved on the home side
- the exit's timezone, so you can launch browsers with a matching one
- how long the first request through the tunnel took

It prints a table, or JSON with `-json`. `-exit <name>` checks one exit. It exits 0 when every check passes and 1 when one fails, so it works in scripts and health checks.

`domicile status` shows the connected exits, the server's addresses and fingerprint, and the active rules, also with `-json`.

## Security

- The home agent refuses to connect to private, loopback, link-local and cloud-metadata addresses, so an agent on the VPS cannot reach your router or other devices on your LAN. The check runs on the resolved address, so DNS tricks do not get around it. It also covers the device's own networks (including IPv6 global addresses) and your public address, which on many connections is the router itself. `domicile agent -allow 192.168.1.50` opens a specific address if you want one reachable.
- The proxy listens on loopback only and every client needs a credential. Each connected tool gets its own, so you can revoke one without touching the others.
- Join codes work once and expire. domicile generates every secret itself and stores only their hashes.
- Agents get read-only tools. Only you can add rules.
- `domicile remove <exit>` revokes a device, and the server disconnects it within a second.

## Reference

### Commands

| Command | Where | Description |
|---|---|---|
| `domicile init [-public-addr host:port]` | VPS | Create state, the server certificate and the first proxy user |
| `domicile add <exit>` | VPS | Print a one-time join code for a home device |
| `domicile remove <exit>` | VPS | Revoke an exit; the server disconnects it within a second |
| `domicile user add\|remove\|list` | VPS | Manage proxy users |
| `domicile rule add\|remove\|list` | VPS | Manage routing rules |
| `domicile server` | VPS | Run the server and the local proxy |
| `domicile status [-json]` | VPS | Show exits, connections and active rules |
| `domicile verify [-exit name] [-json]` | VPS | Check what sites see through each exit |
| `domicile connect <tool> [-undo]` | VPS | Point a tool at the proxy |
| `domicile run -- <command>` | VPS | Run a command with the proxy in its environment |
| `domicile mcp` | VPS | Read-only MCP tools for agents, over stdio |
| `domicile agent join <code>` | Home | Pair with the server, then run |
| `domicile agent [-allow ip,...]` | Home | Run the exit after pairing |
| `domicile service install\|uninstall server\|agent` | Both | Run under systemd (Linux) or launchd (macOS) |
| `domicile version` | Both | Print the version |

Run `domicile <command> -h` for a command's flags.

### Files

Everything lives in the state directory, `~/.local/state/domicile` by default (`$XDG_STATE_HOME/domicile` when that is set). Every command takes `-state-dir` to use another one.

| File | Side | Contents |
|---|---|---|
| `state.json` | VPS | Exits and proxy users, stored as hashes of their secrets |
| `server.crt`, `server.key` | VPS | The server's TLS certificate, pinned by every exit |
| `domicile.json` | VPS | Routing rules |
| `control.sock` | VPS | Local socket that `status`, `verify` and `mcp` talk to |
| `agent.json` | Home | This device's credential and the server's fingerprint |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error, or a `verify` check failed |
| 2 | Bad command or flags |
| 3 | `verify` could not run |
| 4 | The agent's credential was revoked or its join code was already used |

## Building from source

You need Go 1.26.5 or later.

```sh
git clone https://github.com/avinash-1707/domicile.git
cd domicile
go build -o domicile ./cmd/domicile
go test -race ./...
```

## License

[Apache-2.0](LICENSE)
