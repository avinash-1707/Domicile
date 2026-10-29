# domicile

Give your VPS agents a home-network exit. domicile routes selected domains through your own residential connection and verifies the exit IP and leaks.

> Status: early development. Every command below works, but there is no tagged release yet and flags may still change.

## Why

Agents that run around the clock on a VPS browse from a datacenter IP. Many sites score the IP's network before they look at the browser, so a script that works on your laptop gets CAPTCHAs, 403s or refused logins from the VPS. Patching the browser fingerprint does not help, because the decision is made at the network layer.

domicile lets the agent use a connection you already have. A small agent on a device at home (a Raspberry Pi, an old laptop, a machine at a relative's place, with their consent) dials out to your VPS. A proxy on the VPS sends only the domains you choose through that device. Everything else, including LLM API calls, git and SSH, goes out directly as before.

```
agent browser → domicile on the VPS → rule matches? → tunnel → your home device → site
                                    → no match      → direct from the VPS
```

## Install

Linux and macOS, amd64 and arm64, on both machines:

```sh
curl -fsSL https://raw.githubusercontent.com/avinash-1707/domicile/main/install.sh | sh
```

The script downloads the latest release binary, checks it against the release's `SHA256SUMS` and installs it to `/usr/local/bin` (set `DOMICILE_BIN_DIR` to change that). It asks before using sudo. On Linux it offers to raise the UDP buffer limits QUIC needs. Until the first release is tagged, build from source with Go 1.26: `go build ./cmd/domicile`.

## Usage

On the VPS:

```sh
domicile init -public-addr vps.example.com:443   # creates state and prints your proxy URL
domicile add home                                # prints a one-time join command
domicile rule add reddit.com -via home
domicile server
```

On the home device, paste the join command `add` printed:

```sh
domicile agent join dj1.…
```

Or install and pair in one step, which also offers to set it up as a service:

```sh
curl -fsSL https://raw.githubusercontent.com/avinash-1707/domicile/main/install.sh | sh -s -- join dj1.…
```

To keep either side running across reboots, install it as a service. On Linux this writes a hardened systemd unit that runs as your user (run it with sudo); on macOS it writes a launchd agent:

```sh
sudo domicile service install server     # on the VPS
domicile service install agent           # on the home device; sudo on Linux
```

`-print` shows the unit and the commands without changing anything, and `service uninstall` removes it. A device whose credential was revoked stops instead of retrying.

Point your agent's tools at the proxy, each with its own credential:

```sh
domicile connect playwright-mcp     # updates .mcp.json, or prints the `claude mcp add` command
domicile connect agent-browser      # sets the proxy in ~/.agent-browser/config.json
domicile connect shell              # prints ALL_PROXY / HTTPS_PROXY exports
domicile run -- node agent.js       # any command; Node's fetch needs Node 22.21+ or 24+
```

`connect <tool> -undo` restores the tool's file and revokes its credential. Anything else can use the proxy URL `init` printed (`socks5h://agent:…@127.0.0.1:1080`). Domains with a rule go out through home; everything else goes direct from the VPS. `domicile remove home` revokes the device; the server disconnects it within a second.

Rule changes apply to a running server within a second. See what is connected and which rules are active:

```sh
domicile status          # add -json for scripts
```

Check what sites see through each exit (run on the VPS while the server runs):

```sh
domicile verify          # add -json for scripts; exits non-zero if a check fails
```


`verify` checks what a site actually sees through each exit:

- the public IP, compared with the VPS's own IP
- whether that IP looks residential or datacenter (a best-effort hint)
- whether DNS was resolved on the home side
- whether the browser timezone matches the exit's location
- tunnel latency and connection health

It prints a table, supports `--json`, and exits non-zero when a check fails.

## How it works

- The home agent dials out to the VPS, so you open no ports at home.
- The VPS runs one local proxy port that speaks SOCKS5 and HTTP CONNECT, bound to `127.0.0.1` and protected by credentials.
- Rules match domains and their subdomains. No match means the traffic goes direct.
- If the home device is offline, matched traffic fails closed by default instead of silently using the datacenter IP. You can allow a direct fallback per rule.
- The home agent refuses to connect to private, loopback, link-local and cloud-metadata addresses, so an agent on the VPS cannot reach your router or other devices on your LAN. The check runs on the resolved address, so DNS tricks do not get around it, and it also covers the device's own networks (including IPv6 global addresses) and your public address, which on many lines is the router itself. `domicile agent -allow 192.168.1.50` opens a specific device if you want one reachable.
- DNS for routed domains is resolved on the home device.
- domicile does not intercept TLS, so it sees the hostnames you connect to and never the page content.

## Integrations

Most agent browser tools already accept a proxy. `domicile connect` writes the setting for you and can undo it.

| Tool | How |
|---|---|
| Playwright MCP | `domicile connect playwright-mcp` |
| agent-browser | `domicile connect agent-browser` |
| curl, Python, Go, most CLIs | `domicile connect shell` prints the `ALL_PROXY` / `HTTPS_PROXY` exports |
| Anything else | `domicile run -- <command>`, which also covers Node's built-in `fetch` |

An MCP server (`domicile mcp`, add it to your agent's MCP config) lets an agent check which exit it is on, run `verify`, and report a site that blocked it. Reports become suggested `domicile rule add` commands; the agent cannot change routing. Only you can add rules.

## Who this is for

domicile is free for solo developers who already have a device on a residential connection. It does not create IPs.

It works well when:

- your agent uses your own accounts at low volume (reading pages, logging in, scheduled checks)
- one stable IP is enough; a personal home IP is often cleaner than a shared proxy pool

You still need a paid proxy if you need rotating IPs, high volume, IPs in countries where you have no device, or you have no residential connection. domicile will not add rotation or pooling.

## Limitations

- A residential IP fixes IP reputation only. Browser fingerprint, TLS fingerprint, behavior and per-account rate limits are separate problems.
- Your home IP becomes associated with your agent's activity.
- Results depend on your ISP and your IP's history.
- Hosted cloud browsers (Browser Use Cloud, Browserbase and similar) are not supported in v1.

Use your own connection for your own agents. domicile is not meant for large-scale scraping, account creation or getting around a platform's rules.

## License

To be decided.
