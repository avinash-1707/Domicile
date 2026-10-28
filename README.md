# domicile

Give your VPS agents a home-network exit. domicile routes selected domains through your own residential connection and verifies the exit IP and leaks.

> Status: early development. Nothing here is usable yet. The commands below describe the planned v1 and will change.

## Why

Agents that run around the clock on a VPS browse from a datacenter IP. Many sites score the IP's network before they look at the browser, so a script that works on your laptop gets CAPTCHAs, 403s or refused logins from the VPS. Patching the browser fingerprint does not help, because the decision is made at the network layer.

domicile lets the agent use a connection you already have. A small agent on a device at home (a Raspberry Pi, an old laptop, a machine at a relative's place, with their consent) dials out to your VPS. A proxy on the VPS sends only the domains you choose through that device. Everything else, including LLM API calls, git and SSH, goes out directly as before.

```
agent browser → domicile on the VPS → rule matches? → tunnel → your home device → site
                                    → no match      → direct from the VPS
```

## Planned usage

On the VPS:

```sh
curl -fsSL https://raw.githubusercontent.com/avinash-1707/domicile/main/install.sh | sh
domicile init                 # starts the server, prints a one-line join command
```

On the home device, paste the join command it printed:

```sh
curl -fsSL https://raw.githubusercontent.com/avinash-1707/domicile/main/install.sh | sh -s -- join <token>
```

Back on the VPS:

```sh
domicile rule add reddit.com --via home
domicile connect playwright-mcp   # or agent-browser, or shell
domicile verify
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
- The home agent refuses to connect to private, loopback, link-local and cloud-metadata addresses, so an agent on the VPS cannot reach your router or other devices on your LAN.
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

An MCP server (`domicile mcp`) lets an agent check which exit it is on, whether it is healthy, and which hosts recently blocked it. It is read-only. Only you can add rules.

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
