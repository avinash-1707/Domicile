package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/exit"
	"github.com/avinash-1707/domicile/internal/state"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/quictun"
)

const agentFile = "agent.json"

// runAgent runs the exit. `agent join <code>` pairs this device first, saves
// the pairing, and then runs; plain `agent` runs from the saved pairing,
// which is what a service manager starts.
func runAgent(ctx context.Context, args []string, log *slog.Logger) error {
	join := len(args) > 0 && args[0] == "join"
	if join {
		args = args[1:]
	}
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for this device's pairing")
	allowList := fs.String("allow", "", "comma-separated IPs or CIDRs on the local network the exit may reach (default: none; the LAN, loopback and cloud metadata are refused)")
	path := func() string { return filepath.Join(*stateDir, agentFile) }

	var a state.Agent
	if join {
		code, err := positionalAndFlags(fs, args, "agent join <code | ->")
		if err != nil {
			return err
		}
		if code == "-" {
			// Reading from stdin keeps the code out of `ps` and shell
			// history on shared machines.
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil && line == "" {
				return fmt.Errorf("read join code from stdin: %w", err)
			}
			code = line
		}
		unlock, err := lockAgent(*stateDir)
		if err != nil {
			return err
		}
		defer unlock()
		if a, err = pair(ctx, code, path(), log); err != nil {
			return err
		}
	} else {
		if err := parseFlags(fs, args); err != nil {
			return err
		}
		unlock, err := lockAgent(*stateDir)
		if err != nil {
			return err
		}
		defer unlock()
		if a, err = state.LoadAgent(path()); err != nil {
			return err
		}
	}

	pin, err := certs.ParseFingerprint(a.PinSHA256)
	if err != nil {
		return fmt.Errorf("%s: server fingerprint: %w", path(), err)
	}
	allow, err := parseAllow(*allowList)
	if err != nil {
		return fmt.Errorf("-allow: %w", err)
	}
	if len(allow) > 0 {
		log.Warn("exit may reach these local destinations", "allow", *allowList)
	}
	err = exit.Run(ctx, exit.Config{
		Name:       a.Name,
		Credential: a.Credential,
		Dial:       dialer(a.Server, pin),
		Allow:      allow,
		Logger:     log,
	})
	if errors.Is(err, exit.ErrUnauthorized) {
		return fmt.Errorf("%w: this exit was removed or re-paired on the server; pair again with a new code from `domicile add %s`", err, a.Name)
	}
	return err
}

// pair exchanges a join code's one-time token for a credential and saves it.
func pair(ctx context.Context, code, path string, log *slog.Logger) (state.Agent, error) {
	c, err := decodeJoinCode(code)
	if err != nil {
		return state.Agent{}, err
	}
	pin, err := certs.ParseFingerprint(c.Pin)
	if err != nil {
		return state.Agent{}, err
	}
	cred, err := exit.Join(ctx, dialer(c.Server, pin), c.Name, c.Token)
	if err != nil {
		return state.Agent{}, err
	}
	a := state.Agent{Name: c.Name, Server: c.Server, PinSHA256: c.Pin, Credential: cred}
	if err := state.SaveAgent(path, a); err != nil {
		// The token is spent; without the saved credential the device must
		// be paired again, so say so plainly.
		return state.Agent{}, fmt.Errorf("paired, but could not save the credential (pair again with a new code): %w", err)
	}
	log.Info("paired with server", "exit", c.Name, "server", c.Server, "saved", path)
	return a, nil
}

// parseAllow parses "192.168.1.50,10.0.0.0/24". A bare IP means that one
// address. Prefixes broader than /8 (IPv4) or /32 (IPv6) are refused: they
// would quietly switch the deny list off.
func parseAllow(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, err := netip.ParsePrefix(item); err == nil {
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				// Destinations are compared as IPv4, so a mapped prefix
				// must be too, or it would silently match nothing.
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 32) {
				return nil, fmt.Errorf("%q is too broad; list the specific devices or subnets to open", item)
			}
			out = append(out, p.Masked())
			continue
		}
		ip, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR", item)
		}
		ip = ip.Unmap()
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
}

// lockAgent allows one agent per device: two would keep replacing each
// other's session on the server.
func lockAgent(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := state.LockFile(filepath.Join(dir, agentFile+".lock"), 0)
	if err != nil {
		return nil, fmt.Errorf("another domicile agent is already running for %s", dir)
	}
	return unlock, nil
}

func dialer(addr string, pin certs.Fingerprint) func(context.Context) (tunnel.Session, error) {
	tlsConf := certs.PinnedClientConfig(pin, tunnel.ALPN)
	return func(ctx context.Context) (tunnel.Session, error) {
		return quictun.Dial(ctx, addr, tlsConf, quictun.Config{})
	}
}
