package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

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
	err = exit.Run(ctx, exit.Config{
		Name:       a.Name,
		Credential: a.Credential,
		Dial:       dialer(a.Server, pin),
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
