package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/server"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/quictun"
	"github.com/avinash-1707/domicile/internal/wire"
)

// exitsEnv holds exit credentials as name=token pairs.
// SIMPLIFIED: replaced by `domicile add` and stored credentials once
// registration exists; an environment variable keeps tokens out of `ps`.
const exitsEnv = "DOMICILE_EXITS"

func runServer(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := fs.String("listen", ":443", "UDP address exits connect to")
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for the server certificate")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: domicile server [flags]\n\nExit credentials come from %s=name=token[,name=token...].\n\nFlags:\n", exitsEnv)
		fs.PrintDefaults()
	}
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	exits, err := parseExits(os.Getenv(exitsEnv))
	if err != nil {
		return fmt.Errorf("%s: %w", exitsEnv, err)
	}
	cert, err := certs.LoadOrCreate(*stateDir)
	if err != nil {
		return err
	}
	pin, err := certs.FingerprintOf(cert)
	if err != nil {
		return err
	}

	// Exits only ever open the hello stream, so at most one concurrent
	// stream is allowed from them.
	l, err := quictun.Listen(*listen, certs.ServerConfig(cert, tunnel.ALPN), quictun.Config{MaxIncomingStreams: 1})
	if err != nil {
		return err
	}
	log.Info("server listening", "addr", l.Addr().String(), "fingerprint", pin.String(), "exits", len(exits))

	srv := server.New(server.Config{Exits: exits, Logger: log})
	serveErr := srv.Serve(ctx, l)
	// Serve has closed every exit session; closing the listener now is clean.
	return errors.Join(serveErr, l.Close())
}

// minTokenLen keeps stopgap tokens out of guessing range: the server does not
// throttle failed hellos, and a correct guess takes over the exit.
const minTokenLen = 32

// parseExits parses "name=token,name=token". Names must be unique, tokens at
// least minTokenLen bytes, and both fit in a wire frame.
func parseExits(s string) (map[string]string, error) {
	exits := make(map[string]string)
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("no exits configured")
	}
	for pair := range strings.SplitSeq(s, ",") {
		name, token, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || name == "" || token == "" {
			// The pair may contain a token, so it is not echoed back.
			return nil, errors.New("each entry must be name=token")
		}
		if len(name) > wire.MaxField {
			return nil, fmt.Errorf("exit name longer than %d bytes", wire.MaxField)
		}
		if len(token) < minTokenLen || len(token) > wire.MaxField {
			return nil, fmt.Errorf("token for exit %q must be %d to %d bytes; generate one with `openssl rand -hex 32`", name, minTokenLen, wire.MaxField)
		}
		if _, dup := exits[name]; dup {
			return nil, fmt.Errorf("exit %q listed twice", name)
		}
		exits[name] = token
	}
	return exits, nil
}

// defaultStateDir follows systemd's StateDirectory= when set, otherwise the
// XDG state location.
func defaultStateDir() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "domicile")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "domicile")
	}
	return "domicile-state"
}
