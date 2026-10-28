package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/exit"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/quictun"
	"github.com/avinash-1707/domicile/internal/wire"
)

// tokenEnv holds the exit's token, kept out of the command line so it does
// not show up in `ps`.
const tokenEnv = "DOMICILE_TOKEN"

func runAgent(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	serverAddr := fs.String("server", "", "server address, host:port (required)")
	pinHex := fs.String("pin", "", "server certificate fingerprint printed by `domicile server` (required)")
	name := fs.String("name", "", "this exit's name, as configured on the server (required)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: domicile agent -server host:port -pin <fingerprint> -name <exit>\n\nThe exit's token comes from %s.\n\nFlags:\n", tokenEnv)
		fs.PrintDefaults()
	}
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *serverAddr == "" || *pinHex == "" || *name == "" {
		fmt.Fprintln(fs.Output(), "-server, -pin and -name are required")
		fs.Usage()
		return errUsage
	}
	token := os.Getenv(tokenEnv)
	if token == "" {
		return fmt.Errorf("%s is not set", tokenEnv)
	}
	// Checked here because an oversized value would otherwise fail on every
	// reconnect forever.
	if len(token) > wire.MaxField || len(*name) > wire.MaxField {
		return fmt.Errorf("-name and %s must be at most %d bytes", tokenEnv, wire.MaxField)
	}
	pin, err := certs.ParseFingerprint(*pinHex)
	if err != nil {
		return fmt.Errorf("-pin: %w", err)
	}

	tlsConf := certs.PinnedClientConfig(pin, tunnel.ALPN)
	err = exit.Run(ctx, exit.Config{
		Name:  *name,
		Token: token,
		Dial: func(ctx context.Context) (tunnel.Session, error) {
			return quictun.Dial(ctx, *serverAddr, tlsConf, quictun.Config{})
		},
		Logger: log,
	})
	if errors.Is(err, exit.ErrUnauthorized) {
		return fmt.Errorf("%w: check -name and %s", err, tokenEnv)
	}
	return err
}
