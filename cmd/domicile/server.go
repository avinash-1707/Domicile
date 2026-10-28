package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/proxy"
	"github.com/avinash-1707/domicile/internal/server"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/quictun"
	"github.com/avinash-1707/domicile/internal/wire"
)

// Credentials come from environment variables, which keep them out of `ps`.
// SIMPLIFIED: replaced by `domicile add` and stored, hashed credentials once
// registration exists.
const (
	exitsEnv      = "DOMICILE_EXITS"       // exit name=token pairs
	proxyUsersEnv = "DOMICILE_PROXY_USERS" // proxy user=password pairs
)

// defaultProxyAddr is loopback so the proxy is never reachable from other
// hosts unless explicitly configured.
const defaultProxyAddr = "127.0.0.1:1080"

func runServer(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := fs.String("listen", ":443", "UDP address exits connect to")
	proxyAddr := fs.String("proxy", defaultProxyAddr, "TCP address of the SOCKS5 / HTTP CONNECT proxy for agents")
	via := fs.String("via", "", "exit that carries all proxied traffic (default: the only configured exit)")
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for the server certificate")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: domicile server [flags]\n\nCredentials come from the environment, as comma-separated pairs:\n  %s=name=token\n  %s=user=password\n\nFlags:\n", exitsEnv, proxyUsersEnv)
		fs.PrintDefaults()
	}
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	exits, err := parseCredentials(os.Getenv(exitsEnv))
	if err != nil {
		return fmt.Errorf("%s: %w", exitsEnv, err)
	}
	users, err := parseCredentials(os.Getenv(proxyUsersEnv))
	if err != nil {
		return fmt.Errorf("%s: %w", proxyUsersEnv, err)
	}
	for user := range users {
		// HTTP Basic auth splits user:password at the first colon.
		if strings.Contains(user, ":") {
			return fmt.Errorf("%s: user %q must not contain ':'", proxyUsersEnv, user)
		}
	}
	route, err := routeExit(*via, exits)
	if err != nil {
		return err
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
	pl, err := net.Listen("tcp", *proxyAddr)
	if err != nil {
		l.Close()
		return fmt.Errorf("proxy listen: %w", err)
	}
	if !isLoopback(pl.Addr()) {
		log.Warn("proxy is reachable from other hosts; credentials are still required", "addr", pl.Addr().String())
	}

	srv := server.New(server.Config{Exits: exits, Logger: log})
	prx, err := proxy.New(proxy.Config{
		Users: users,
		// SIMPLIFIED: every connection goes through one exit until domain
		// rules choose per destination.
		Dial: func(ctx context.Context, dst wire.Open) (tunnel.Stream, error) {
			return srv.Dial(ctx, route, dst)
		},
		Logger: log,
	})
	if err != nil {
		l.Close()
		pl.Close()
		return err
	}
	log.Info("server listening", "tunnel", l.Addr().String(), "proxy", pl.Addr().String(), "via", route, "fingerprint", pin.String())

	// Either loop failing stops the other.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	go func() { errc <- prx.Serve(ctx, pl) }()
	go func() { errc <- srv.Serve(ctx, l) }()
	first := <-errc
	cancel()
	second := <-errc
	// Serve has closed every exit session; closing the listener now is clean.
	return errors.Join(first, second, l.Close())
}

// routeExit picks the exit for all proxied traffic.
func routeExit(via string, exits map[string]string) (string, error) {
	if via != "" {
		if _, ok := exits[via]; !ok {
			return "", fmt.Errorf("-via %q is not a configured exit", via)
		}
		return via, nil
	}
	if len(exits) != 1 {
		return "", errors.New("several exits configured; choose one with -via")
	}
	for name := range exits {
		return name, nil
	}
	panic("unreachable")
}

func isLoopback(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	return ok && ta.IP.IsLoopback()
}

// minSecretLen keeps stopgap tokens and passwords out of guessing range: the
// server does not throttle failed attempts, and a guessed exit token takes
// over the exit.
const minSecretLen = 32

// parseCredentials parses "name=secret,name=secret". Names must be unique,
// secrets at least minSecretLen bytes, and both fit in a wire frame.
func parseCredentials(s string) (map[string]string, error) {
	creds := make(map[string]string)
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("not set")
	}
	for pair := range strings.SplitSeq(s, ",") {
		name, secret, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || name == "" || secret == "" {
			// The pair may contain a secret, so it is not echoed back.
			return nil, errors.New("each entry must be name=secret")
		}
		if len(name) > wire.MaxField {
			return nil, fmt.Errorf("name longer than %d bytes", wire.MaxField)
		}
		if len(secret) < minSecretLen || len(secret) > wire.MaxField {
			return nil, fmt.Errorf("secret for %q must be %d to %d bytes; generate one with `openssl rand -hex 32`", name, minSecretLen, wire.MaxField)
		}
		if _, dup := creds[name]; dup {
			return nil, fmt.Errorf("%q listed twice", name)
		}
		creds[name] = secret
	}
	return creds, nil
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
