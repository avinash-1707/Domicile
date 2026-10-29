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
	"time"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/proxy"
	"github.com/avinash-1707/domicile/internal/route"
	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/server"
	"github.com/avinash-1707/domicile/internal/state"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/quictun"
)

// stateReloadEvery is how often the server re-reads the state file, which
// bounds how long a removed exit or proxy user keeps working.
const stateReloadEvery = time.Second

// defaultProxyAddr is loopback so the proxy is never reachable from other
// hosts unless explicitly configured.
const defaultProxyAddr = "127.0.0.1:1080"

func runServer(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := fs.String("listen", ":443", "UDP address exits connect to")
	proxyAddr := fs.String("proxy", defaultProxyAddr, "TCP address of the SOCKS5 / HTTP CONNECT proxy for agents")
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for server state and certificate (from `domicile init`)")
	configPath := fs.String("config", "", "rules file (default <state-dir>/domicile.json)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	live, err := state.OpenLive(statePath(*stateDir))
	if err != nil {
		return err
	}
	explicitConfig := *configPath != ""
	if !explicitConfig {
		*configPath = filepath.Join(*stateDir, configFile)
	}
	// A missing rules file means every destination goes direct, so it must
	// never be silent: a typo in -config would send ruled traffic out of
	// the datacenter IP.
	if _, err := os.Stat(*configPath); errors.Is(err, os.ErrNotExist) {
		if explicitConfig {
			return fmt.Errorf("-config %s does not exist", *configPath)
		}
		log.Warn("no rules file; all traffic goes direct from the VPS", "config", *configPath)
	}
	conf, err := rules.Load(*configPath)
	if err != nil {
		return err
	}
	for _, r := range conf.Rules {
		if _, ok := live.State().Exits[r.Via]; !ok {
			return fmt.Errorf("rule for %s uses exit %q, which has not been added; run `domicile add %s`", r.Match, r.Via, r.Via)
		}
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
	exposed := !isLoopback(pl.Addr())
	if exposed {
		log.Warn("proxy is reachable from other hosts; credentials are still required, and direct connections to local and private addresses are refused", "addr", pl.Addr().String())
	}

	srv := server.New(server.Config{Auth: live, Logger: log})
	// SIMPLIFIED: rules are read once at start; `domicile rule` changes need
	// a restart until the control socket can reload them live.
	router := route.New(rules.NewTable(conf), srv, log, route.Options{BlockLocalDirect: exposed})
	prx, err := proxy.New(proxy.Config{CheckUser: live.CheckUser, Dial: router.Dial, Logger: log})
	if err != nil {
		l.Close()
		pl.Close()
		return err
	}
	log.Info("server listening", "tunnel", l.Addr().String(), "proxy", pl.Addr().String(), "rules", len(conf.Rules), "config", *configPath, "fingerprint", pin.String())

	// Either loop failing stops the other.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	go func() { errc <- prx.Serve(ctx, pl) }()
	go func() { errc <- srv.Serve(ctx, l) }()
	go watchState(ctx, live, srv, log)
	first := <-errc
	cancel()
	second := <-errc
	// Serve has closed every exit session; closing the listener now is clean.
	return errors.Join(first, second, l.Close())
}

func isLoopback(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	return ok && ta.IP.IsLoopback()
}

// watchState reloads the state file when the CLI changes it, and drops
// sessions whose exit was removed or re-paired.
func watchState(ctx context.Context, live *state.Live, srv *server.Server, log *slog.Logger) {
	t := time.NewTicker(stateReloadEvery)
	defer t.Stop()
	seen := live.Generation()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := live.Reload(); err != nil {
			// Keep serving with the last good state; a half-edited or
			// unreadable file must not take every exit offline.
			log.Error("reload state", "err", err)
			continue
		}
		// Compare generations, not "did this Reload change anything": a
		// join's own reload may already have absorbed a removal.
		if g := live.Generation(); g != seen {
			seen = g
			srv.Revalidate()
		}
	}
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
