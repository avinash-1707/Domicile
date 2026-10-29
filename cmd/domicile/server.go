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
	"slices"
	"strings"
	"time"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/control"
	"github.com/avinash-1707/domicile/internal/proxy"
	"github.com/avinash-1707/domicile/internal/route"
	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/server"
	"github.com/avinash-1707/domicile/internal/state"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/quictun"
	"github.com/avinash-1707/domicile/internal/wire"
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
	controlPath := fs.String("control", "", "control socket for `domicile verify` (default <state-dir>/control.sock)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *controlPath == "" {
		*controlPath = defaultControlPath(*stateDir)
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
	// The socket only serves `domicile verify`; failing to create it (a path
	// too long for a unix socket, say) must not stop the proxy, unless
	// another server already owns it.
	cl, err := control.Listen(*controlPath)
	if errors.Is(err, control.ErrInUse) {
		l.Close()
		pl.Close()
		return err
	}
	if err != nil {
		log.Warn("control socket unavailable; `domicile verify` will not work", "path", *controlPath, "err", err)
		cl = nil
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
		if cl != nil {
			cl.Close()
		}
		return err
	}
	log.Info("server listening", "tunnel", l.Addr().String(), "proxy", pl.Addr().String(), "rules", len(conf.Rules), "config", *configPath, "fingerprint", pin.String())

	// Either loop failing stops the other.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	loops := 2
	errc := make(chan error, 3)
	go func() { errc <- prx.Serve(ctx, pl) }()
	go func() { errc <- srv.Serve(ctx, l) }()
	if cl != nil {
		loops++
		go func() { errc <- control.Serve(ctx, cl, controlHandler{srv: srv, live: live}, log) }()
	}
	go watchState(ctx, live, srv, log)
	errs := []error{<-errc}
	cancel()
	for range loops - 1 {
		errs = append(errs, <-errc)
	}
	// Serve has closed every exit session; closing the listener now is clean.
	return errors.Join(append(errs, l.Close())...)
}

func isLoopback(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	return ok && ta.IP.IsLoopback()
}

// controlHandler answers the control socket from the live server.
type controlHandler struct {
	srv  *server.Server
	live *state.Live
}

func (h controlHandler) Exits() []control.ExitStatus {
	exits := h.live.State().Exits
	out := make([]control.ExitStatus, 0, len(exits))
	for name, e := range exits {
		out = append(out, control.ExitStatus{Name: name, Connected: h.srv.Connected(name), Paired: e.CredentialSHA256 != ""})
	}
	slices.SortFunc(out, func(a, b control.ExitStatus) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func (h controlHandler) DialExit(ctx context.Context, exit string, dst wire.Open) (tunnel.Stream, error) {
	return h.srv.Dial(ctx, exit, dst)
}

func defaultControlPath(stateDir string) string { return filepath.Join(stateDir, "control.sock") }

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
