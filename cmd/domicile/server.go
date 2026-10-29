package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	// Read once and parse and hash the same bytes, so a change landing
	// during startup is picked up by the first reload.
	ruleData, err := os.ReadFile(*configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read rules: %w", err)
	}
	conf := rules.Config{Rules: []rules.Rule{}}
	if ruleData != nil {
		if conf, err = rules.Parse(ruleData, *configPath); err != nil {
			return err
		}
	}
	knownExit := func(exit string) bool { _, ok := live.State().Exits[exit]; return ok }
	if err := checkRuleExits(conf, knownExit); err != nil {
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
	router := route.New(rules.NewTable(conf), srv, log, route.Options{BlockLocalDirect: exposed})
	lr := &liveRules{path: *configPath, router: router, log: log, conf: conf, sum: sha256.Sum256(ruleData), known: knownExit}
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
		h := controlHandler{
			srv: srv, live: live, rules: lr, started: time.Now(),
			tunnelAddr: l.Addr().String(), proxyAddr: pl.Addr().String(), fingerprint: pin.String(),
		}
		go func() { errc <- control.Serve(ctx, cl, h, log) }()
	}
	go watch(ctx, live, srv, lr, log)
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
	srv         *server.Server
	live        *state.Live
	rules       *liveRules
	started     time.Time
	tunnelAddr  string
	proxyAddr   string
	fingerprint string
}

func (h controlHandler) Status() control.Status {
	exits := h.live.State().Exits
	out := make([]control.ExitStatus, 0, len(exits))
	for name, e := range exits {
		es := control.ExitStatus{Name: name, Paired: e.CredentialSHA256 != ""}
		if since, ok := h.srv.ConnectedSince(name); ok {
			es.Connected, es.ConnectedSince = true, &since
		}
		out = append(out, es)
	}
	slices.SortFunc(out, func(a, b control.ExitStatus) int { return strings.Compare(a.Name, b.Name) })
	conf, rerr := h.rules.snapshot()
	return control.Status{
		Started:     h.started,
		TunnelAddr:  h.tunnelAddr,
		ProxyAddr:   h.proxyAddr,
		Fingerprint: h.fingerprint,
		Exits:       out,
		RulesFile:   h.rules.path,
		Rules:       append([]rules.Rule{}, conf.Rules...), // never null in JSON
		RulesError:  rerr,
	}
}

func (h controlHandler) DialExit(ctx context.Context, exit string, dst wire.Open) (tunnel.Stream, error) {
	return h.srv.Dial(ctx, exit, dst)
}

// liveRules keeps the router's rules in step with the rules file, so
// `domicile rule add` takes effect on a running server.
type liveRules struct {
	path   string
	router *route.Router
	known  func(exit string) bool
	log    *slog.Logger

	mu   sync.Mutex
	conf rules.Config
	sum  [sha256.Size]byte
	err  string
}

// reload applies the file if its content changed. Anything that cannot be
// applied keeps the last good rules, so traffic is never rerouted by
// accident: a half-edited file, a file briefly missing during `git pull` or
// an editor's save, or a rule naming an exit that has not been added (which
// startup refuses too). Clearing all rules is `{"rules": []}`.
func (lr *liveRules) reload() {
	data, err := os.ReadFile(lr.path)
	if errors.Is(err, os.ErrNotExist) {
		lr.fail(errors.New("rules file is missing; still using the previous rules (write {\"rules\": []} to clear them)"))
		return
	}
	if err != nil {
		lr.fail(err)
		return
	}
	sum := sha256.Sum256(data)
	lr.mu.Lock()
	if sum == lr.sum {
		// Back to what is applied (say, a broken edit was reverted).
		lr.err = ""
		lr.mu.Unlock()
		return
	}
	lr.mu.Unlock()
	// Parse the bytes that were hashed, so the stored hash always describes
	// the applied rules.
	conf, err := rules.Parse(data, lr.path)
	if err != nil {
		lr.fail(err)
		return
	}
	if err := checkRuleExits(conf, lr.known); err != nil {
		lr.fail(err)
		return
	}
	lr.router.SetTable(rules.NewTable(conf))
	lr.mu.Lock()
	lr.conf, lr.sum, lr.err = conf, sum, ""
	lr.mu.Unlock()
	lr.log.Info("rules reloaded", "rules", len(conf.Rules), "config", lr.path)
}

// checkRuleExits refuses rules naming an exit that has not been added: with
// fallback_direct such a rule would send its traffic direct.
func checkRuleExits(conf rules.Config, known func(string) bool) error {
	for _, r := range conf.Rules {
		if !known(r.Via) {
			return fmt.Errorf("rule for %s uses exit %q, which has not been added; run `domicile add %s`", r.Match, r.Via, r.Via)
		}
	}
	return nil
}

func (lr *liveRules) fail(err error) {
	lr.mu.Lock()
	first := lr.err != err.Error()
	lr.err = err.Error()
	lr.mu.Unlock()
	if first {
		lr.log.Error("rules file not applied; keeping the previous rules", "err", err)
	}
}

func (lr *liveRules) snapshot() (rules.Config, string) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return lr.conf, lr.err
}

func defaultControlPath(stateDir string) string { return filepath.Join(stateDir, "control.sock") }

// watch reloads the state and rules files when the CLI changes them. A
// state change drops sessions whose exit was removed or re-paired.
func watch(ctx context.Context, live *state.Live, srv *server.Server, lr *liveRules, log *slog.Logger) {
	t := time.NewTicker(stateReloadEvery)
	defer t.Stop()
	seen := live.Generation()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// State first, so `domicile add office && domicile rule add x -via
		// office` in the same second sees the new exit.
		err := live.Reload()
		if err != nil {
			// Keep serving with the last good state; a half-edited or
			// unreadable file must not take every exit offline.
			log.Error("reload state", "err", err)
		}
		lr.reload()
		if err != nil {
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
