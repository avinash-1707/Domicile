package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/avinash-1707/domicile/internal/control"
	"github.com/avinash-1707/domicile/internal/mcp"
	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/secret"
	"github.com/avinash-1707/domicile/internal/state"
	"github.com/avinash-1707/domicile/internal/verify"
	"golang.org/x/sys/unix"
)

// toolRun is the proxy user `domicile run` uses. Its password is kept in a
// file so concurrent runs share it instead of rotating each other out.
const toolRun = "run"

// exitCode carries a child process's exit status out of main.
type exitCode int

func (c exitCode) Error() string { return fmt.Sprintf("exit status %d", int(c)) }

// runRun starts a command with domicile's proxy in its environment. Node's
// fetch needs NODE_USE_ENV_PROXY=1 and Node 22.21+ or 24+ (decision S-21).
func runRun(ctx context.Context, args []string, out io.Writer) error {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep == len(args)-1 {
		return errors.New("usage: domicile run [flags] -- <command> [args...]")
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for server state")
	proxyAddr := fs.String("proxy", defaultProxyAddr, "address of domicile's proxy, as passed to `domicile server -proxy`")
	if err := parseFlags(fs, args[:sep]); err != nil {
		return err
	}
	password, err := runCredential(*stateDir)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, args[sep+1], args[sep+2:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, out, os.Stderr
	cmd.Env = proxyEnv(os.Environ(), *proxyAddr, password)
	// main turns SIGINT/SIGTERM into ctx cancellation; pass SIGTERM on and
	// give the child time to clean up instead of killing it outright.
	// Without a terminal (systemd, Docker, scripts) the command gets its own
	// process group and the signal goes to the whole group, so background
	// jobs it started are not orphaned. With a terminal it stays in the
	// terminal's group: a separate group would be stopped by the kernel when
	// it reads, writes or configures the terminal, and Ctrl-C already
	// reaches every process in it. After WaitDelay only the leader is
	// killed; a background job that ignores SIGTERM outlives the run.
	if !isTerminal(os.Stdin) && !isTerminal(os.Stdout) && !isTerminal(os.Stderr) {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	} else {
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	}
	cmd.WaitDelay = 10 * time.Second
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return exitCode(128 + int(ws.Signal()))
		}
		return exitCode(ee.ExitCode())
	}
	return err
}

// isTerminal reports whether f is a terminal. A character-device check is
// not enough: /dev/null, a service's usual stdin, is one too.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlGetTermios)
	return err == nil
}

// proxyEnv replaces any proxy settings in env with domicile's.
func proxyEnv(env []string, addr, password string) []string {
	drop := map[string]bool{}
	for _, k := range []string{"ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY"} {
		drop[k], drop[strings.ToLower(k)] = true, true
	}
	var out []string
	for _, kv := range env {
		if k, _, _ := strings.Cut(kv, "="); !drop[k] {
			out = append(out, kv)
		}
	}
	h := proxyURL("http", addr, toolRun, password)
	return append(out,
		"ALL_PROXY="+proxyURL("socks5h", addr, toolRun, password),
		"HTTPS_PROXY="+h, "HTTP_PROXY="+h, "https_proxy="+h, "http_proxy="+h,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"NODE_USE_ENV_PROXY=1",
	)
}

// runCredential returns the run user's password, creating it on first use
// or if the user was removed.
func runCredential(stateDir string) (string, error) {
	path := filepath.Join(stateDir, "run.secret")
	// Two runs started together must not each create a credential and lock
	// the other out.
	unlock, err := state.LockFile(path+".lock", 5*time.Second)
	if err != nil {
		return "", err
	}
	defer unlock()
	st, err := state.Load(statePath(stateDir))
	if err != nil {
		return "", err
	}
	if data, err := os.ReadFile(path); err == nil {
		pw := strings.TrimSpace(string(data))
		if u, ok := st.Users[toolRun]; ok && secret.MatchesDigest(pw, u.PasswordSHA256) {
			return pw, nil
		}
	}
	pw, err := state.NewSecret()
	if err != nil {
		return "", err
	}
	if err := state.WriteFileAtomic(path, []byte(pw+"\n"), 0o600); err != nil {
		return "", err
	}
	err = state.Update(statePath(stateDir), func(st *state.State) error {
		st.Users[toolRun] = state.User{PasswordSHA256: secret.Digest(pw), Created: time.Now().UTC()}
		return nil
	})
	return pw, err
}

// runMCP serves the read-only agent tools over stdio, backed by the running
// server's control socket.
func runMCP(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for server state")
	controlPath := fs.String("control", "", "control socket of the running server (default <state-dir>/control.sock)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *controlPath == "" {
		*controlPath = defaultControlPath(*stateDir)
	}
	cl := control.Client{Path: *controlPath}
	call := func(timeout time.Duration) (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, timeout)
	}
	verifyOnce := &verifyCache{}

	srv := &mcp.Server{Name: "domicile", Version: version, Handlers: map[string]mcp.Handler{
		"exit_status": func(ctx context.Context, _ json.RawMessage) (any, error) {
			ctx, cancel := call(10 * time.Second)
			defer cancel()
			return cl.Status(ctx)
		},
		"exit_verify": func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a struct {
				Exit string `json:"exit"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			ctx, cancel := call(2 * time.Minute)
			defer cancel()
			return verifyOnce.get(a.Exit, func() ([]verify.Report, error) { return checkExits(ctx, cl, a.Exit) })
		},
		"blocked_hosts": func(ctx context.Context, _ json.RawMessage) (any, error) {
			ctx, cancel := call(10 * time.Second)
			defer cancel()
			list, err := cl.Blocked(ctx)
			if err != nil {
				return nil, err
			}
			// Reasons are text other agents wrote, possibly steered by a
			// web page; they are not passed on to the next agent.
			type entry struct {
				Host    string    `json:"host"`
				Count   int       `json:"count"`
				Last    time.Time `json:"last"`
				Suggest string    `json:"suggest"`
			}
			out := make([]entry, 0, len(list))
			for _, b := range list {
				out = append(out, entry{b.Host, b.Count, b.Last, b.Suggest})
			}
			return out, nil
		},
		"report_blocked": func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a struct {
				Host   string `json:"host"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			ctx, cancel := call(10 * time.Second)
			defer cancel()
			if r := []rune(a.Reason); len(r) > maxReason {
				a.Reason = string(r[:maxReason])
			}
			if err := cl.ReportBlocked(ctx, a.Host, a.Reason); err != nil {
				return nil, err
			}
			list, err := cl.Blocked(ctx)
			if err != nil {
				return nil, err
			}
			for _, b := range list {
				if h, _ := rules.NormalizeDomain(a.Host); b.Host == h {
					return map[string]string{
						"recorded": b.Host,
						"next":     "Routing is unchanged. Ask the user whether to run: " + b.Suggest,
					}, nil
				}
			}
			return map[string]string{"recorded": a.Host}, nil
		},
	}}
	return srv.Serve(ctx, in, out)
}

// maxReason caps a reported reason, in runes.
const maxReason = 200

// verifyCache runs one exit_verify at a time and reuses a result for a
// minute, so an agent calling it in a loop cannot use up ip-api's rate limit
// and break the operator's own `domicile verify`.
type verifyCache struct {
	mu   sync.Mutex
	key  string
	at   time.Time
	last []verify.Report
}

func (c *verifyCache) get(key string, run func() ([]verify.Report, error)) ([]verify.Report, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last != nil && c.key == key && time.Since(c.at) < time.Minute {
		return c.last, nil
	}
	r, err := run()
	if err != nil {
		return nil, err
	}
	c.key, c.at, c.last = key, time.Now(), r
	return r, nil
}

// checkExits runs verify for one exit or all, as `domicile verify` does.
func checkExits(ctx context.Context, cl control.Client, only string) ([]verify.Report, error) {
	st, err := cl.Status(ctx)
	if err != nil {
		return nil, err
	}
	exits := st.Exits
	if only != "" {
		if exits = filterExit(exits, only); len(exits) == 0 {
			return nil, fmt.Errorf("no exit named %q", only)
		}
	}
	direct := func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	}
	base := verify.Measure(ctx, direct, verify.Config{})
	var reports []verify.Report
	for _, e := range exits {
		if !e.Connected {
			reports = append(reports, verify.Report{Exit: e.Name, Checks: []verify.Check{{Name: "exit", Result: verify.Fail, Detail: notConnected(e)}}})
			continue
		}
		via := func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			return cl.DialExit(ctx, e.Name, host, port)
		}
		reports = append(reports, verify.Run(ctx, e.Name, via, base, verify.Config{}))
	}
	return reports, nil
}
