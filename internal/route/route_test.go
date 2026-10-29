package route

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/server"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/wire"
)

// fakeExits records which exit was asked for and can be switched down.
type fakeExits struct {
	down  atomic.Bool
	asked atomic.Value // string
}

func (f *fakeExits) Dial(_ context.Context, exit string, _ wire.Open) (tunnel.Stream, error) {
	f.asked.Store(exit)
	if f.down.Load() {
		return nil, server.ErrExitDown
	}
	return nil, nil // the stream itself is not under test
}

func router(t *testing.T, logs io.Writer, rs ...rules.Rule) (*Router, *fakeExits) {
	t.Helper()
	path := t.TempDir() + "/domicile.json"
	if err := (rules.Config{Rules: rs}).Save(path); err != nil {
		t.Fatal(err)
	}
	c, err := rules.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeExits{}
	return New(rules.NewTable(c), f, slog.New(slog.NewTextHandler(logs, nil)), Options{}), f
}

// listener returns a local TCP destination as a wire.Open.
func listener(t *testing.T) wire.Open {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return wire.Open{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
}

func TestMatchedGoesThroughExit(t *testing.T) {
	r, f := router(t, io.Discard, rules.Rule{Match: "reddit.com", Via: "home"})
	_, path, err := r.Dial(context.Background(), wire.Open{Host: "www.reddit.com", Port: 443})
	if err != nil || path != "home" || f.asked.Load() != "home" {
		t.Fatalf("path %q, asked %v, err %v; want through home", path, f.asked.Load(), err)
	}
}

func TestUnmatchedGoesDirect(t *testing.T) {
	r, f := router(t, io.Discard, rules.Rule{Match: "reddit.com", Via: "home"})
	dst := listener(t)
	st, path, err := r.Dial(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if path != Direct || f.asked.Load() != nil {
		t.Fatalf("path %q, exit asked %v; want direct without touching an exit", path, f.asked.Load())
	}
}

func TestFailClosedWhenExitDown(t *testing.T) {
	r, f := router(t, io.Discard, rules.Rule{Match: "127.0.0.1", Via: "home"})
	f.down.Store(true)
	dst := listener(t) // reachable directly, so a fallback would succeed
	_, path, err := r.Dial(context.Background(), dst)
	if !errors.Is(err, server.ErrExitDown) || path != "home" {
		t.Fatalf("path %q err %v; want refused with ErrExitDown, never direct", path, err)
	}
}

func TestFallbackDirectWhenExitDown(t *testing.T) {
	var logs bytes.Buffer
	r, f := router(t, &logs, rules.Rule{Match: "127.0.0.1", Via: "home", OnExitDown: rules.FallbackDirect})
	f.down.Store(true)
	dst := listener(t)
	st, path, err := r.Dial(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if !strings.HasPrefix(path, Direct+" (fallback") {
		t.Fatalf("path %q, want a fallback", path)
	}
	if !strings.Contains(logs.String(), "falling back to direct") {
		t.Fatal("fallback was not logged")
	}
}

func TestRoutingResumesWhenExitReturns(t *testing.T) {
	r, f := router(t, io.Discard, rules.Rule{Match: "127.0.0.1", Via: "home", OnExitDown: rules.FallbackDirect})
	dst := listener(t)
	f.down.Store(true)
	st, _, err := r.Dial(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	f.down.Store(false) // the exit reconnected
	if _, path, err := r.Dial(context.Background(), dst); err != nil || path != "home" {
		t.Fatalf("after reconnect: path %q, err %v; want back through home", path, err)
	}
}

func TestFallbackOnlyForExitDown(t *testing.T) {
	// A destination failure reported by a live exit must not trigger a
	// direct retry: that would reveal the datacenter IP to the same site.
	refusing := &refusingExits{}
	path := t.TempDir() + "/domicile.json"
	(rules.Config{Rules: []rules.Rule{{Match: "a.com", Via: "home", OnExitDown: rules.FallbackDirect}}}).Save(path)
	c, _ := rules.Load(path)
	r := New(rules.NewTable(c), refusing, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	_, p, err := r.Dial(context.Background(), wire.Open{Host: "a.com", Port: 443})
	var oe *wire.OpenError
	if !errors.As(err, &oe) || p != "home" {
		t.Fatalf("path %q err %v; want the exit's refusal, no fallback", p, err)
	}
}

type refusingExits struct{}

func (refusingExits) Dial(context.Context, string, wire.Open) (tunnel.Stream, error) {
	return nil, &wire.OpenError{Status: wire.OpenRefused}
}

func TestDirectFailureUsesExitStatuses(t *testing.T) {
	r, _ := router(t, io.Discard)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	_, _, err := r.Dial(context.Background(), wire.Open{Host: "127.0.0.1", Port: port})
	var oe *wire.OpenError
	if !errors.As(err, &oe) || oe.Status != wire.OpenRefused {
		t.Fatalf("direct dial to a closed port = %v, want OpenError refused", err)
	}
}

func TestBlockLocalDirect(t *testing.T) {
	r := New(rules.NewTable(rules.Config{}), &fakeExits{}, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{BlockLocalDirect: true})
	dst := listener(t) // a real local service the proxy must not expose
	for _, host := range []string{dst.Host, "localhost", "::1", "169.254.169.254", "10.0.0.1", "0.0.0.0"} {
		_, _, err := r.Dial(context.Background(), wire.Open{Host: host, Port: dst.Port})
		var oe *wire.OpenError
		if !errors.As(err, &oe) || oe.Status != wire.OpenDenied {
			t.Errorf("direct dial to %s = %v, want denied", host, err)
		}
	}
}
