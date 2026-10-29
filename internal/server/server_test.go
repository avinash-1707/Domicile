package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/exit"
	"github.com/avinash-1707/domicile/internal/secret"
	"github.com/avinash-1707/domicile/internal/server"
	"github.com/avinash-1707/domicile/internal/state"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/quictun"
	"github.com/avinash-1707/domicile/internal/wire"
)

// Short timers so liveness tests finish fast; production uses the defaults.
var testQUIC = quictun.Config{KeepAlivePeriod: 100 * time.Millisecond, MaxIdleTimeout: 600 * time.Millisecond}

type harness struct {
	t         *testing.T
	cert      tls.Certificate
	pin       certs.Fingerprint
	statePath string
	live      *state.Live
	srv       *server.Server
	addr      string
	stop      func()
	logOut    io.Writer
}

// The exit "home" is paired with this credential in every harness.
const homeCredential = "secret-token"

// testDestinations lets the exit reach the loopback test servers, which its
// deny list would otherwise refuse.
var testDestinations = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}

func newHarness(t *testing.T) *harness {
	t.Helper()
	cert, err := certs.SelfSigned("domicile")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := certs.FingerprintOf(cert)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, cert: cert, pin: pin, statePath: filepath.Join(t.TempDir(), "state.json"), logOut: io.Discard}
	err = state.Create(h.statePath, state.State{
		Exits: map[string]state.Exit{"home": {CredentialSHA256: secret.Digest(homeCredential)}},
		Users: map[string]state.User{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.live, err = state.OpenLive(h.statePath); err != nil {
		t.Fatal(err)
	}
	h.start("127.0.0.1:0")
	return h
}

// issueToken stores a one-time join token for exit, as `domicile add` does.
func (h *harness) issueToken(exit string, ttl time.Duration) string {
	h.t.Helper()
	tok, err := state.NewSecret()
	if err != nil {
		h.t.Fatal(err)
	}
	err = state.Update(h.statePath, func(st *state.State) error {
		e := st.Exits[exit]
		e.Join = &state.JoinToken{SHA256: secret.Digest(tok), Expires: time.Now().Add(ttl)}
		st.Exits[exit] = e
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

func (h *harness) dialer(addr string) func(context.Context) (tunnel.Session, error) {
	return func(ctx context.Context) (tunnel.Session, error) {
		return quictun.Dial(ctx, addr, certs.PinnedClientConfig(h.pin, tunnel.ALPN), testQUIC)
	}
}

// start runs a server on addr; restarting on the same addr simulates a
// server reboot.
func (h *harness) start(addr string) {
	h.t.Helper()
	cfg := testQUIC
	cfg.MaxIncomingStreams = 1 // the exit only ever opens the hello stream
	l, err := quictun.Listen(addr, certs.ServerConfig(h.cert, tunnel.ALPN), cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := server.New(server.Config{Auth: h.live, Logger: slog.New(slog.NewTextHandler(h.logOut, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		// Serve closes the exit sessions before returning, so closing the
		// listener afterwards is a clean shutdown.
		if err := srv.Serve(ctx, l); err != nil {
			h.t.Error(err)
		}
		l.Close()
	}()
	h.srv = srv
	h.addr = l.Addr().String()
	h.stop = sync.OnceFunc(func() {
		cancel()
		<-stopped
	})
	h.t.Cleanup(h.stop)
}

// runExit starts an exit dialing serverAddr and returns its Run result.
func (h *harness) runExit(serverAddr, token string) <-chan error {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- exit.Run(ctx, exit.Config{
			Name:       "home",
			Credential: token,
			Dial:       h.dialer(serverAddr),
			Allow:      testDestinations,
			Logger:     quietLogger(),
		})
	}()
	h.t.Cleanup(func() {
		cancel()
		<-finished
	})
	return done
}

func (h *harness) waitConnected(want bool, within time.Duration) {
	h.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if h.srv.Connected("home") == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("exit connected = %v after %v, want %v", !want, within, want)
}

func TestJoinThenConnect(t *testing.T) {
	h := newHarness(t)
	tok := h.issueToken("office", time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cred, err := exit.Join(ctx, h.dialer(h.addr), "office", tok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exit.Join(ctx, h.dialer(h.addr), "office", tok); !errors.Is(err, exit.ErrJoinRejected) {
		t.Fatalf("second join with the same token = %v, want rejected", err)
	}

	done := make(chan error, 1)
	rctx, stop := context.WithCancel(context.Background())
	defer func() { stop(); <-done }()
	go func() {
		done <- exit.Run(rctx, exit.Config{Name: "office", Credential: cred, Dial: h.dialer(h.addr), Allow: testDestinations, Logger: quietLogger()})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !h.srv.Connected("office") {
		if time.Now().After(deadline) {
			t.Fatal("joined exit did not connect with its new credential")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLogsNeverContainSecrets(t *testing.T) {
	h := newHarness(t)
	var logs syncBuffer
	h.logOut = &logs
	addr := h.addr
	h.stop()
	h.start(addr) // restart with the capturing logger

	tok := h.issueToken("office", time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cred, err := exit.Join(ctx, h.dialer(h.addr), "office", tok)
	if err != nil {
		t.Fatal(err)
	}
	exit.Join(ctx, h.dialer(h.addr), "office", tok) // reuse: rejected and logged
	h.runExit(h.addr, homeCredential)
	h.waitConnected(true, 5*time.Second)
	exit.Join(ctx, h.dialer(h.addr), "home", "guessed-token-value")
	wrong := exit.Run(ctx, exit.Config{Name: "home", Credential: "wrong-credential-value", Dial: h.dialer(h.addr), Logger: quietLogger()})
	if !errors.Is(wrong, exit.ErrUnauthorized) {
		t.Fatalf("wrong credential = %v", wrong)
	}

	// Covers the tunnel server's log; the proxy has its own test.
	out := logs.String()
	for _, secret := range []string{tok, cred, homeCredential, "guessed-token-value", "wrong-credential-value"} {
		if strings.Contains(out, secret) {
			t.Fatalf("server log contains a secret:\n%s", out)
		}
	}
	if !strings.Contains(out, "exit paired") || !strings.Contains(out, "exit rejected") {
		t.Fatalf("expected events missing from the log:\n%s", out)
	}
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestExpiredTokenRejected(t *testing.T) {
	h := newHarness(t)
	tok := h.issueToken("office", -time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := exit.Join(ctx, h.dialer(h.addr), "office", tok); !errors.Is(err, exit.ErrJoinRejected) {
		t.Fatalf("expired token = %v, want rejected", err)
	}
}

func TestRemovedExitIsCutOffAndCannotReconnect(t *testing.T) {
	h := newHarness(t)
	done := h.runExit(h.addr, homeCredential)
	h.waitConnected(true, 5*time.Second)

	// `domicile remove home`, then the server's state watcher.
	if err := state.Update(h.statePath, func(st *state.State) error { delete(st.Exits, "home"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := h.live.Reload(); err != nil {
		t.Fatal(err)
	}
	h.srv.Revalidate()
	h.waitConnected(false, time.Second)

	select {
	case err := <-done:
		if !errors.Is(err, exit.ErrUnauthorized) {
			t.Fatalf("removed exit's Run = %v, want ErrUnauthorized", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("removed exit kept retrying")
	}
}

// revokingAuth accepts one credential check, then reports the exit as
// removed: a `domicile remove` landing between authenticate and register.
type revokingAuth struct {
	digest string
	calls  atomic.Int32
}

func (a *revokingAuth) ExitCredential(string) (string, bool) {
	if a.calls.Add(1) == 1 {
		return a.digest, true
	}
	return "", false
}

func (a *revokingAuth) Join(string, string) (string, error) { return "", errors.New("no joins") }

func TestRevokedDuringHandshakeIsNotRegistered(t *testing.T) {
	cert, _ := certs.SelfSigned("domicile")
	pin, _ := certs.FingerprintOf(cert)
	cfg := testQUIC
	cfg.MaxIncomingStreams = 1
	l, err := quictun.Listen("127.0.0.1:0", certs.ServerConfig(cert, tunnel.ALPN), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	srv := server.New(server.Config{Auth: &revokingAuth{digest: secret.Digest(homeCredential)}, Logger: quietLogger()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, l)

	done := make(chan error, 1)
	rctx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() {
		done <- exit.Run(rctx, exit.Config{
			Name: "home", Credential: homeCredential, Logger: quietLogger(),
			Dial: func(ctx context.Context) (tunnel.Session, error) {
				return quictun.Dial(ctx, l.Addr().String(), certs.PinnedClientConfig(pin, tunnel.ALPN), testQUIC)
			},
		})
	}()
	time.Sleep(500 * time.Millisecond)
	if srv.Connected("home") {
		t.Fatal("a session whose credential was revoked mid-handshake was registered")
	}
}

func TestEchoThroughExit(t *testing.T) {
	h := newHarness(t)
	h.runExit(h.addr, homeCredential)
	h.waitConnected(true, 5*time.Second)

	st := h.dial(echoServer(t))
	defer st.Close()

	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		st.Write(payload)
		st.CloseWrite()
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes, want %d identical bytes", len(got), len(payload))
	}
}

func TestWrongTokenIsFinal(t *testing.T) {
	h := newHarness(t)
	done := h.runExit(h.addr, "wrong-token")
	select {
	case err := <-done:
		if !errors.Is(err, exit.ErrUnauthorized) {
			t.Fatalf("Run returned %v, want ErrUnauthorized", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exit kept retrying with rejected credentials")
	}
	if h.srv.Connected("home") {
		t.Fatal("server registered an exit with a wrong token")
	}
}

func TestWrongTokenLeavesLiveExitAlone(t *testing.T) {
	h := newHarness(t)
	h.runExit(h.addr, homeCredential)
	h.waitConnected(true, 5*time.Second)

	select {
	case err := <-h.runExit(h.addr, "wrong-token"):
		if !errors.Is(err, exit.ErrUnauthorized) {
			t.Fatalf("impostor Run returned %v, want ErrUnauthorized", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("impostor exit was not rejected")
	}
	if !h.srv.Connected("home") {
		t.Fatal("rejected impostor knocked the real exit off")
	}
	st := h.dial(echoServer(t))
	st.Close()
}

func TestUnsupportedVersionGetsFinalReply(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := quictun.Dial(ctx, h.addr, certs.PinnedClientConfig(h.pin, tunnel.ALPN), testQUIC)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	st, err := sess.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// A Hello from a future exit: version 2, otherwise well formed.
	if _, err := st.Write([]byte{wire.Version + 1, byte(wire.HelloAuth), 4, 'h', 'o', 'm', 'e', 1, 'x'}); err != nil {
		t.Fatal(err)
	}
	rep, err := wire.ReadHelloReply(st)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != wire.HelloUnsupportedVersion {
		t.Fatalf("reply = %v, want unsupported_version", rep.Status)
	}
}

func TestPendingSessionsLimitedPerIP(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	idle := func() tunnel.Session {
		sess, err := quictun.Dial(ctx, h.addr, certs.PinnedClientConfig(h.pin, tunnel.ALPN), quictun.Config{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sess.Close() })
		return sess
	}
	// Four sessions that never say hello fill this IP's pending slots.
	var held []tunnel.Session
	for range 4 {
		held = append(held, idle())
	}
	extra := idle()
	select {
	case <-extra.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("fifth unauthenticated session from one IP was not dropped")
	}
	for _, s := range held {
		select {
		case <-s.Done():
			t.Fatal("a session within the per-IP limit was dropped early")
		default:
		}
	}
}

func TestDialReportsDestinationFailure(t *testing.T) {
	h := newHarness(t)
	h.runExit(h.addr, homeCredential)
	h.waitConnected(true, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host, port := splitHostPort(t, closedPort(t))
	_, err := h.srv.Dial(ctx, "home", wire.Open{Host: host, Port: port})
	var oe *wire.OpenError
	if !errors.As(err, &oe) || oe.Status != wire.OpenRefused {
		t.Fatalf("Dial to closed port = %v, want refused", err)
	}

	// The failed stream must not break the session.
	st := h.dial(echoServer(t))
	st.Close()
}

func TestExitRefusesLocalDestinations(t *testing.T) {
	h := newHarness(t)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	defer func() { stop(); <-done }()
	// No Allow list: the deny list applies in full.
	go func() {
		done <- exit.Run(ctx, exit.Config{Name: "home", Credential: homeCredential, Dial: h.dialer(h.addr), Logger: quietLogger()})
	}()
	h.waitConnected(true, 5*time.Second)

	_, port := splitHostPort(t, echoServer(t))
	for _, host := range []string{"192.168.1.1", "localhost", "127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"} {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := h.srv.Dial(dctx, "home", wire.Open{Host: host, Port: port})
		cancel()
		var oe *wire.OpenError
		if !errors.As(err, &oe) || oe.Status != wire.OpenDenied {
			t.Errorf("exit dial to %s = %v, want denied", host, err)
		}
	}
}

func TestDialUnknownExit(t *testing.T) {
	h := newHarness(t)
	_, err := h.srv.Dial(context.Background(), "nobody", wire.Open{Host: "example.com", Port: 443})
	if !errors.Is(err, server.ErrExitDown) {
		t.Fatalf("Dial = %v, want ErrExitDown", err)
	}
}

func TestServerNoticesSilentExitLoss(t *testing.T) {
	h := newHarness(t)
	relay := newUDPRelay(t, h.addr)
	h.runExit(relay.addr(), homeCredential)
	h.waitConnected(true, 5*time.Second)

	// The home link goes dark without any close message (power cut, Wi-Fi drop).
	relay.blackhole.Store(true)
	h.waitConnected(false, 3*time.Second)
}

func TestExitReconnectsAfterServerRestart(t *testing.T) {
	h := newHarness(t)
	h.runExit(h.addr, homeCredential)
	h.waitConnected(true, 5*time.Second)

	addr := h.addr
	h.stop()
	h.start(addr)
	h.waitConnected(true, 10*time.Second)

	st := h.dial(echoServer(t))
	st.Close()
}

func (h *harness) dial(addr string) tunnel.Stream {
	h.t.Helper()
	host, port := splitHostPort(h.t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := h.srv.Dial(ctx, "home", wire.Open{Host: host, Port: port})
	if err != nil {
		h.t.Fatal(err)
	}
	return st
}

func echoServer(t *testing.T) string {
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
			go func() {
				defer c.Close()
				if _, err := io.Copy(c, c); err == nil {
					c.(*net.TCPConn).CloseWrite()
				}
			}()
		}
	}()
	return l.Addr().String()
}

func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func splitHostPort(t testing.TB, addr string) (string, uint16) {
	t.Helper()
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(port)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// udpRelay forwards one client's datagrams to a server and back, and can
// silently drop everything to simulate a dead link.
type udpRelay struct {
	conn      *net.UDPConn
	blackhole atomic.Bool
}

func newUDPRelay(t *testing.T, serverAddr string) *udpRelay {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.Dial("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		front.Close()
		back.Close()
	})
	r := &udpRelay{conn: front}
	var client atomic.Pointer[net.UDPAddr]

	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			client.Store(from)
			if !r.blackhole.Load() {
				back.Write(buf[:n])
			}
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			if c := client.Load(); c != nil && !r.blackhole.Load() {
				front.WriteToUDP(buf[:n], c)
			}
		}
	}()
	return r
}

func (r *udpRelay) addr() string { return r.conn.LocalAddr().String() }
