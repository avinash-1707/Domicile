package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/exit"
	"github.com/avinash-1707/domicile/internal/proxy"
	"github.com/avinash-1707/domicile/internal/secret"
	"github.com/avinash-1707/domicile/internal/server"
	"github.com/avinash-1707/domicile/internal/state"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/quictun"
	"github.com/avinash-1707/domicile/internal/wire"
)

const (
	proxyUser = "agent"
	proxyPass = "proxy-password-123"
)

// env is a tunnel server with one connected exit and a proxy in front.
type env struct {
	proxyAddr string
	logs      *syncBuffer
}

// newEnv starts the server, an exit named "home" (unless withExit is false)
// and the proxy routing everything through "home".
func newEnv(t *testing.T, withExit bool) *env {
	t.Helper()
	cert, err := certs.SelfSigned("domicile")
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := certs.FingerprintOf(cert)
	l, err := quictun.Listen("127.0.0.1:0", certs.ServerConfig(cert, tunnel.ALPN), quictun.Config{MaxIncomingStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
		l.Close()
	})

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	statePath := filepath.Join(t.TempDir(), "state.json")
	err = state.Create(statePath, state.State{
		Exits: map[string]state.Exit{"home": {CredentialSHA256: secret.Digest("exit-token")}},
		Users: map[string]state.User{},
	})
	if err != nil {
		t.Fatal(err)
	}
	live, err := state.OpenLive(statePath)
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(server.Config{Auth: live, Logger: quiet})
	wg.Go(func() { srv.Serve(ctx, l) })

	if withExit {
		wg.Go(func() {
			exit.Run(ctx, exit.Config{
				Name:       "home",
				Credential: "exit-token",
				// The test destinations are loopback servers.
				Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
				Dial: func(ctx context.Context) (tunnel.Session, error) {
					return quictun.Dial(ctx, l.Addr().String(), certs.PinnedClientConfig(pin, tunnel.ALPN), quictun.Config{})
				},
				Logger: quiet,
			})
		})
		deadline := time.Now().Add(5 * time.Second)
		for !srv.Connected("home") {
			if time.Now().After(deadline) {
				t.Fatal("exit did not connect")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	logs := &syncBuffer{}
	p, err := proxy.New(proxy.Config{
		CheckUser: func(u, p string) bool { return u == proxyUser && secret.Equal(p, proxyPass) },
		Dial: func(ctx context.Context, dst wire.Open) (tunnel.Stream, string, error) {
			st, err := srv.Dial(ctx, "home", dst)
			return st, "home", err
		},
		Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wg.Go(func() { p.Serve(ctx, pl) })
	return &env{proxyAddr: pl.Addr().String(), logs: logs}
}

// uploadThenReply is a destination that reads until the client half-closes,
// then answers with the byte count. It only answers if half-close works.
func uploadThenReply(t *testing.T) (host string, port uint16) {
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
				n, err := io.Copy(io.Discard, c)
				if err != nil {
					return
				}
				fmt.Fprintf(c, "received %d bytes", n)
			}()
		}
	}()
	a := l.Addr().(*net.TCPAddr)
	return "127.0.0.1", uint16(a.Port)
}

// echoAfterEOF is a destination that reads until the client half-closes,
// then sends back exactly what it received, preserving order.
func echoAfterEOF(t *testing.T) string {
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
				got, err := io.ReadAll(c)
				if err == nil {
					c.Write(got)
				}
			}()
		}
	}()
	return l.Addr().String()
}

func socksConnect(t *testing.T, proxyAddr, user, pass, host string, port uint16) (*net.TCPConn, byte) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	msg := []byte{5, 1, 2, 1, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	msg = append(msg, 5, 1, 0, 3, byte(len(host)))
	msg = append(msg, host...)
	msg = append(msg, byte(port>>8), byte(port))
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2+2+10)
	if _, err := io.ReadFull(c, reply[:4]); err != nil {
		return c.(*net.TCPConn), 0xFF
	}
	if reply[3] != 0 { // auth refused
		return c.(*net.TCPConn), 0xFE
	}
	if _, err := io.ReadFull(c, reply[4:]); err != nil {
		t.Fatal(err)
	}
	return c.(*net.TCPConn), reply[5]
}

func httpConnect(t *testing.T, proxyAddr, auth, target, early string) (*net.TCPConn, *bufio.Reader, *http.Response) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if auth != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(auth)) + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"+early); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*net.TCPConn), br, resp
}

func TestSOCKS5ThroughExitWithHalfClose(t *testing.T) {
	e := newEnv(t, true)
	host, port := uploadThenReply(t)
	c, code := socksConnect(t, e.proxyAddr, proxyUser, proxyPass, host, port)
	if code != 0 {
		t.Fatalf("SOCKS reply %d, want success", code)
	}
	upload := bytes.Repeat([]byte("u"), 300<<10)
	if _, err := c.Write(upload); err != nil {
		t.Fatal(err)
	}
	c.CloseWrite() // upload done; the download must still arrive
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("received %d bytes", len(upload)); string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestHTTPConnectThroughExitKeepsEarlyData(t *testing.T) {
	e := newEnv(t, true)
	target := echoAfterEOF(t)
	// "EARLY" is sent in the same write as the request, like a client that
	// does not wait for 200 before its TLS ClientHello.
	c, br, resp := httpConnect(t, e.proxyAddr, proxyUser+":"+proxyPass, target, "EARLY")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if _, err := c.Write([]byte("-more")); err != nil {
		t.Fatal(err)
	}
	c.CloseWrite()
	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "EARLY-more" {
		t.Fatalf("destination received %q, want %q; early data was lost or reordered", got, "EARLY-more")
	}
}

func TestProxyRequiresCredentials(t *testing.T) {
	e := newEnv(t, true)
	host, port := uploadThenReply(t)
	target := fmt.Sprintf("%s:%d", host, port)

	t.Run("socks without auth method", func(t *testing.T) {
		c, err := net.Dial("tcp", e.proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte{5, 1, 0})
		reply := make([]byte, 2)
		if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0xFF {
			t.Fatalf("reply %v, %v; want no-acceptable-methods", reply, err)
		}
	})
	t.Run("socks wrong password", func(t *testing.T) {
		if _, code := socksConnect(t, e.proxyAddr, proxyUser, "wrong", host, port); code != 0xFE {
			t.Fatalf("code %d, want auth refusal", code)
		}
	})
	t.Run("http without credentials", func(t *testing.T) {
		if _, _, resp := httpConnect(t, e.proxyAddr, "", target, ""); resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status %d, want 407", resp.StatusCode)
		}
	})
	t.Run("http wrong password", func(t *testing.T) {
		if _, _, resp := httpConnect(t, e.proxyAddr, proxyUser+":wrong", target, ""); resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status %d, want 407", resp.StatusCode)
		}
	})

	if strings.Contains(e.logs.String(), proxyPass) || strings.Contains(e.logs.String(), "wrong") {
		t.Fatalf("logs contain a password:\n%s", e.logs.String())
	}
}

func TestPlainHTTPThroughExit(t *testing.T) {
	e := newEnv(t, true)
	got := make(chan http.Header, 1)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		io.WriteString(w, "hello over plain http")
	}))
	defer site.Close()

	proxyURL, _ := url.Parse("http://" + proxyUser + ":" + proxyPass + "@" + e.proxyAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := client.Get(site.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello over plain http" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if h := <-got; h.Get("Proxy-Authorization") != "" {
		t.Fatal("the site received the proxy credentials")
	}
	if !strings.Contains(e.logs.String(), "proto=http-forward") {
		t.Fatalf("forwarded request not logged:\n%s", e.logs.String())
	}
}

func TestMalformedRequestDoesNotLogHeaders(t *testing.T) {
	e := newEnv(t, false)
	c, err := net.Dial("tcp", e.proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b64 := base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + proxyPass))
	io.WriteString(c, "CONNECT a.com:443 HTTP/1.1\r\nProxy-Authorization: Basic "+b64+"\x00\r\n\r\n")
	io.ReadAll(c)
	time.Sleep(50 * time.Millisecond)
	if strings.Contains(e.logs.String(), b64) {
		t.Fatalf("log leaks credentials:\n%s", e.logs.String())
	}
}

func TestOversizedHandshakeRejected(t *testing.T) {
	e := newEnv(t, true)
	c, err := net.Dial("tcp", e.proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	auth := base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + proxyPass))
	// Valid credentials, but 20 KiB of headers: over the handshake cap.
	req := "CONNECT " + echoAfterEOF(t) + " HTTP/1.1\r\nProxy-Authorization: Basic " + auth + "\r\nX-Pad: " + strings.Repeat("a", 20<<10) + "\r\n\r\n"
	go io.WriteString(c, req)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err == nil && resp.StatusCode == http.StatusOK {
		t.Fatal("oversized handshake was accepted")
	}
	time.Sleep(50 * time.Millisecond)
	if strings.Contains(e.logs.String(), "msg=proxied") {
		t.Fatal("oversized handshake led to a dial")
	}
}

func TestExitDownFailsClosed(t *testing.T) {
	e := newEnv(t, false)
	if _, code := socksConnect(t, e.proxyAddr, proxyUser, proxyPass, "example.com", 443); code != 0x03 {
		t.Fatalf("SOCKS reply %d, want network unreachable", code)
	}
	_, _, resp := httpConnect(t, e.proxyAddr, proxyUser+":"+proxyPass, "example.com:443", "")
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("X-Domicile-Result") != "exit_down" {
		t.Fatalf("status %d result %q, want 502 exit_down", resp.StatusCode, resp.Header.Get("X-Domicile-Result"))
	}
}

func TestDestinationRefusedReported(t *testing.T) {
	e := newEnv(t, true)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	if _, code := socksConnect(t, e.proxyAddr, proxyUser, proxyPass, "127.0.0.1", port); code != 0x05 {
		t.Fatalf("SOCKS reply %d, want connection refused", code)
	}
}

func TestNewRequiresUsers(t *testing.T) {
	_, err := proxy.New(proxy.Config{Dial: func(context.Context, wire.Open) (tunnel.Stream, string, error) { return nil, "", nil }})
	if err == nil {
		t.Fatal("proxy started without any users")
	}
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
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
