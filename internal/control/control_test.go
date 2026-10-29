package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/wire"
)

// fakeHandler "dials" by connecting to a real local TCP server, wrapped as
// a stream, standing in for a path through an exit.
type fakeHandler struct{}

func (fakeHandler) Exits() []ExitStatus {
	return []ExitStatus{{Name: "home", Connected: true, Paired: true}}
}

func (fakeHandler) DialExit(ctx context.Context, exit string, dst wire.Open) (tunnel.Stream, error) {
	if exit != "home" {
		return nil, errors.New("exit is not connected")
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(dst.Host, strconv.Itoa(int(dst.Port))))
	if err != nil {
		return nil, err
	}
	return tunnel.TCPStream(c.(*net.TCPConn), time.Second), nil
}

func start(t *testing.T) Client {
	t.Helper()
	// Unix socket paths are length-limited, so keep this one short.
	dir, err := os.MkdirTemp("", "dmc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		Serve(ctx, l, fakeHandler{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	t.Cleanup(func() { cancel(); <-done })
	return Client{Path: path}
}

func TestExitsAndDial(t *testing.T) {
	cl := start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exits, err := cl.Exits(ctx)
	if err != nil || len(exits) != 1 || exits[0].Name != "home" || !exits[0].Connected {
		t.Fatalf("Exits = %+v, %v", exits, err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got, _ := io.ReadAll(c)
		c.Write(append([]byte("echo:"), got...))
	}()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	c, err := cl.DialExit(ctx, "home", "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hi"))
	c.(interface{ CloseWrite() error }).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "echo:hi" {
		t.Fatalf("got %q, %v", got, err)
	}

	if _, err := cl.DialExit(ctx, "garage", "127.0.0.1", port); err == nil {
		t.Fatal("dial through an unknown exit succeeded")
	}
}

func TestSocketIsPrivateAndExclusive(t *testing.T) {
	cl := start(t)
	info, err := os.Stat(cl.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %o, want 600", info.Mode().Perm())
	}
	if _, err := Listen(cl.Path); err == nil {
		t.Fatal("a second server took over a live control socket")
	}
}

func TestStaleSocketReplaced(t *testing.T) {
	dir, _ := os.MkdirTemp("", "dmc")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "c.sock")
	// A socket left behind by a crash: bound, then closed without unlinking.
	old, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()
	l, err := Listen(path)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	l.Close()
}

func TestNeverRemovesARegularFile(t *testing.T) {
	dir, _ := os.MkdirTemp("", "dmc")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "domicile.json") // a -control typo for -config
	os.WriteFile(path, []byte(`{"rules":[]}`), 0o644)
	if _, err := Listen(path); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != `{"rules":[]}` {
		t.Fatalf("file damaged: %q, %v", data, err)
	}
}

func TestSocketCreatedPrivate(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir, _ := os.MkdirTemp("", "dmc")
	defer os.RemoveAll(dir)
	os.Chmod(dir, 0o755)
	path := filepath.Join(dir, "c.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket created %o under umask 0, want 600", info.Mode().Perm())
	}
}

func TestOversizedRequestRefused(t *testing.T) {
	cl := start(t)
	c, err := net.Dial("unix", cl.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go c.Write(make([]byte, 64<<10)) // no newline
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, _ := io.ReadAll(c)
	if len(got) > 200 {
		t.Fatalf("server read a 64 KiB request: replied %d bytes", len(got))
	}
}
