package tunnel_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/quictun"
	"github.com/avinash-1707/domicile/internal/tunnel/tunneltest"
)

// stallTimeout is short so the stalled-destination test finishes quickly.
const stallTimeout = 300 * time.Millisecond

func pair(t *testing.T) (server, exit tunnel.Session) {
	return tunneltest.Pair(t,
		func(tlsConf *tls.Config) (tunnel.Listener, error) {
			return quictun.Listen("127.0.0.1:0", tlsConf, quictun.Config{})
		},
		func(ctx context.Context, addr string, tlsConf *tls.Config) (tunnel.Session, error) {
			return quictun.Dial(ctx, addr, tlsConf, quictun.Config{})
		},
	)
}

// tcpServer accepts one connection and hands it to handle.
func tcpServer(t *testing.T, handle func(*net.TCPConn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		handle(c.(*net.TCPConn))
	}()
	return l.Addr().String()
}

// pipeTo connects a fresh stream's exit end to addr through Pipe and returns
// the server end plus Pipe's result.
func pipeTo(t *testing.T, addr string) (tunnel.Stream, <-chan error) {
	t.Helper()
	server, exit := pair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	local, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { local.Close() })
	// QUIC announces a stream with its first byte; the exit end discards it.
	if _, err := local.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	remote, err := exit.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(remote, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- tunnel.Pipe(context.Background(), remote, c.(*net.TCPConn), stallTimeout) }()
	return local, done
}

func TestPipeHalfClosesBothWays(t *testing.T) {
	addr := tcpServer(t, func(c *net.TCPConn) {
		defer c.Close()
		if _, err := io.Copy(c, c); err == nil {
			c.CloseWrite()
		}
	})
	local, done := pipeTo(t, addr)

	payload := make([]byte, 2<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		local.Write(payload)
		local.CloseWrite()
	}()
	got, err := io.ReadAll(local)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes, want %d identical bytes", len(got), len(payload))
	}
	if err := waitDone(t, done); err != nil {
		t.Fatalf("Pipe returned %v after a clean exchange", err)
	}
}

func TestPipeAbortReachesStreamPeer(t *testing.T) {
	addr := tcpServer(t, func(c *net.TCPConn) {
		c.Write([]byte("partial"))
		c.SetLinger(0)
		c.Close() // RST: the destination died mid-response
	})
	local, done := pipeTo(t, addr)

	_, err := io.ReadAll(local)
	if err == nil {
		t.Fatal("stream peer read a reset connection as a clean end")
	}
	if waitDone(t, done) == nil {
		t.Fatal("Pipe returned nil after the destination reset")
	}
}

func TestPipeStreamAbortResetsTCP(t *testing.T) {
	tcpErr := make(chan error, 1)
	addr := tcpServer(t, func(c *net.TCPConn) {
		defer c.Close()
		_, err := io.Copy(io.Discard, c)
		tcpErr <- err
	})
	local, done := pipeTo(t, addr)

	if _, err := local.Write([]byte("some upload")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	local.Close() // the client gave up mid-upload

	select {
	case err := <-tcpErr:
		if err == nil {
			t.Fatal("destination saw a clean end for an aborted upload")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("destination connection still open after stream abort")
	}
	if waitDone(t, done) == nil {
		t.Fatal("Pipe returned nil after the stream was aborted")
	}
}

func TestPipeStreamAbortWhileDestinationStalled(t *testing.T) {
	addr := tcpServer(t, func(c *net.TCPConn) {
		time.Sleep(30 * time.Second) // accepts but never reads
		c.Close()
	})
	local, done := pipeTo(t, addr)

	// Fills the destination's TCP buffers, so Pipe blocks writing to it.
	go local.Write(make([]byte, 64<<20))
	time.Sleep(100 * time.Millisecond)
	local.Close()

	if waitDone(t, done) == nil {
		t.Fatal("Pipe returned nil after the stream was aborted")
	}
}

func TestPipeContextCancelAbortsBothSides(t *testing.T) {
	tcpErr := make(chan error, 1)
	addr := tcpServer(t, func(c *net.TCPConn) {
		defer c.Close()
		_, err := io.Copy(io.Discard, c)
		tcpErr <- err
	})

	server, exit := pair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	local, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	local.Write([]byte{0})
	remote, err := exit.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	pipeCtx, stopPipe := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tunnel.Pipe(pipeCtx, remote, c.(*net.TCPConn), stallTimeout) }()
	time.Sleep(50 * time.Millisecond)
	stopPipe() // the session ended

	if waitDone(t, done) == nil {
		t.Fatal("Pipe returned nil after its context was cancelled")
	}
	select {
	case err := <-tcpErr:
		if err == nil {
			t.Fatal("destination saw a clean end after the session was lost")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("destination still connected after the session was lost")
	}
	if _, err := io.ReadAll(local); err == nil {
		t.Fatal("stream peer read a lost session as a clean end")
	}
}

func waitDone(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Pipe did not return")
		return nil
	}
}
