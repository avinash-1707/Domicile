package tunnel_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
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
		// Resetting at once can race the client's own connect on some
		// kernels and fail the dial instead of the transfer under test.
		time.Sleep(50 * time.Millisecond)
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

func TestPipeReportsWhichDirectionFailed(t *testing.T) {
	// The destination sends its whole response, then resets while the
	// client is still uploading: download done, upload cut.
	addr := tcpServer(t, func(c *net.TCPConn) {
		c.Write([]byte("response"))
		c.CloseWrite()
		time.Sleep(100 * time.Millisecond)
		c.SetLinger(0)
		c.Close()
	})
	local, done := pipeTo(t, addr)

	got, err := io.ReadAll(local)
	if err != nil || string(got) != "response" {
		t.Fatalf("download = %q, %v; want the full response", got, err)
	}
	go func() {
		for {
			if _, err := local.Write(make([]byte, 32<<10)); err != nil {
				return
			}
		}
	}()

	err = waitDone(t, done)
	var pe *tunnel.PipeError
	if !errors.As(err, &pe) {
		t.Fatalf("Pipe error = %v, want *PipeError", err)
	}
	// Pipe runs on the exit side here, so the client's upload flows from the
	// stream to the destination connection.
	if !pe.ToConn || !pe.OtherDone {
		t.Fatalf("PipeError = %+v, want the stream-to-connection upload to fail after a clean download", pe)
	}
}

func TestPipeFarEndStoppingReadsKeepsUpload(t *testing.T) {
	// Pipe runs on the exit side. The destination streams a large response
	// while it reads the upload; the stream's far end finishes its upload
	// and immediately stops reading the response. Writing the response into
	// the stream then fails, but the upload still in flight must reach the
	// destination in full instead of being reset.
	got := make(chan int64, 1)
	addr := tcpServer(t, func(c *net.TCPConn) {
		defer c.Close()
		go c.Write(make([]byte, 16<<20))
		// Read slowly so the upload is still in flight when the response
		// write is refused.
		var n int64
		buf := make([]byte, 32<<10)
		for {
			m, err := c.Read(buf)
			n += int64(m)
			if err == io.EOF {
				break
			}
			if err != nil {
				n = -1
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		got <- n
	})
	local, done := pipeTo(t, addr)

	upload := make([]byte, 4<<20)
	if _, err := local.Write(upload); err != nil {
		t.Fatal(err)
	}
	if err := local.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	local.StopReading() // a deliberate stop, not an abort

	var n int64
	select {
	case n = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("upload did not complete")
	}
	err := waitDone(t, done)
	if n != int64(len(upload)) {
		t.Fatalf("destination received %d bytes, want all %d without a reset (Pipe: %v)", n, len(upload), err)
	}
	var pe *tunnel.PipeError
	if !errors.As(err, &pe) || pe.ToConn || !pe.OtherDone {
		t.Fatalf("Pipe = %v, want a refused response write after a complete upload", err)
	}
}

func TestPipeLostTunnelIsNotTreatedAsPeerStop(t *testing.T) {
	// Pipe runs on the exit side. The upload is finished; the destination
	// is still sending its response when the whole session dies. That is a
	// cut, not the far end choosing to stop reading: Pipe must abort at once
	// and the destination must not get a clean close.
	destErr := make(chan error, 1)
	addr := tcpServer(t, func(c *net.TCPConn) {
		defer c.Close()
		io.Copy(io.Discard, c) // the upload, until the client's FIN
		buf := make([]byte, 32<<10)
		for {
			if _, err := c.Write(buf); err != nil {
				destErr <- err
				return
			}
		}
	})

	server, exit := pair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	local, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	local.Write([]byte{0})
	remote, err := exit.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadFull(remote, make([]byte, 1))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- tunnel.Pipe(context.Background(), remote, c.(*net.TCPConn), stallTimeout) }()

	local.CloseWrite() // upload complete
	io.ReadFull(local, make([]byte, 64<<10))
	server.Close() // the tunnel drops mid-response

	start := time.Now()
	err = waitDone(t, done)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Pipe took %v to notice the lost tunnel; it lingered as if the peer stopped reading", elapsed)
	}
	if errors.Is(err, tunnel.ErrPeerStoppedReading) {
		t.Fatalf("lost tunnel reported as peer stopped reading: %v", err)
	}
	select {
	case <-destErr:
	case <-time.After(2 * time.Second):
		t.Fatal("destination was not cut off")
	}
}

func TestPipePeerAbortAfterFINIsNotTreatedAsStop(t *testing.T) {
	// Pipe runs on the exit side. The upload is finished; the destination
	// is still sending when the stream's far end aborts (Close after
	// CloseWrite sends only STOP_SENDING). Pipe must abort at once rather
	// than linger as if the far end had merely stopped reading.
	destErr := make(chan error, 1)
	addr := tcpServer(t, func(c *net.TCPConn) {
		defer c.Close()
		io.Copy(io.Discard, c)
		buf := make([]byte, 32<<10)
		for {
			if _, err := c.Write(buf); err != nil {
				destErr <- err
				return
			}
		}
	})
	local, done := pipeTo(t, addr)

	local.CloseWrite()
	io.ReadFull(local, make([]byte, 64<<10))
	local.Close()

	start := time.Now()
	err := waitDone(t, done)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Pipe took %v; it treated an abort as a deliberate stop", elapsed)
	}
	if errors.Is(err, tunnel.ErrPeerStoppedReading) {
		t.Fatalf("abort reported as peer stopped reading: %v", err)
	}
	select {
	case <-destErr:
	case <-time.After(2 * time.Second):
		t.Fatal("destination was not cut off")
	}
}

func TestPipeTCPToTCP(t *testing.T) {
	// The direct path: both sides are TCP. Half-close carries through and a
	// destination reset reaches the client as a reset.
	t.Run("half close", func(t *testing.T) {
		addr := tcpServer(t, func(c *net.TCPConn) {
			defer c.Close()
			n, err := io.Copy(io.Discard, c)
			if err == nil {
				fmt.Fprintf(c, "got %d", n)
				c.CloseWrite()
			}
		})
		client, dst := tcpPair(t, addr)
		done := make(chan error, 1)
		go func() {
			done <- tunnel.Pipe(context.Background(), tunnel.TCPStream(dst, stallTimeout), client.server, stallTimeout)
		}()
		client.conn.Write(make([]byte, 100<<10))
		client.conn.CloseWrite()
		got, err := io.ReadAll(client.conn)
		if err != nil || string(got) != "got 102400" {
			t.Fatalf("got %q, %v", got, err)
		}
		if err := waitDone(t, done); err != nil {
			t.Fatalf("Pipe = %v after a clean exchange", err)
		}
	})
	t.Run("destination reset", func(t *testing.T) {
		addr := tcpServer(t, func(c *net.TCPConn) {
			c.Write([]byte("partial"))
			c.SetLinger(0)
			c.Close()
		})
		client, dst := tcpPair(t, addr)
		done := make(chan error, 1)
		go func() {
			done <- tunnel.Pipe(context.Background(), tunnel.TCPStream(dst, stallTimeout), client.server, stallTimeout)
		}()
		if _, err := io.ReadAll(client.conn); err == nil {
			t.Fatal("client read a reset destination as a clean end")
		}
		if waitDone(t, done) == nil {
			t.Fatal("Pipe returned nil after the destination reset")
		}
	})
}

func TestPipeTCPToTCPEdgeCases(t *testing.T) {
	t.Run("destination never reads", func(t *testing.T) {
		addr := tcpServer(t, func(c *net.TCPConn) {
			time.Sleep(30 * time.Second)
			c.Close()
		})
		client, dst := tcpPair(t, addr)
		done := make(chan error, 1)
		go func() {
			done <- tunnel.Pipe(context.Background(), tunnel.TCPStream(dst, stallTimeout), client.server, stallTimeout)
		}()
		go client.conn.Write(make([]byte, 8<<20))
		if waitDone(t, done) == nil {
			t.Fatal("Pipe returned nil for a stalled destination")
		}
	})

	t.Run("client reset reaches destination as reset", func(t *testing.T) {
		destErr := make(chan error, 1)
		addr := tcpServer(t, func(c *net.TCPConn) {
			defer c.Close()
			_, err := io.Copy(io.Discard, c)
			destErr <- err
		})
		client, dst := tcpPair(t, addr)
		go tunnel.Pipe(context.Background(), tunnel.TCPStream(dst, stallTimeout), client.server, stallTimeout)
		client.conn.Write(make([]byte, 64<<10))
		time.Sleep(50 * time.Millisecond)
		client.conn.SetLinger(0)
		client.conn.Close()
		select {
		case err := <-destErr:
			if err == nil {
				t.Fatal("destination saw a clean end for an upload the client aborted")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("destination never learned of the abort")
		}
	})

	t.Run("write to a closed peer is a stop", func(t *testing.T) {
		gone := make(chan struct{})
		addr := tcpServer(t, func(c *net.TCPConn) {
			c.Close()
			close(gone)
		})
		_, dst := tcpPair(t, addr)
		<-gone
		st := tunnel.TCPStream(dst, stallTimeout)
		var err error
		for range 50 { // the first writes can succeed before the RST comes back
			if _, err = st.Write(make([]byte, 32<<10)); err != nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !errors.Is(err, tunnel.ErrPeerStoppedReading) {
			t.Fatalf("write to a closed peer = %v, want ErrPeerStoppedReading", err)
		}
	})
}

type clientSide struct {
	conn   *net.TCPConn // the client's end
	server *net.TCPConn // the proxy's end of the client connection
}

// tcpPair returns a connected client pair and a connection to addr.
func tcpPair(t *testing.T, addr string) (clientSide, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		accepted <- c
	}()
	cc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sc := <-accepted
	dc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close(); sc.Close(); dc.Close() })
	return clientSide{cc.(*net.TCPConn), sc.(*net.TCPConn)}, dc.(*net.TCPConn)
}

func TestPipeErrorConnFailed(t *testing.T) {
	tests := []struct {
		toConn, write, want bool
	}{
		{true, true, true},   // writing to c failed
		{false, false, true}, // reading from c failed
		{true, false, false}, // reading from the stream failed
		{false, true, false}, // writing to the stream failed
	}
	for _, tt := range tests {
		e := &tunnel.PipeError{ToConn: tt.toConn, Write: tt.write, Err: io.ErrUnexpectedEOF}
		if got := e.ConnFailed(); got != tt.want {
			t.Errorf("ToConn=%v Write=%v: ConnFailed = %v, want %v", tt.toConn, tt.write, got, tt.want)
		}
	}
}
