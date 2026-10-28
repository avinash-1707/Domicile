// Package tunneltest checks that a tunnel transport meets the tunnel package
// contract. Each transport's tests call Run with its own constructors.
package tunneltest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/tunnel"
)

// ListenFunc starts a server-side listener on a free localhost port.
type ListenFunc func(tlsConf *tls.Config) (tunnel.Listener, error)

// DialFunc connects an exit to addr.
type DialFunc func(ctx context.Context, addr string, tlsConf *tls.Config) (tunnel.Session, error)

// Pair returns a connected server session and exit session. Both are closed
// when the test ends.
func Pair(t testing.TB, listen ListenFunc, dial DialFunc) (server, exit tunnel.Session) {
	t.Helper()
	cert, err := certs.SelfSigned("domicile")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := certs.FingerprintOf(cert)
	if err != nil {
		t.Fatal(err)
	}
	l, err := listen(certs.ServerConfig(cert, tunnel.ALPN))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	accepted := make(chan tunnel.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		s, err := l.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- s
	}()

	exit, err = dial(ctx, l.Addr().String(), certs.PinnedClientConfig(pin, tunnel.ALPN))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { exit.Close() })

	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server, exit
}

// Run exercises the contract every transport must meet.
func Run(t *testing.T, listen ListenFunc, dial DialFunc) {
	t.Run("EchoBothDirections", func(t *testing.T) {
		server, exit := Pair(t, listen, dial)
		go echo(exit)

		payload := make([]byte, 1<<20)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		got := roundTrip(t, server, payload)
		if !bytes.Equal(got, payload) {
			t.Fatalf("echoed %d bytes, mismatch with %d sent", len(got), len(payload))
		}
	})

	t.Run("ConcurrentStreams", func(t *testing.T) {
		server, exit := Pair(t, listen, dial)
		go echo(exit)

		var wg sync.WaitGroup
		errs := make(chan error, 50)
		for i := range 50 {
			wg.Go(func() {
				payload := bytes.Repeat([]byte{byte(i)}, 32<<10)
				if got := roundTrip(t, server, payload); !bytes.Equal(got, payload) {
					errs <- errors.New("stream payload mismatch")
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	})

	t.Run("AcceptStreamHonorsContext", func(t *testing.T) {
		_, exit := Pair(t, listen, dial)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if _, err := exit.AcceptStream(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("AcceptStream error = %v, want deadline exceeded", err)
		}
	})

	t.Run("CloseUnblocksRead", func(t *testing.T) {
		server, exit := Pair(t, listen, dial)
		local, _ := openAccepted(t, server, exit)

		readErr := make(chan error, 1)
		go func() {
			_, err := local.Read(make([]byte, 1))
			readErr <- err
		}()
		time.Sleep(50 * time.Millisecond) // let Read block
		local.Close()
		if err := waitErr(t, readErr); err == nil {
			t.Fatal("Read returned nil error after Close")
		}
	})

	t.Run("CloseAfterCloseWriteReleasesRead", func(t *testing.T) {
		server, exit := Pair(t, listen, dial)
		local, remote := openAccepted(t, server, exit)

		if err := local.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		readErr := make(chan error, 1)
		go func() {
			_, err := local.Read(make([]byte, 1))
			readErr <- err
		}()
		time.Sleep(50 * time.Millisecond) // let Read block
		local.Close()
		if err := waitErr(t, readErr); err == nil {
			t.Fatal("Read returned nil error after Close")
		}

		// The peer learns we stopped reading, so its writes start failing.
		writeErr := make(chan error, 1)
		go func() {
			for {
				if _, err := remote.Write(make([]byte, 1<<10)); err != nil {
					writeErr <- err
					return
				}
			}
		}()
		if err := waitErr(t, writeErr); err == nil {
			t.Fatal("peer Write kept succeeding after Close")
		}
	})

	t.Run("CloseUnblocksWriteAndAbortsPeer", func(t *testing.T) {
		server, exit := Pair(t, listen, dial)
		local, remote := openAccepted(t, server, exit)

		// The peer never reads, so this write stalls on flow control.
		writeErr := make(chan error, 1)
		go func() {
			_, err := local.Write(make([]byte, 64<<20))
			writeErr <- err
		}()
		time.Sleep(200 * time.Millisecond)
		local.Close()
		if err := waitErr(t, writeErr); err == nil {
			t.Fatal("Write returned nil error after Close")
		}

		readAll := make(chan error, 1)
		go func() {
			_, err := io.Copy(io.Discard, remote)
			readAll <- err
		}()
		if err := waitErr(t, readAll); err == nil {
			t.Fatal("peer read the aborted stream as a clean end")
		}
	})

	t.Run("SessionCloseFailsStreamRead", func(t *testing.T) {
		server, exit := Pair(t, listen, dial)
		_, remote := openAccepted(t, server, exit)

		readAll := make(chan error, 1)
		go func() {
			_, err := io.Copy(io.Discard, remote)
			readAll <- err
		}()
		time.Sleep(50 * time.Millisecond)
		server.Close()
		if err := waitErr(t, readAll); err == nil {
			t.Fatal("stream read ended cleanly after the session died")
		}
	})

	t.Run("ListenerAcceptHonorsContext", func(t *testing.T) {
		cert, err := certs.SelfSigned("domicile")
		if err != nil {
			t.Fatal(err)
		}
		l, err := listen(certs.ServerConfig(cert, tunnel.ALPN))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if _, err := l.Accept(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Accept error = %v, want deadline exceeded", err)
		}
	})

	t.Run("WrongPinRejected", func(t *testing.T) {
		cert, err := certs.SelfSigned("domicile")
		if err != nil {
			t.Fatal(err)
		}
		other, err := certs.SelfSigned("domicile")
		if err != nil {
			t.Fatal(err)
		}
		wrongPin, err := certs.FingerprintOf(other)
		if err != nil {
			t.Fatal(err)
		}
		l, err := listen(certs.ServerConfig(cert, tunnel.ALPN))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if s, err := l.Accept(ctx); err == nil {
				s.Close()
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s, err := dial(ctx, l.Addr().String(), certs.PinnedClientConfig(wrongPin, tunnel.ALPN))
		if err == nil {
			s.Close()
			t.Fatal("dial succeeded against a server with the wrong certificate")
		}
	})

	t.Run("SessionCloseSignalsPeer", func(t *testing.T) {
		server, exit := Pair(t, listen, dial)
		// Some transports only notice a session after the first stream.
		go echo(exit)
		roundTrip(t, server, []byte("x"))

		server.Close()
		select {
		case <-exit.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("exit session not done after server closed it")
		}
	})
}

// openAccepted opens a stream from server and returns it with the exit's end.
// One byte is written so transports that announce streams lazily deliver it;
// the exit end has consumed that byte.
func openAccepted(t testing.TB, server, exit tunnel.Session) (local, remote tunnel.Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	local, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { local.Close() })
	if _, err := local.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	remote, err = exit.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { remote.Close() })
	if _, err := io.ReadFull(remote, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return local, remote
}

// waitErr returns the operation's error, failing the test if it is still
// blocked after a second.
func waitErr(t testing.TB, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal("operation still blocked one second after it should have failed")
		return nil
	}
}

// roundTrip opens a stream, sends payload, half-closes, and reads the reply
// until the peer closes.
func roundTrip(t testing.TB, s tunnel.Session, payload []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := s.OpenStream(ctx)
	if err != nil {
		t.Error(err)
		return nil
	}
	defer st.Close()

	writeErr := make(chan error, 1)
	go func() {
		_, err := st.Write(payload)
		if err == nil {
			err = st.CloseWrite()
		}
		writeErr <- err
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Error(err)
	}
	if err := <-writeErr; err != nil {
		t.Error(err)
	}
	return got
}

// echo copies every accepted stream back to its sender until the session ends.
func echo(s tunnel.Session) {
	for {
		st, err := s.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer st.Close()
			if _, err := io.Copy(st, st); err == nil {
				_ = st.CloseWrite()
			}
		}()
	}
}
