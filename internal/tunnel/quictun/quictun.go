// Package quictun implements tunnel sessions over QUIC. Each proxied
// connection is a QUIC stream, so packet loss on one stream does not stall
// the others.
package quictun

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/avinash-1707/domicile/internal/tunnel"
)

// defaultKeepAlive keeps NAT mappings on home routers open and stays well
// under quic-go's 30 s default idle timeout, so idle sessions survive.
const defaultKeepAlive = 15 * time.Second

// Config tunes the QUIC connection. Zero values use quic-go's defaults,
// except KeepAlivePeriod, which defaults to defaultKeepAlive.
type Config struct {
	MaxStreamReceiveWindow     uint64
	MaxConnectionReceiveWindow uint64
	KeepAlivePeriod            time.Duration
	MaxIdleTimeout             time.Duration
}

func (c Config) quic() *quic.Config {
	keepAlive := c.KeepAlivePeriod
	if keepAlive == 0 {
		keepAlive = defaultKeepAlive
	}
	return &quic.Config{
		MaxStreamReceiveWindow:     c.MaxStreamReceiveWindow,
		MaxConnectionReceiveWindow: c.MaxConnectionReceiveWindow,
		KeepAlivePeriod:            keepAlive,
		MaxIdleTimeout:             c.MaxIdleTimeout,
		// A browser page opens tens of connections; the default cap of 100
		// concurrent streams is too low for several busy agents.
		MaxIncomingStreams: 1000,
	}
}

// Listen starts a QUIC listener on addr (UDP). tlsConf must offer tunnel.ALPN.
func Listen(addr string, tlsConf *tls.Config, cfg Config) (tunnel.Listener, error) {
	l, err := quic.ListenAddr(addr, tlsConf, cfg.quic())
	if err != nil {
		return nil, fmt.Errorf("quic listen %s: %w", addr, err)
	}
	return &listener{l: l}, nil
}

// Dial connects to a QUIC tunnel server.
func Dial(ctx context.Context, addr string, tlsConf *tls.Config, cfg Config) (tunnel.Session, error) {
	conn, err := quic.DialAddr(ctx, addr, tlsConf, cfg.quic())
	if err != nil {
		return nil, fmt.Errorf("quic dial %s: %w", addr, err)
	}
	return &session{conn: conn}, nil
}

type listener struct {
	l *quic.Listener
}

func (l *listener) Accept(ctx context.Context) (tunnel.Session, error) {
	conn, err := l.l.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &session{conn: conn}, nil
}

func (l *listener) Addr() net.Addr { return l.l.Addr() }
func (l *listener) Close() error   { return l.l.Close() }

type session struct {
	conn *quic.Conn
}

func (s *session) OpenStream(ctx context.Context) (tunnel.Stream, error) {
	st, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &stream{st: st}, nil
}

func (s *session) AcceptStream(ctx context.Context) (tunnel.Stream, error) {
	st, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &stream{st: st}, nil
}

func (s *session) Done() <-chan struct{} { return s.conn.Context().Done() }

func (s *session) Close() error { return s.conn.CloseWithError(0, "") }

type stream struct {
	st          *quic.Stream
	closedWrite atomic.Bool
}

func (s *stream) Read(p []byte) (int, error)  { return s.st.Read(p) }
func (s *stream) Write(p []byte) (int, error) { return s.st.Write(p) }

// CloseWrite sends FIN; quic-go's Close only closes the send direction.
func (s *stream) CloseWrite() error {
	s.closedWrite.Store(true)
	return s.st.Close()
}

// Close aborts whatever is still open. CancelWrite (not quic-go's Close) is
// used for the send side because it unblocks a Write stuck on flow control,
// is safe concurrently with Write, and sends RESET_STREAM so the peer sees an
// abort instead of a clean end. After a graceful CloseWrite it is skipped, as
// it would discard data the peer has not acknowledged yet.
func (s *stream) Close() error {
	s.st.CancelRead(0)
	if !s.closedWrite.Load() {
		s.st.CancelWrite(0)
	}
	return nil
}
