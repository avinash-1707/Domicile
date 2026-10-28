// Package quictun implements tunnel sessions over QUIC. Each proxied
// connection is a QUIC stream, so packet loss on one stream does not stall
// the others.
package quictun

import (
	"context"
	"crypto/tls"
	"errors"
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

// defaultMaxIncomingStreams suits the exit side: a browser page opens tens
// of connections, so quic-go's default of 100 is too low for several busy
// agents.
const defaultMaxIncomingStreams = 1000

// Config tunes the QUIC connection. Zero values use quic-go's defaults,
// except KeepAlivePeriod (defaultKeepAlive) and MaxIncomingStreams
// (defaultMaxIncomingStreams).
type Config struct {
	MaxStreamReceiveWindow     uint64
	MaxConnectionReceiveWindow uint64
	KeepAlivePeriod            time.Duration
	MaxIdleTimeout             time.Duration
	// MaxIncomingStreams caps concurrent bidirectional streams the peer may
	// open. Unidirectional streams are never used and always refused.
	MaxIncomingStreams int64
}

func (c Config) quic() *quic.Config {
	keepAlive := c.KeepAlivePeriod
	if keepAlive == 0 {
		keepAlive = defaultKeepAlive
	}
	maxStreams := c.MaxIncomingStreams
	if maxStreams == 0 {
		maxStreams = defaultMaxIncomingStreams
	}
	return &quic.Config{
		MaxStreamReceiveWindow:     c.MaxStreamReceiveWindow,
		MaxConnectionReceiveWindow: c.MaxConnectionReceiveWindow,
		KeepAlivePeriod:            keepAlive,
		MaxIdleTimeout:             c.MaxIdleTimeout,
		MaxIncomingStreams:         maxStreams,
		MaxIncomingUniStreams:      -1,
	}
}

// Listen starts a QUIC listener on addr (UDP). tlsConf must offer tunnel.ALPN.
func Listen(addr string, tlsConf *tls.Config, cfg Config) (tunnel.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("quic listen %s: %w", addr, err)
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("quic listen %s: %w", addr, err)
	}
	// Owning the Transport and socket lets Close release the port at once;
	// quic.ListenAddr keeps it bound while closed connections drain.
	tr := &quic.Transport{Conn: udp}
	l, err := tr.Listen(tlsConf, cfg.quic())
	if err != nil {
		tr.Close()
		udp.Close()
		return nil, fmt.Errorf("quic listen %s: %w", addr, err)
	}
	return &listener{l: l, tr: tr, udp: udp}, nil
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
	l   *quic.Listener
	tr  *quic.Transport
	udp *net.UDPConn
}

func (l *listener) Accept(ctx context.Context) (tunnel.Session, error) {
	conn, err := l.l.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &session{conn: conn}, nil
}

func (l *listener) Addr() net.Addr { return l.l.Addr() }
func (l *listener) Close() error {
	return errors.Join(l.l.Close(), l.tr.Close(), l.udp.Close())
}

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

func (s *session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

func (s *session) Close() error { return s.conn.CloseWithError(0, "") }

type stream struct {
	st          *quic.Stream
	closedWrite atomic.Bool
}

// Stream error codes. They let the peer tell a deliberate stop from an
// abort: both arrive as STOP_SENDING once this side has sent its FIN.
const (
	codeAbort       quic.StreamErrorCode = 1
	codeStopReading quic.StreamErrorCode = 2
)

func (s *stream) Read(p []byte) (int, error) { return s.st.Read(p) }
func (s *stream) Write(p []byte) (int, error) {
	n, err := s.st.Write(p)
	// Only the peer's StopReading earns the sentinel; its aborts, connection
	// errors and local cancels stay as they are.
	var se *quic.StreamError
	if errors.As(err, &se) && se.Remote && se.ErrorCode == codeStopReading {
		err = fmt.Errorf("%w: %w", tunnel.ErrPeerStoppedReading, err)
	}
	return n, err
}

// CloseWrite sends FIN; quic-go's Close only closes the send direction.
func (s *stream) CloseWrite() error {
	s.closedWrite.Store(true)
	return s.st.Close()
}

func (s *stream) StopReading() { s.st.CancelRead(codeStopReading) }

// Close aborts whatever is still open. CancelWrite (not quic-go's Close) is
// used for the send side because it unblocks a Write stuck on flow control,
// is safe concurrently with Write, and sends RESET_STREAM so the peer sees an
// abort instead of a clean end. After a graceful CloseWrite it is skipped, as
// it would discard data the peer has not acknowledged yet.
func (s *stream) Close() error {
	// A no-op if StopReading already ran, so the peer keeps that signal.
	s.st.CancelRead(codeAbort)
	if !s.closedWrite.Load() {
		s.st.CancelWrite(codeAbort)
	}
	return nil
}
