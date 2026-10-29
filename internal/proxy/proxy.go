// Package proxy is the local proxy agents connect to on the VPS. One port
// speaks SOCKS5 and HTTP CONNECT; the first byte tells them apart. Both
// require credentials, and neither ever resolves a hostname locally: names
// travel to the exit as written.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/avinash-1707/domicile/internal/server"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/wire"
)

const (
	handshakeTimeout = 10 * time.Second
	// dialTimeout covers the tunnel round trip plus the exit's own DNS and
	// connect timeout.
	dialTimeout = 15 * time.Second
	// replyGrace leaves time to write the dial outcome after a dial that
	// used its whole budget.
	replyGrace = 5 * time.Second
	// maxHandshakeBytes bounds what a client may send before the handshake
	// completes. A CONNECT request or SOCKS exchange is a few hundred bytes.
	maxHandshakeBytes = 16 << 10
)

// DialFunc opens a stream to dst and names the path it took (an exit or
// "direct") for the log.
type DialFunc func(ctx context.Context, dst wire.Open) (st tunnel.Stream, path string, err error)

// Config configures a proxy Server.
type Config struct {
	// CheckUser reports whether user/pass may use the proxy. It is required:
	// the proxy never runs without credentials.
	CheckUser func(user, pass string) bool
	Dial      DialFunc
	// StallTimeout bounds how long a client that stopped reading can hold a
	// connection. Defaults to tunnel.DefaultStallTimeout.
	StallTimeout time.Duration
	Logger       *slog.Logger
}

// Server accepts proxy clients.
type Server struct {
	cfg Config
	log *slog.Logger
}

// New returns a Server. It returns an error without a credential check,
// since the proxy never runs without credentials.
func New(cfg Config) (*Server, error) {
	if cfg.CheckUser == nil {
		return nil, errors.New("proxy: no credential check configured")
	}
	if cfg.Dial == nil {
		return nil, errors.New("proxy: no dial function")
	}
	if cfg.StallTimeout == 0 {
		cfg.StallTimeout = tunnel.DefaultStallTimeout
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, log: log}, nil
}

// Serve accepts clients on l until ctx is cancelled or accepting fails, then
// closes l, aborts every open connection and waits for their handlers. It
// returns nil on cancellation.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	// Handlers get their own context so a failing listener also tears them
	// down; otherwise Serve would wait on live connections and never return.
	hctx, cancelHandlers := context.WithCancel(ctx)
	stop := context.AfterFunc(hctx, func() { l.Close() })
	var wg sync.WaitGroup
	defer func() {
		cancelHandlers()
		stop()
		l.Close()
		wg.Wait()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("proxy accept: %w", err)
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			c.Close()
			return fmt.Errorf("proxy: listener returned %T, want *net.TCPConn", c)
		}
		wg.Go(func() { s.handle(hctx, tc) })
	}
}

func (s *Server) handle(ctx context.Context, c *net.TCPConn) {
	start := time.Now()
	// Shutdown must not wait out a client that is mid-handshake.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	limit := &handshakeLimit{r: c, remaining: maxHandshakeBytes}
	br := bufio.NewReader(limit)
	if err := c.SetDeadline(start.Add(handshakeTimeout)); err != nil {
		c.Close()
		return
	}

	first, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	proto := "http"
	var dst wire.Open
	var fwd *http.Request
	if first[0] == socksVersion {
		proto = "socks5"
		dst, err = socksHandshake(br, c, s.cfg.CheckUser)
	} else {
		dst, fwd, err = httpConnectHandshake(br, c, s.cfg.CheckUser)
	}
	if err != nil {
		// Auth failures are logged without the attempted credentials.
		s.log.Info("proxy handshake failed", "proto", proto, "err", err)
		c.Close()
		return
	}
	limit.lift()
	// The dial and its reply get their own budget; the handshake deadline
	// would otherwise cut off slow but reportable outcomes like a timeout.
	if err := c.SetDeadline(time.Now().Add(dialTimeout + replyGrace)); err != nil {
		c.Close()
		return
	}

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	st, path, err := s.cfg.Dial(dctx, dst)
	cancel()
	o := outcomeOf(err)
	if err != nil {
		s.log.Info("proxy connect failed", "proto", proto, "host", dst.Host, "port", dst.Port, "via", path, "result", o.reason, "err", err)
		s.reply(c, proto, o)
		c.Close()
		return
	}
	if fwd != nil {
		s.forward(ctx, c, st, fwd, dst, path, start)
		return
	}
	if err := s.reply(c, proto, o); err != nil {
		st.Close()
		c.Close()
		return
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		st.Close()
		c.Close()
		return
	}
	// From here Pipe alone owns teardown: a plain Close racing its abort
	// could end a cut connection with FIN instead of RST.
	if !stop() {
		st.Close()
		c.Close()
		return
	}

	pipeErr := tunnel.Pipe(ctx, st, &bufferedConn{TCPConn: c, r: br}, s.cfg.StallTimeout)
	attrs := []any{"proto", proto, "host", dst.Host, "port", dst.Port, "via", path, "duration", time.Since(start).Round(time.Millisecond)}
	var pe *tunnel.PipeError
	switch {
	case pipeErr == nil:
		s.log.Info("proxied", append(attrs, "result", "ok")...)
	case errors.As(pipeErr, &pe) && !pe.ToConn && pe.OtherDone:
		// The whole response reached the client; only the client's last
		// bytes were cut, typically a TLS close the server no longer read.
		s.log.Info("proxied", append(attrs, "result", "ok", "upload_cut", pe.Err)...)
	case ctx.Err() != nil:
		s.log.Info("proxied", append(attrs, "result", "shutdown")...)
	case errors.As(pipeErr, &pe) && pe.ConnFailed():
		// The client hung up or reset, usually right after getting what it
		// wanted; the destination side was fine.
		s.log.Info("proxied", append(attrs, "result", "client_closed", "err", pe.Err)...)
	default:
		s.log.Info("proxied", append(attrs, "result", "aborted", "err", pipeErr)...)
	}
}

func (s *Server) reply(w io.Writer, proto string, o outcome) error {
	if proto == "socks5" {
		return socksReply(w, o.socks)
	}
	if o.http == http.StatusOK {
		_, err := io.WriteString(w, "HTTP/1.1 200 Connection Established\r\n\r\n")
		return err
	}
	return writeHTTPStatus(w, o.http, "X-Domicile-Result: "+o.reason+"\r\n")
}

// forward sends one plain-HTTP request through st and relays the response.
// The connection carries that single exchange and is then closed.
func (s *Server) forward(ctx context.Context, c *net.TCPConn, st tunnel.Stream, req *http.Request, dst wire.Open, path string, start time.Time) {
	defer st.Close()
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { st.Close(); c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Time{})
	attrs := []any{"proto", "http-forward", "host", dst.Host, "port", dst.Port, "via", path}

	if err := forwardRequest(st, req); err != nil {
		s.log.Info("proxied", append(attrs, "result", "aborted", "err", err)...)
		_ = c.SetLinger(0)
		return
	}
	// No half-close after the request: some servers drop a request whose
	// client sent FIN. Connection: close ends the exchange instead.
	if _, err := io.Copy(stallWriter(c, s.cfg.StallTimeout), st); err != nil {
		// The response was cut: reset the client rather than end cleanly.
		_ = c.SetLinger(0)
		s.log.Info("proxied", append(attrs, "result", "aborted", "err", err)...)
		return
	}
	_ = c.CloseWrite()
	s.log.Info("proxied", append(attrs, "result", "ok", "duration", time.Since(start).Round(time.Millisecond))...)
}

// stallWriter fails a write to c that makes no progress for timeout.
func stallWriter(c *net.TCPConn, timeout time.Duration) io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		if err := c.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return 0, err
		}
		return c.Write(p)
	})
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// outcome is how a dial result is reported to each kind of client.
type outcome struct {
	socks  byte
	http   int
	reason string
}

// outcomeOf maps a dial error to client-visible codes. The proxy never
// retries on its own; only the router's fallback_direct rules choose another
// path.
func outcomeOf(err error) outcome {
	if err == nil {
		return outcome{socks: socksSucceeded, http: http.StatusOK, reason: "ok"}
	}
	if errors.Is(err, server.ErrExitDown) {
		return outcome{socks: socksNetworkUnreachable, http: http.StatusBadGateway, reason: "exit_down"}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return outcome{socks: socksTTLExpired, http: http.StatusGatewayTimeout, reason: "timeout"}
	}
	var oe *wire.OpenError
	if errors.As(err, &oe) {
		switch oe.Status {
		case wire.OpenDNSFail:
			return outcome{socks: socksHostUnreachable, http: http.StatusBadGateway, reason: oe.Status.String()}
		case wire.OpenDenied:
			return outcome{socks: socksNotAllowed, http: http.StatusForbidden, reason: oe.Status.String()}
		case wire.OpenRefused:
			return outcome{socks: socksConnRefused, http: http.StatusBadGateway, reason: oe.Status.String()}
		case wire.OpenTimeout:
			return outcome{socks: socksTTLExpired, http: http.StatusGatewayTimeout, reason: oe.Status.String()}
		case wire.OpenUnreachable:
			return outcome{socks: socksHostUnreachable, http: http.StatusBadGateway, reason: oe.Status.String()}
		}
	}
	return outcome{socks: socksGeneralFailure, http: http.StatusBadGateway, reason: "tunnel_error"}
}

// handshakeLimit caps bytes read until lift is called.
type handshakeLimit struct {
	r         io.Reader
	remaining int64 // negative once lifted
}

func (l *handshakeLimit) Read(p []byte) (int, error) {
	if l.remaining < 0 {
		return l.r.Read(p)
	}
	if l.remaining == 0 {
		return 0, errors.New("proxy: handshake too large")
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

// lift removes the cap once the handshake is done. It runs on the handler's
// goroutine before any other reader exists.
func (l *handshakeLimit) lift() { l.remaining = -1 }

// bufferedConn reads through the handshake's bufio.Reader so bytes the client
// sent early are not lost, and otherwise behaves as the TCP connection.
type bufferedConn struct {
	*net.TCPConn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// WriteTo shadows (*net.TCPConn).WriteTo, which would read the socket
// directly and skip bytes already buffered from the handshake.
func (c *bufferedConn) WriteTo(w io.Writer) (int64, error) { return io.Copy(w, c.r) }
