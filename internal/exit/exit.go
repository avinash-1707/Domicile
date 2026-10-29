// Package exit runs the home side of the tunnel. It keeps one session to the
// server open, authenticates, and connects every stream the server opens to
// the requested destination. Connections only ever go out from home: the exit
// dials the server, never the other way round.
package exit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/wire"
)

// ErrUnauthorized means the server rejected the exit's credential: it was
// revoked with `domicile remove`, or replaced by a newer pairing. Retrying
// cannot help, so Run returns it instead of reconnecting.
var ErrUnauthorized = errors.New("server rejected exit credentials")

// ErrJoinRejected means the server refused a join token: wrong, expired or
// already used.
var ErrJoinRejected = errors.New("server rejected the join code (wrong, expired or already used); run `domicile add` again for a new one")

const (
	defaultDestinationTimeout = 10 * time.Second
	helloTimeout              = 10 * time.Second
	// A session that stayed up this long resets the reconnect backoff.
	stableSession = 30 * time.Second
)

// Config configures an exit.
type Config struct {
	Name       string
	Credential string

	// Dial opens a new session to the server.
	Dial func(ctx context.Context) (tunnel.Session, error)

	// Allow re-opens local destinations the deny list would refuse, such as
	// one device on the home LAN. It is set on the device only; the server
	// cannot change it.
	Allow []netip.Prefix

	// DestinationTimeout bounds DNS resolution plus TCP connect per stream.
	DestinationTimeout time.Duration

	Logger *slog.Logger
}

// Run keeps the exit connected until ctx is cancelled, reconnecting with
// backoff after any failure except ErrUnauthorized. It returns nil when ctx
// is cancelled.
func Run(ctx context.Context, cfg Config) error {

	if cfg.DestinationTimeout == 0 {
		cfg.DestinationTimeout = defaultDestinationTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	log := cfg.Logger.With("exit", cfg.Name)
	// The deny list is part of the dialer itself, so no code path can
	// connect to a destination without passing it.
	local := newLocalNets()
	dialer := &net.Dialer{Control: guard(cfg.Allow, local)}
	// Extra MPTCP subflows would be opened by the kernel without passing
	// through Control.
	dialer.SetMultipathTCP(false)
	b := newBackoff()

	for {
		start := time.Now()
		err := runSession(ctx, cfg, dialer, local, log)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrUnauthorized) || errors.Is(err, wire.ErrVersion) {
			return err
		}
		if time.Since(start) >= stableSession {
			b.reset()
		}
		wait := b.next()
		log.Warn("tunnel down, reconnecting", "err", err, "in", wait.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

func runSession(ctx context.Context, cfg Config, dialer *net.Dialer, local *localNets, log *slog.Logger) error {
	sess, err := cfg.Dial(ctx)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	// Deferred first so it runs last: the session is closed and ctx
	// cancelled before waiting, which ends every stream.
	var streams sync.WaitGroup
	defer streams.Wait()
	defer sess.Close()
	// Streams live no longer than their session, so a lost tunnel always
	// releases the destination connections it was carrying.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	rep, err := hello(ctx, sess, wire.Hello{Kind: wire.HelloAuth, Name: cfg.Name, Secret: cfg.Credential})
	if err != nil {
		return err
	}
	// The server sees this device's public address; on a public-IPv4 line
	// that is the home router, so the exit must refuse to dial it.
	if ip, err := netip.ParseAddr(rep.Observed); err == nil {
		local.setPublic(ip)
	}
	log.Info("connected to server")

	for {
		st, err := sess.AcceptStream(ctx)
		if err != nil {
			return fmt.Errorf("session ended: %w", err)
		}
		streams.Go(func() { serveStream(ctx, st, cfg, dialer, log) })
	}
}

// Join pairs a new exit: it presents the one-time token from `domicile add`
// on a fresh session and returns the long-lived credential the server
// issues. The session is closed afterwards; Run then connects normally.
func Join(ctx context.Context, dial func(context.Context) (tunnel.Session, error), name, token string) (string, error) {
	sess, err := dial(ctx)
	if err != nil {
		return "", fmt.Errorf("connect to server: %w", err)
	}
	defer sess.Close()
	rep, err := hello(ctx, sess, wire.Hello{Kind: wire.HelloJoin, Name: name, Secret: token})
	if errors.Is(err, ErrUnauthorized) {
		return "", ErrJoinRejected
	}
	if err != nil {
		return "", err
	}
	if rep.Credential == "" {
		return "", errors.New("server accepted the join but sent no credential")
	}
	return rep.Credential, nil
}

// hello sends h and returns the server's accepting reply.
func hello(ctx context.Context, sess tunnel.Session, h wire.Hello) (wire.HelloReply, error) {
	ctx, cancel := context.WithTimeout(ctx, helloTimeout)
	defer cancel()
	st, err := sess.OpenStream(ctx)
	if err != nil {
		return wire.HelloReply{}, fmt.Errorf("open hello stream: %w", err)
	}
	defer st.Close()
	stop := context.AfterFunc(ctx, func() { st.Close() })
	defer stop()

	if err := wire.WriteHello(st, h); err != nil {
		return wire.HelloReply{}, fmt.Errorf("send hello: %w", err)
	}
	rep, err := wire.ReadHelloReply(st)
	if err != nil {
		return wire.HelloReply{}, fmt.Errorf("read hello reply: %w", err)
	}
	switch rep.Status {
	case wire.HelloOK:
		return rep, nil
	case wire.HelloUnauthorized:
		return wire.HelloReply{}, ErrUnauthorized
	case wire.HelloUnsupportedVersion:
		return wire.HelloReply{}, fmt.Errorf("server rejected frame version %d: %w", wire.Version, wire.ErrVersion)
	default:
		return wire.HelloReply{}, fmt.Errorf("hello rejected: %s", rep.Status)
	}
}

func serveStream(ctx context.Context, st tunnel.Stream, cfg Config, dialer *net.Dialer, log *slog.Logger) {
	open, err := wire.ReadOpen(st)
	if err != nil {
		log.Warn("bad open frame", "err", err)
		st.Close()
		return
	}
	dst := net.JoinHostPort(open.Host, strconv.Itoa(int(open.Port)))

	dctx, cancel := context.WithTimeout(ctx, cfg.DestinationTimeout)
	conn, err := dialer.DialContext(dctx, "tcp", dst)
	cancel()
	status := wire.DialStatus(err)
	if errors.Is(err, errDenied) {
		status = wire.OpenDenied
	}
	var hc tunnel.HalfCloser
	if err == nil {
		var ok bool
		if hc, ok = conn.(tunnel.HalfCloser); !ok {
			conn.Close()
			log.Error("dialer returned a connection without CloseWrite", "type", fmt.Sprintf("%T", conn))
			status = wire.OpenUnreachable
		}
	}

	if status != wire.OpenOK {
		log.Info("destination failed", "host", open.Host, "status", status)
		// CloseWrite before Close: Close resets the stream, which can
		// discard the reply before it reaches the server.
		if err := wire.WriteOpenReply(st, status); err == nil {
			_ = st.CloseWrite()
		}
		st.Close()
		return
	}
	if err := wire.WriteOpenReply(st, status); err != nil {
		conn.Close()
		st.Close()
		return
	}
	if err := tunnel.Pipe(ctx, st, hc, tunnel.DefaultStallTimeout); err != nil {
		log.Debug("stream ended with error", "host", open.Host, "err", err)
	}
}
