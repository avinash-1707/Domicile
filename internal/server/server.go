// Package server runs the VPS side of the tunnel. It accepts sessions from
// exits, authenticates each one, and opens streams through a named exit on
// request.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/avinash-1707/domicile/internal/secret"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/wire"
)

// ErrExitDown means the named exit has no live session.
var ErrExitDown = errors.New("exit is not connected")

var errUnauthorized = errors.New("unauthorized exit")

const (
	helloTimeout = 5 * time.Second
	// maxPendingHellos caps sessions that have not authenticated yet, so
	// anyone who can reach the port cannot hold unbounded server state.
	maxPendingHellos = 64
	// maxPendingPerIP stops one host from filling every pending slot and
	// locking out a real exit while it reconnects. QUIC only accepts a
	// session after a completed handshake, so source IPs are not spoofed.
	maxPendingPerIP = 4
	// dropLogEvery rate-limits the "dropping session" warning so a flood
	// does not flood the logs too.
	dropLogEvery = 10 * time.Second
	// rejectGrace lets a rejected exit read the reply before the session is
	// closed; closing at once can drop the reply in flight.
	rejectGrace = 2 * time.Second
)

// Config configures a Server.
type Config struct {
	// Exits maps each exit name to its token.
	// SIMPLIFIED: plain tokens held in memory. Registration (one-time
	// tokens, hashed long-lived credentials, revocation) replaces this.
	Exits map[string]string

	Logger *slog.Logger
}

// Server tracks connected exits.
type Server struct {
	exits map[string]string
	log   *slog.Logger

	pending chan struct{} // semaphore of size maxPendingHellos

	mu        sync.Mutex
	sessions  map[string]tunnel.Session
	pendingIP map[string]int
	lastDrop  time.Time
	dropped   int
	closed    bool
}

// New returns a Server. It does nothing until Serve is called.
func New(cfg Config) *Server {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		exits:     cfg.Exits,
		log:       log,
		pending:   make(chan struct{}, maxPendingHellos),
		sessions:  make(map[string]tunnel.Session),
		pendingIP: make(map[string]int),
	}
}

// Serve accepts exit sessions from l until ctx is cancelled or l fails. On
// return every exit session is closed. It returns nil on cancellation.
func (s *Server) Serve(ctx context.Context, l tunnel.Listener) error {
	defer s.closeAll()
	for {
		sess, err := l.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		ip := hostOf(sess.RemoteAddr())
		if !s.reservePending(ip) {
			s.noteDrop(ip)
			sess.Close()
			continue
		}
		go s.admit(ctx, sess, ip)
	}
}

// Connected reports whether exit currently has a live session.
func (s *Server) Connected(exit string) bool {
	return s.session(exit) != nil
}

// Dial opens a stream through exit to dst. It returns once the exit has
// connected to dst, or with an error: ErrExitDown, a *wire.OpenError
// carrying the exit's reason, or a tunnel error.
func (s *Server) Dial(ctx context.Context, exit string, dst wire.Open) (tunnel.Stream, error) {
	sess := s.session(exit)
	if sess == nil {
		return nil, ErrExitDown
	}
	st, err := sess.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream to %s: %w", exit, err)
	}
	stop := context.AfterFunc(ctx, func() { st.Close() })
	if err := wire.WriteOpen(st, dst); err != nil {
		stop()
		st.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := wire.ReadOpenReply(st); err != nil {
		stop()
		st.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if !stop() {
		// ctx fired after the reply arrived and the stream is already closed.
		return nil, ctx.Err()
	}
	return st, nil
}

func (s *Server) admit(ctx context.Context, sess tunnel.Session, ip string) {
	name, err := s.authenticate(ctx, sess)
	s.releasePending(ip)
	if err != nil {
		s.log.Warn("exit rejected", "err", err)
		sess.Close()
		return
	}
	if !s.register(name, sess) {
		sess.Close()
		return
	}
	s.log.Info("exit connected", "exit", name)

	<-sess.Done()
	if s.unregister(name, sess) {
		s.log.Warn("exit disconnected", "exit", name)
	}
}

func (s *Server) authenticate(ctx context.Context, sess tunnel.Session) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, helloTimeout)
	defer cancel()
	st, err := sess.AcceptStream(ctx)
	if err != nil {
		return "", fmt.Errorf("no hello stream: %w", err)
	}
	defer st.Close()
	stop := context.AfterFunc(ctx, func() { st.Close() })
	defer stop()

	h, err := wire.ReadHello(st)
	if errors.Is(err, wire.ErrVersion) {
		reject(st, sess, wire.HelloUnsupportedVersion)
		return "", fmt.Errorf("read hello: %w", err)
	}
	if err != nil {
		return "", fmt.Errorf("read hello: %w", err)
	}
	if !s.validToken(h) {
		reject(st, sess, wire.HelloUnauthorized)
		return "", fmt.Errorf("%w %q", errUnauthorized, h.Name)
	}
	if err := wire.WriteHelloReply(st, wire.HelloOK); err != nil {
		return "", fmt.Errorf("write hello reply: %w", err)
	}
	if err := st.CloseWrite(); err != nil {
		return "", fmt.Errorf("finish hello: %w", err)
	}
	return h.Name, nil
}

// reject sends a final status and waits briefly for the exit to read it.
func reject(st tunnel.Stream, sess tunnel.Session, status wire.HelloStatus) {
	if err := wire.WriteHelloReply(st, status); err != nil {
		return
	}
	_ = st.CloseWrite()
	select {
	case <-sess.Done():
	case <-time.After(rejectGrace):
	}
}

func (s *Server) validToken(h wire.Hello) bool {
	return secret.Check(s.exits, h.Name, h.Token)
}

// reservePending takes a global and a per-IP pending slot, or neither.
func (s *Server) reservePending(ip string) bool {
	select {
	case s.pending <- struct{}{}:
	default:
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingIP[ip] >= maxPendingPerIP {
		<-s.pending
		return false
	}
	s.pendingIP[ip]++
	return true
}

func (s *Server) releasePending(ip string) {
	s.mu.Lock()
	if s.pendingIP[ip]--; s.pendingIP[ip] <= 0 {
		delete(s.pendingIP, ip)
	}
	s.mu.Unlock()
	<-s.pending
}

func (s *Server) noteDrop(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropped++
	if time.Since(s.lastDrop) < dropLogEvery {
		return
	}
	s.log.Warn("dropping unauthenticated sessions over the limit", "last_ip", ip, "dropped", s.dropped)
	s.lastDrop = time.Now()
	s.dropped = 0
}

// hostOf returns the IP part of addr, or the whole address if it has no port.
func hostOf(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// register records sess as exit's session. A newer session replaces an older
// one: the exit reconnected before the server noticed the old one died.
func (s *Server) register(name string, sess tunnel.Session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if old, ok := s.sessions[name]; ok {
		s.log.Info("exit reconnected, replacing old session", "exit", name)
		old.Close()
	}
	s.sessions[name] = sess
	return true
}

// unregister removes sess if it is still exit's current session.
func (s *Server) unregister(name string, sess tunnel.Session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[name] != sess {
		return false
	}
	delete(s.sessions, name)
	return true
}

func (s *Server) session(name string) tunnel.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[name]
}

func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for name, sess := range s.sessions {
		sess.Close()
		delete(s.sessions, name)
	}
}
