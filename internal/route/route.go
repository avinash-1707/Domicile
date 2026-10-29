// Package route picks the path for each proxied connection: through the exit
// a rule names, or direct from the VPS when no rule matches.
package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/server"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/wire"
)

// Direct is the path name for connections made from the VPS itself.
const Direct = "direct"

// ExitDialer opens a stream through a named exit; *server.Server satisfies it.
type ExitDialer interface {
	Dial(ctx context.Context, exit string, dst wire.Open) (tunnel.Stream, error)
}

// Options adjust a Router.
type Options struct {
	// BlockLocalDirect refuses direct connections to the VPS itself and to
	// private, link-local (cloud metadata) and unspecified addresses. Set it
	// whenever the proxy is reachable from other hosts: their clients could
	// not reach those addresses without the proxy.
	BlockLocalDirect bool
}

// Router routes connections by rule.
type Router struct {
	table  *rules.Table
	exits  ExitDialer
	direct net.Dialer
	log    *slog.Logger
}

// New returns a Router over the given rules.
func New(table *rules.Table, exits ExitDialer, log *slog.Logger, opts Options) *Router {
	if log == nil {
		log = slog.Default()
	}
	r := &Router{table: table, exits: exits, log: log}
	if opts.BlockLocalDirect {
		// Control sees the resolved address right before connecting, so a
		// hostname that resolves to a local address is caught too.
		r.direct.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return errLocalDenied
			}
			if ip := ap.Addr().Unmap(); ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				return errLocalDenied
			}
			return nil
		}
	}
	return r
}

var errLocalDenied = errors.New("direct connection to a local or private address refused")

// Dial connects to dst and returns the stream plus the path it took: an exit
// name, Direct, or "direct (fallback from <exit>)". Destination failures are
// *wire.OpenError on either path, so callers report them the same way.
func (r *Router) Dial(ctx context.Context, dst wire.Open) (tunnel.Stream, string, error) {
	rule, ok := r.table.Match(dst.Host)
	if !ok {
		st, err := r.dialDirect(ctx, dst)
		return st, Direct, err
	}
	st, err := r.exits.Dial(ctx, rule.Via, dst)
	if errors.Is(err, server.ErrExitDown) && rule.OnExitDown == rules.FallbackDirect {
		// Logged every time: this traffic now leaves from the datacenter IP.
		r.log.Warn("exit down, falling back to direct", "exit", rule.Via, "host", dst.Host, "rule", rule.Match)
		st, err := r.dialDirect(ctx, dst)
		return st, fmt.Sprintf("%s (fallback from %s)", Direct, rule.Via), err
	}
	return st, rule.Via, err
}

// dialDirect connects from the VPS. Failures are reported with the same
// statuses an exit would use.
func (r *Router) dialDirect(ctx context.Context, dst wire.Open) (tunnel.Stream, error) {
	c, err := r.direct.DialContext(ctx, "tcp", net.JoinHostPort(dst.Host, strconv.Itoa(int(dst.Port))))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, errLocalDenied) {
			return nil, &wire.OpenError{Status: wire.OpenDenied}
		}
		return nil, &wire.OpenError{Status: wire.DialStatus(err)}
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("direct dial returned %T", c)
	}
	return tunnel.TCPStream(tc, tunnel.DefaultStallTimeout), nil
}
