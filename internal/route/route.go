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
	"sync/atomic"
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
	// BlockLocalDirect refuses direct connections to the VPS itself (any
	// address on its interfaces, public ones included) and to
	// private, link-local (cloud metadata) and unspecified addresses. Set it
	// whenever the proxy is reachable from other hosts: their clients could
	// not reach those addresses without the proxy.
	BlockLocalDirect bool
}

// Router routes connections by rule.
type Router struct {
	table  atomic.Pointer[rules.Table]
	exits  ExitDialer
	direct net.Dialer
	log    *slog.Logger
	// ownAddrs lists the VPS's interface addresses; tests replace it.
	ownAddrs func() ([]netip.Addr, error)
}

// New returns a Router over the given rules.
func New(table *rules.Table, exits ExitDialer, log *slog.Logger, opts Options) *Router {
	if log == nil {
		log = slog.Default()
	}
	r := &Router{exits: exits, log: log, ownAddrs: interfaceAddrs}
	r.table.Store(table)
	if opts.BlockLocalDirect {
		// Control sees the resolved address right before connecting, so a
		// hostname that resolves to a local address is caught too.
		r.direct.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return errLocalDenied
			}
			ip := ap.Addr().Unmap().WithZone("")
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				return errLocalDenied
			}
			// The VPS's own public addresses reach services bound to them,
			// which remote clients could not otherwise get past its firewall.
			// SIMPLIFIED: lists interfaces on every dial; cache them if the
			// exposed proxy ever carries enough direct traffic to notice.
			own, err := r.ownAddrs()
			if err != nil {
				return errLocalDenied
			}
			for _, a := range own {
				if a == ip {
					return errLocalDenied
				}
			}
			return nil
		}
	}
	return r
}

// interfaceAddrs lists the addresses assigned to this host's interfaces.
func interfaceAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

var errLocalDenied = errors.New("direct connection to a local or private address refused")

// Dial connects to dst and returns the stream plus the path it took: an exit
// name, Direct, or "direct (fallback from <exit>)". Destination failures are
// *wire.OpenError on either path, so callers report them the same way.
func (r *Router) Dial(ctx context.Context, dst wire.Open) (tunnel.Stream, string, error) {
	rule, ok := r.table.Load().Match(dst.Host)
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

// SetTable replaces the rules for new connections; open ones keep their path.
func (r *Router) SetTable(t *rules.Table) { r.table.Store(t) }

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
