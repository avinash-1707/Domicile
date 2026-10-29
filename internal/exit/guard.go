package exit

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// errDenied marks a destination the exit refuses: something on or about
// the home network rather than the internet.
var errDenied = errors.New("destination is on the local network; refused")

// deniedPrefixes are never dialled unless explicitly allowed. A compromised
// or prompt-injected agent on the VPS must not reach the user's router,
// NAS or other devices through the exit. Fixed ranges alone do not cover a
// home network (IPv6 global prefixes, a public WAN address), so the guard
// also denies the device's own networks and public address; see guard.
var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("10.0.0.0/8"),     // private
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, cloud metadata
	netip.MustParsePrefix("172.16.0.0/12"),  // private
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF assignments; the home router on DS-Lite (192.0.0.2)
	netip.MustParsePrefix("192.168.0.0/16"), // private
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking; fake-IP ranges of local proxy apps
	netip.MustParsePrefix("224.0.0.0/4"),    // multicast
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, broadcast
	netip.MustParsePrefix("::/96"),          // unspecified, loopback, IPv4-compatible
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64 (RFC 8215)
	netip.MustParsePrefix("2001::/32"),      // Teredo, which embeds IPv4
	netip.MustParsePrefix("2002::/16"),      // 6to4, which embeds IPv4
	netip.MustParsePrefix("fc00::/7"),       // unique local
	netip.MustParsePrefix("fe80::/10"),      // link-local
	netip.MustParsePrefix("fec0::/10"),      // deprecated site-local
	netip.MustParsePrefix("ff00::/8"),       // multicast
}

// nat64 is the well-known NAT64 prefix; its last 32 bits are an IPv4
// address, which must pass the same check.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// destinationAllowed reports whether the exit may connect to ip. allow
// re-opens specific local destinations the device's owner chose; local
// holds the device's own networks and public address.
func destinationAllowed(ip netip.Addr, allow, local []netip.Prefix) bool {
	ip = ip.Unmap().WithZone("")
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	if nat64.Contains(ip) {
		b := ip.As16()
		if !destinationAllowed(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), allow, local) {
			return false
		}
	}
	for _, p := range deniedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	for _, p := range local {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// localNets tracks the device's own networks: every interface address and
// on-link prefix, plus the public address the server reports seeing. With
// native IPv6 every home device has a global address under the home prefix,
// and on a public-IPv4 line the WAN address is the router itself; neither is
// in deniedPrefixes.
type localNets struct {
	public atomic.Pointer[netip.Addr]

	mu      sync.Mutex
	ifaces  []netip.Prefix
	fetched time.Time
	// list is replaced in tests.
	list func() ([]netip.Prefix, error)
}

// ifaceRefresh bounds how stale the interface list can be; IPv6 privacy
// addresses rotate and DHCP leases change.
const ifaceRefresh = 5 * time.Second

func newLocalNets() *localNets { return &localNets{list: interfacePrefixes} }

// setPublic records the address the server sees this exit connect from.
func (n *localNets) setPublic(ip netip.Addr) {
	ip = ip.Unmap().WithZone("")
	n.public.Store(&ip)
}

// prefixes returns the current set. If the interfaces cannot be listed it
// returns an error, and the guard refuses the dial rather than risk the LAN.
func (n *localNets) prefixes() ([]netip.Prefix, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ifaces == nil || time.Since(n.fetched) > ifaceRefresh {
		ps, err := n.list()
		if err != nil {
			return nil, err
		}
		n.ifaces, n.fetched = ps, time.Now()
	}
	out := n.ifaces
	if ip := n.public.Load(); ip != nil && ip.IsValid() {
		out = append(append([]netip.Prefix{}, out...), netip.PrefixFrom(*ip, ip.BitLen()))
	}
	return out, nil
}

func interfacePrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		bits, _ := ipn.Mask.Size()
		ip = ip.Unmap()
		if ip.Is4() && bits > 32 {
			bits -= 96
		}
		out = append(out, netip.PrefixFrom(ip, bits).Masked())
	}
	return out, nil
}

// guard is a net.Dialer Control hook. It runs on the address the socket is
// about to connect to, after DNS and for every address tried, so a hostname
// that resolves (or rebinds) to a local address and every IP literal
// notation are caught alike. Anything it cannot parse is refused.
func guard(allow []netip.Prefix, local *localNets) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return errDenied
		}
		nets, err := local.prefixes()
		if err != nil {
			return errDenied
		}
		if !destinationAllowed(ap.Addr(), allow, nets) {
			return errDenied
		}
		return nil
	}
}
