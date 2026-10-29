package exit

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestDestinationAllowed(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// Each denied range, with the addresses just inside and outside.
		{"0.0.0.0", false}, {"0.255.255.255", false}, {"1.0.0.0", true},
		{"9.255.255.255", true}, {"10.0.0.0", false}, {"10.255.255.255", false}, {"11.0.0.0", true},
		{"100.63.255.255", true}, {"100.64.0.0", false}, {"100.127.255.255", false}, {"100.128.0.0", true},
		{"126.255.255.255", true}, {"127.0.0.1", false}, {"127.255.255.255", false}, {"128.0.0.0", true},
		{"169.253.255.255", true}, {"169.254.169.254", false}, {"169.255.0.0", true},
		{"172.15.255.255", true}, {"172.16.0.0", false}, {"172.31.255.255", false}, {"172.32.0.0", true},
		{"192.167.255.255", true}, {"192.168.1.1", false}, {"192.169.0.0", true},
		{"192.0.0.2", false}, {"192.0.1.0", true}, {"198.18.0.1", false}, {"198.19.255.255", false}, {"198.20.0.0", true},
		{"223.255.255.255", true}, {"224.0.0.1", false}, {"239.255.255.255", false},
		{"240.0.0.1", false}, {"255.255.255.255", false},
		{"93.184.216.34", true}, {"8.8.8.8", true},
		// IPv6.
		{"::", false}, {"::1", false}, {"::2", false}, {"::7f00:1", false},
		{"fc00::1", false}, {"fdff:ffff::1", false}, {"fe00::1", true},
		{"fe80::1", false}, {"febf::1", false}, {"fec0::1", false}, {"ff00::1", false},
		{"2002:c0a8:101::1", false}, {"2001:0:4136:e378::1", false}, {"2001:db8::1", true},
		{"64:ff9b:1::c0a8:101", false},
		{"ff02::1", false}, {"2606:4700::1", true},
		// IPv4 hidden inside IPv6.
		{"::ffff:127.0.0.1", false}, {"::ffff:192.168.1.1", false}, {"::ffff:8.8.8.8", true},
		{"64:ff9b::a00:1", false}, {"64:ff9b::c0a8:101", false}, {"64:ff9b::808:808", true},
		{"fe80::1%eth0", false},
	}
	for _, tt := range tests {
		ip := netip.MustParseAddr(tt.ip)
		if got := destinationAllowed(ip, nil, nil); got != tt.want {
			t.Errorf("destinationAllowed(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestAllowList(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("192.168.1.50/32"), netip.MustParsePrefix("fd00::/64")}
	for ip, want := range map[string]bool{
		"192.168.1.50":         true,
		"::ffff:192.168.1.50":  true,
		"192.168.1.51":         false, // only what was listed
		"fd00::7":              true,
		"10.0.0.1":             false,
		"127.0.0.1":            false,
		"64:ff9b::c0a8:132":    true, // NAT64 form of the allowed address
		"64:ff9b::c0a8:133":    false,
		"2606:4700:4700::1111": true,
	} {
		if got := destinationAllowed(netip.MustParseAddr(ip), allow, nil); got != want {
			t.Errorf("destinationAllowed(%s) = %v, want %v", ip, got, want)
		}
	}
}

// localTarget is a listener the guard must keep the exit away from. It
// counts connections it receives.
func localTarget(t *testing.T) (port string, hits *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	hits = &atomic.Int32{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	_, port, _ = net.SplitHostPort(l.Addr().String())
	return port, hits
}

func TestGuardRefusesLocalTargets(t *testing.T) {
	port, hits := localTarget(t)
	d := &net.Dialer{Control: guard(nil, newLocalNets()), Timeout: 2 * time.Second}
	for _, host := range []string{"127.0.0.1", "localhost", "::ffff:127.0.0.1", "2130706433", "0x7f.1", "017700000001", "127.1"} {
		// Some resolvers treat the odd notations as names and fail; those
		// never reach the guard, so they prove nothing about it.
		if _, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host); err != nil {
			t.Logf("%s does not resolve here; skipped", host)
			continue
		}
		c, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
		if err == nil {
			c.Close()
			t.Errorf("dial %s connected to a local service", host)
			continue
		}
		if !errors.Is(err, errDenied) {
			t.Errorf("dial %s: %v, want denied", host, err)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("local service received %d connections through the guard", n)
	}
}

func TestGuardRefusesOwnAddresses(t *testing.T) {
	// With native IPv6 the device's own global address is outside every
	// fixed private range; a service bound to [::] must still be refused.
	l6, err6 := net.Listen("tcp", "[::]:0")
	l4, err4 := net.Listen("tcp", "0.0.0.0:0")
	if err6 == nil {
		defer l6.Close()
	}
	if err4 == nil {
		defer l4.Close()
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: guard(nil, newLocalNets()), Timeout: time.Second}
	tested := 0
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsPrivate() {
			continue
		}
		l := l4
		if ipn.IP.To4() == nil {
			l = l6
		}
		if l == nil {
			continue
		}
		_, port, _ := net.SplitHostPort(l.Addr().String())
		tested++
		c, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(ipn.IP.String(), port))
		if err == nil {
			c.Close()
			t.Errorf("dial to this device's own address %s connected", ipn.IP)
		} else if !errors.Is(err, errDenied) {
			t.Errorf("dial to own address %s: %v, want denied", ipn.IP, err)
		}
	}
	if tested == 0 {
		t.Skip("this machine has no global addresses to test")
	}
}

func TestGuardRefusesObservedPublicAddress(t *testing.T) {
	// On a public-IPv4 line the address the server sees is the home router.
	n := &localNets{list: func() ([]netip.Prefix, error) { return nil, nil }}
	g := guard(nil, n)
	if err := g("tcp", "203.0.113.7:80", nil); err != nil {
		t.Fatalf("before the server reports it, a public address is fine: %v", err)
	}
	n.setPublic(netip.MustParseAddr("::ffff:203.0.113.7"))
	if err := g("tcp", "203.0.113.7:80", nil); !errors.Is(err, errDenied) {
		t.Fatalf("observed public address = %v, want denied", err)
	}
	if err := g("tcp", "203.0.113.8:80", nil); err != nil {
		t.Fatalf("a neighbouring public address was refused: %v", err)
	}
}

func TestGuardFailsClosed(t *testing.T) {
	ok := &localNets{list: func() ([]netip.Prefix, error) { return nil, nil }}
	if err := guard(nil, ok)("tcp", ":80", nil); !errors.Is(err, errDenied) {
		t.Fatalf("unparseable address = %v, want denied", err)
	}
	broken := &localNets{list: func() ([]netip.Prefix, error) { return nil, errors.New("no interfaces") }}
	if err := guard(nil, broken)("tcp", "93.184.216.34:443", nil); !errors.Is(err, errDenied) {
		t.Fatalf("interface listing failed but dial allowed: %v", err)
	}
}

func TestGuardCatchesDNSRebinding(t *testing.T) {
	// The attacker's DNS answers a public address first and loopback the
	// second time, hoping a check-then-connect sees only the first. The
	// guard checks the address actually being connected, so the rebound
	// lookup is refused.
	port, hits := localTarget(t)
	answers := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")}
	resolver := fakeDNS(t, answers)
	d := &net.Dialer{Control: guard(nil, newLocalNets()), Resolver: resolver, Timeout: 300 * time.Millisecond}
	target := net.JoinHostPort("rebind.example", port)

	// First lookup: a documentation-range public address, allowed by the
	// guard; nothing listens there, so it just fails to connect.
	if _, err := d.DialContext(context.Background(), "tcp", target); errors.Is(err, errDenied) {
		t.Fatalf("public answer was denied: %v", err)
	}
	// Second lookup rebinds to loopback.
	_, err := d.DialContext(context.Background(), "tcp", target)
	if !errors.Is(err, errDenied) {
		t.Fatalf("rebound dial = %v, want denied", err)
	}
	if hits.Load() != 0 {
		t.Fatal("rebinding reached the local service")
	}
}

// fakeDNS serves A records from answers in turn (repeating the last) and
// empty answers for other types, and returns a resolver that uses it.
func fakeDNS(t *testing.T, answers []netip.Addr) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var next atomic.Int32
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			q := buf[:n]
			// The question ends with QTYPE and QCLASS after the name.
			end := 12
			for end < n && q[end] != 0 {
				end += int(q[end]) + 1
			}
			end += 5
			if end > n {
				continue
			}
			qtype := binary.BigEndian.Uint16(q[end-4:])
			resp := append([]byte{}, q[:end]...)
			resp[2], resp[3] = 0x81, 0x80 // response, recursion available
			binary.BigEndian.PutUint16(resp[6:], 0)
			binary.BigEndian.PutUint16(resp[8:], 0)
			binary.BigEndian.PutUint16(resp[10:], 0)
			if qtype == 1 { // A
				i := min(int(next.Add(1))-1, len(answers)-1)
				ip := answers[i].As4()
				binary.BigEndian.PutUint16(resp[6:], 1)
				resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4)
				resp = append(resp, ip[:]...)
			}
			pc.WriteTo(resp, from)
		}
	}()
	addr := pc.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func TestGuardLetsAllowedLocalTargetThrough(t *testing.T) {
	port, hits := localTarget(t)
	d := &net.Dialer{Control: guard([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, newLocalNets())}
	c, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	deadline := time.Now().Add(time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() != 1 {
		t.Fatal("allowed local target was not reached")
	}
}
