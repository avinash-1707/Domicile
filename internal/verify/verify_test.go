package verify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// vantage is a fake ip-api as seen from one place: the geo answer and the
// resolver the DNS endpoint reports.
type vantage struct {
	ip, isp, resolver string
	hosting, mobile   bool
}

// endpoint serves both ip-api paths for v. The DNS path redirects first,
// like the real service.
func endpoint(t *testing.T, v vantage) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/geo":
			fmt.Fprintf(w, `{"status":"success","query":%q,"country":"India","city":"Indore","timezone":"Asia/Kolkata","isp":%q,"as":"AS1 %s","mobile":%v,"proxy":false,"hosting":%v}`,
				v.ip, v.isp, v.isp, v.mobile, v.hosting)
		case "/dns":
			// Like the real service: a unique name under the same site.
			http.Redirect(w, r, "http://u123.edns.ip-api.test/dns-unique", http.StatusFound)
		case "/dns-unique":
			fmt.Fprintf(w, `{"dns":{"geo":"India - %s","ip":%q}}`, v.isp, v.resolver)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// to dials srv whatever host is asked for, standing in for one path.
func to(srv *httptest.Server) Dialer {
	return func(ctx context.Context, _ string, _ uint16) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}
}

var cfg = Config{GeoURL: "http://ip-api.test/geo", DNSURL: "http://edns.ip-api.test/dns"}

var vps = vantage{ip: "5.75.1.1", isp: "Hetzner Online", resolver: "185.12.64.1", hosting: true}

// run measures the VPS baseline from vpsSide and checks one exit.
func run(exit string, via Dialer, vpsSide Dialer) Report {
	base := Measure(context.Background(), vpsSide, cfg)
	return Run(context.Background(), exit, via, base, cfg)
}

func result(r Report, name string) Check {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{}
}

func TestHealthyExit(t *testing.T) {
	home := vantage{ip: "152.58.24.58", isp: "Reliance Jio", resolver: "49.45.40.102", mobile: true}
	r := run("home", to(endpoint(t, home)), to(endpoint(t, vps)))
	if !r.OK {
		t.Fatalf("healthy exit reported as failing: %+v", r.Checks)
	}
	for name, want := range map[string]Result{"exit ip": OK, "network": OK, "dns": OK, "timezone": Info} {
		if got := result(r, name).Result; got != want {
			t.Errorf("%s = %s, want %s (%s)", name, got, want, result(r, name).Detail)
		}
	}
	if !strings.Contains(result(r, "network").Detail, "mobile") {
		t.Errorf("mobile network not described: %s", result(r, "network").Detail)
	}
	if r.ViaExit.IP != home.ip || r.Direct.IP != vps.ip || r.ExitDNS.IP != home.resolver {
		t.Errorf("report fields = %+v", r)
	}
}

func TestTrafficNotLeavingHome(t *testing.T) {
	// The "exit" answers with the VPS's own address: a broken route.
	r := run("home", to(endpoint(t, vps)), to(endpoint(t, vps)))
	if r.OK || result(r, "exit ip").Result != Fail {
		t.Fatalf("same IP not flagged: %+v", r.Checks)
	}
}

func TestDatacenterExitWarns(t *testing.T) {
	office := vantage{ip: "3.3.3.3", isp: "Amazon", resolver: "3.3.3.53", hosting: true}
	r := run("office", to(endpoint(t, office)), to(endpoint(t, vps)))
	if got := result(r, "network").Result; got != Warn {
		t.Fatalf("hosting exit = %s, want warn", got)
	}
	if !r.OK {
		t.Fatal("a best-effort hint must not fail the report on its own")
	}
}

func TestDNSLeak(t *testing.T) {
	leaky := vantage{ip: "152.58.24.58", isp: "Reliance Jio", resolver: vps.resolver}
	r := run("home", to(endpoint(t, leaky)), to(endpoint(t, vps)))
	if r.OK || result(r, "dns").Result != Fail {
		t.Fatalf("DNS leak not flagged: %+v", r.Checks)
	}
}

func TestSameResolverNetworkWarns(t *testing.T) {
	// Both sides resolve through the same provider from a pool of
	// addresses: different IPs, same network. Not provably a leak.
	home := vantage{ip: "152.58.24.58", isp: "Reliance Jio", resolver: "49.45.40.100"}
	vpsSameISP := vantage{ip: "152.58.24.99", isp: "Reliance Jio", resolver: "49.45.40.173"}
	r := run("home", to(endpoint(t, home)), to(endpoint(t, vpsSameISP)))
	if got := result(r, "dns").Result; got != Warn {
		t.Fatalf("same resolver network = %s, want warn (%s)", got, result(r, "dns").Detail)
	}
}

func TestExitUnreachable(t *testing.T) {
	down := func(context.Context, string, uint16) (net.Conn, error) {
		return nil, errors.New("exit is not connected")
	}
	r := run("home", down, to(endpoint(t, vps)))
	if r.OK || result(r, "exit").Result != Fail || !strings.Contains(result(r, "exit").Detail, "not connected") {
		t.Fatalf("unreachable exit = %+v", r.Checks)
	}
}

func TestHostnamesPassedToExit(t *testing.T) {
	// The exit must receive the hostname, not an IP the VPS resolved, or
	// the DNS check would be meaningless.
	var asked []string
	home := endpoint(t, vantage{ip: "152.58.24.58", isp: "Jio", resolver: "49.45.40.102"})
	via := func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		asked = append(asked, fmt.Sprintf("%s:%d", host, port))
		return to(home)(ctx, host, port)
	}
	run("home", via, to(endpoint(t, vps)))
	if len(asked) < 3 || asked[0] != "ip-api.test:80" || asked[1] != "edns.ip-api.test:80" || asked[2] != "u123.edns.ip-api.test:80" {
		t.Fatalf("exit was asked for %v, want the geo host, the DNS host and the unique redirect host, unresolved", asked)
	}
}

func TestVPSResolverUnknownIsNotOK(t *testing.T) {
	home := endpoint(t, vantage{ip: "152.58.24.58", isp: "Jio", resolver: "49.45.40.102"})
	base := Measure(context.Background(), to(endpoint(t, vps)), cfg)
	base.DNS, base.DNSErr = Resolver{}, errors.New("lookup timed out")
	r := Run(context.Background(), "home", to(home), base, cfg)
	if got := result(r, "dns").Result; got == OK {
		t.Fatalf("dns claimed ok without comparing against the VPS: %s", result(r, "dns").Detail)
	}
}

func TestRedirectToAnotherSiteRefused(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer evil.Close()
	var asked []string
	d := func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		asked = append(asked, host)
		return to(evil)(ctx, host, port)
	}
	if _, err := resolver(context.Background(), d, "http://edns.ip-api.test/json"); err == nil {
		t.Fatal("followed a redirect to another site")
	}
	for _, h := range asked {
		if h == "169.254.169.254" {
			t.Fatal("dialed the metadata address")
		}
	}
}
