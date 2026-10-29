// Package verify checks what a website actually sees through an exit: the
// public IP compared with the VPS's, what kind of network it belongs to,
// where DNS was resolved, and the timezone a browser should claim. It makes
// the same requests through the exit and directly from the VPS and compares.
//
// The network classification comes from ip-api.com (decision S-19) and is a
// best-effort hint. The IP and DNS comparisons are facts as far as ip-api's
// answers, which arrive over plain HTTP, can be trusted.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Endpoints used by default. ip-api's free tier is plain HTTP only.
const (
	DefaultGeoURL = "http://ip-api.com/json/?fields=status,message,query,country,city,timezone,isp,as,mobile,proxy,hosting"
	// The DNS endpoint redirects to a unique hostname; whoever resolves that
	// name is the resolver it reports.
	DefaultDNSURL = "http://edns.ip-api.com/json"
)

// Dialer opens a TCP connection to host:port. Through an exit, host is
// passed unresolved so the exit does the lookup.
type Dialer func(ctx context.Context, host string, port uint16) (net.Conn, error)

// Result is one check's verdict.
type Result string

const (
	OK   Result = "ok"
	Fail Result = "fail"
	Warn Result = "warn"
	Info Result = "info"
)

// Check is one line of the report.
type Check struct {
	Name   string `json:"name"`
	Result Result `json:"result"`
	Detail string `json:"detail"`
}

// Location is what the geo endpoint reports for one vantage point.
type Location struct {
	IP       string `json:"ip"`
	ISP      string `json:"isp"`
	ASN      string `json:"asn"`
	Country  string `json:"country"`
	City     string `json:"city"`
	Timezone string `json:"timezone"`
	Hosting  bool   `json:"hosting"`
	Mobile   bool   `json:"mobile"`
	Proxy    bool   `json:"proxy"`
}

// Report is the result for one exit.
type Report struct {
	Exit        string   `json:"exit"`
	OK          bool     `json:"ok"`
	Checks      []Check  `json:"checks"`
	ViaExit     Location `json:"via_exit"`
	Direct      Location `json:"direct"`
	ExitDNS     Resolver `json:"exit_dns"`
	DirectDNS   Resolver `json:"direct_dns"`
	TunnelMilli int64    `json:"tunnel_ms"`
}

// Resolver is the DNS resolver the DNS endpoint saw.
type Resolver struct {
	IP  string `json:"ip"`
	Geo string `json:"geo"`
}

// Config holds the endpoints; zero values use the defaults.
type Config struct {
	GeoURL string
	DNSURL string
}

func (c Config) withDefaults() Config {
	if c.GeoURL == "" {
		c.GeoURL = DefaultGeoURL
	}
	if c.DNSURL == "" {
		c.DNSURL = DefaultDNSURL
	}
	return c
}

// Baseline is what the VPS itself looks like, measured once and compared
// against every exit.
type Baseline struct {
	Location Location
	LocErr   error
	DNS      Resolver
	DNSErr   error
}

// Measure looks up the VPS's own address and resolver.
func Measure(ctx context.Context, direct Dialer, cfg Config) Baseline {
	cfg = cfg.withDefaults()
	var b Baseline
	b.Location, b.LocErr = geo(ctx, direct, cfg.GeoURL)
	b.DNS, b.DNSErr = resolver(ctx, direct, cfg.DNSURL)
	return b
}

// Run checks one exit against the VPS baseline. viaExit dials through it.
func Run(ctx context.Context, exit string, viaExit Dialer, base Baseline, cfg Config) Report {
	cfg = cfg.withDefaults()
	r := Report{Exit: exit}
	add := func(name string, res Result, format string, a ...any) {
		r.Checks = append(r.Checks, Check{Name: name, Result: res, Detail: fmt.Sprintf(format, a...)})
	}

	start := time.Now()
	via, err := geo(ctx, viaExit, cfg.GeoURL)
	r.TunnelMilli = time.Since(start).Milliseconds()
	if err != nil {
		if ctx.Err() != nil {
			// The shared time budget ran out; that says nothing about this exit.
			add("exit", Fail, "verify ran out of time before checking %s", exit)
		} else {
			add("exit", Fail, "could not reach the internet through %s: %v", exit, err)
		}
		return finish(r)
	}
	r.ViaExit = via
	r.Direct = base.Location
	if base.LocErr != nil {
		add("vps", Warn, "could not check the VPS's own address: %v", base.LocErr)
	}

	switch {
	case r.Direct.IP == "":
		add("exit ip", Info, "%s (the VPS's own address is unknown, so not compared)", via.IP)
	case via.IP == r.Direct.IP:
		add("exit ip", Fail, "%s is the VPS's own address: traffic is not leaving through %s", via.IP, exit)
	default:
		add("exit ip", OK, "%s, not the VPS's %s", via.IP, r.Direct.IP)
	}

	kind := "residential"
	if via.Mobile {
		kind = "mobile"
	}
	switch {
	case via.Hosting:
		add("network", Warn, "%s (%s) is listed as hosting/datacenter; sites may treat it like the VPS (hint from ip-api.com)", via.ISP, via.ASN)
	case via.Proxy:
		add("network", Warn, "%s (%s) looks %s but is listed as a proxy/VPN (hint from ip-api.com)", via.ISP, via.ASN, kind)
	default:
		add("network", OK, "%s (%s), looks %s (best-effort hint from ip-api.com)", via.ISP, via.ASN, kind)
	}

	r.ExitDNS, err = resolver(ctx, viaExit, cfg.DNSURL)
	r.DirectDNS = base.DNS
	if err != nil {
		add("dns", Warn, "could not check where DNS is resolved: %v", err)
	} else {
		switch {
		case base.DNSErr != nil || r.DirectDNS.IP == "":
			add("dns", Info, "resolved by %s (%s); the VPS's resolver is unknown, so not compared", r.ExitDNS.IP, r.ExitDNS.Geo)
		case r.ExitDNS.IP == r.DirectDNS.IP:
			add("dns", Fail, "names are resolved by the same resolver address as the VPS, %s (%s): a DNS leak, or both sides use one public resolver", r.ExitDNS.IP, r.ExitDNS.Geo)
		case r.ExitDNS.Geo == r.DirectDNS.Geo:
			// Large providers answer from a pool of addresses, so equal
			// networks with different IPs cannot be told apart: both sides
			// may simply use the same public resolver.
			add("dns", Warn, "the exit and the VPS both resolve through %s, so this cannot tell the two paths apart", r.ExitDNS.Geo)
		default:
			add("dns", OK, "resolved on the exit side by %s (%s), not the VPS's %s", r.ExitDNS.IP, r.ExitDNS.Geo, r.DirectDNS.Geo)
		}
	}

	if via.Timezone != "" {
		add("timezone", Info, "exit is in %s (%s, %s); launch browsers with timezone %s so it matches", via.Timezone, via.City, via.Country, via.Timezone)
	}
	add("tunnel", Info, "first request through the exit took %d ms", r.TunnelMilli)
	return finish(r)
}

func finish(r Report) Report {
	r.OK = true
	for _, c := range r.Checks {
		if c.Result == Fail {
			r.OK = false
		}
	}
	return r
}

// maxRedirects allows the DNS endpoint's one hop with room to spare.
const maxRedirects = 3

func client(d Dialer) *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		// Answers come over plain HTTP, so a redirect must stay on the same
		// site: otherwise a forged answer could point verify at a service
		// on the VPS itself.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to %s refused", req.URL.Scheme)
			}
			orig, host := via[0].URL.Hostname(), req.URL.Hostname()
			if host != orig && !strings.HasSuffix(host, "."+orig) {
				return fmt.Errorf("redirect to another site (%s) refused", host)
			}
			return nil
		},
		Transport: &http.Transport{
			Proxy: nil, // never pick up a proxy from the environment
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				host, p, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				port, err := strconv.ParseUint(p, 10, 16)
				if err != nil {
					return nil, err
				}
				return d(ctx, host, uint16(port))
			},
			DisableKeepAlives: true,
		},
	}
}

func getJSON(ctx context.Context, d Dialer, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client(d).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(v)
}

func geo(ctx context.Context, d Dialer, url string) (Location, error) {
	var g struct {
		Status   string `json:"status"`
		Message  string `json:"message"`
		Query    string `json:"query"`
		Country  string `json:"country"`
		City     string `json:"city"`
		Timezone string `json:"timezone"`
		ISP      string `json:"isp"`
		AS       string `json:"as"`
		Mobile   bool   `json:"mobile"`
		Proxy    bool   `json:"proxy"`
		Hosting  bool   `json:"hosting"`
	}
	if err := getJSON(ctx, d, url, &g); err != nil {
		return Location{}, err
	}
	if g.Status != "success" || g.Query == "" {
		return Location{}, errors.New("lookup failed: " + g.Message)
	}
	return Location{IP: g.Query, ISP: g.ISP, ASN: g.AS, Country: g.Country, City: g.City, Timezone: g.Timezone, Hosting: g.Hosting, Mobile: g.Mobile, Proxy: g.Proxy}, nil
}

func resolver(ctx context.Context, d Dialer, url string) (Resolver, error) {
	var e struct {
		DNS Resolver `json:"dns"`
	}
	if err := getJSON(ctx, d, url, &e); err != nil {
		return Resolver{}, err
	}
	if e.DNS.IP == "" {
		return Resolver{}, errors.New("no resolver in the answer")
	}
	return e.DNS, nil
}
