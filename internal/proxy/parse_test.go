package proxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/avinash-1707/domicile/internal/wire"
)

func allow(user, pass string) bool { return user == "agent" && pass == "pw" }

// socksPrefix is a greeting offering username/password plus valid
// credentials "agent"/"pw".
var socksPrefix = []byte{5, 1, 2, 1, 5, 'a', 'g', 'e', 'n', 't', 2, 'p', 'w'}

func socks(req ...byte) []byte { return append(append([]byte{}, socksPrefix...), req...) }

func TestSocksHandshake(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want wire.Open
	}{
		{"domain", socks(5, 1, 0, 3, 10, 'r', 'e', 'd', 'd', 'i', 't', '.', 'c', 'o', 'm', 1, 187), wire.Open{Host: "reddit.com", Port: 443}},
		{"ipv4", socks(5, 1, 0, 1, 93, 184, 216, 34, 0, 80), wire.Open{Host: "93.184.216.34", Port: 80}},
		{"ipv6", socks(5, 1, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 22), wire.Open{Host: "2001:db8::1", Port: 22}},
		{"several methods offered", append([]byte{5, 3, 0, 1, 2}, socksPrefix[3:]...), wire.Open{}},
	}
	tests[3].in = append(tests[3].in, 5, 1, 0, 3, 1, 'a', 0, 1)
	tests[3].want = wire.Open{Host: "a", Port: 1}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			got, err := socksHandshake(bufio.NewReader(bytes.NewReader(tt.in)), &out, allow)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
			if want := []byte{5, 2, 1, 0}; !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("server wrote %v, want method select + auth ok %v", out.Bytes(), want)
			}
		})
	}
}

func TestSocksHandshakeRejects(t *testing.T) {
	tests := []struct {
		name      string
		in        []byte
		wantReply []byte // last bytes the server must have written
		wantErr   error
	}{
		{"no auth offered", []byte{5, 1, 0}, []byte{5, 0xFF}, nil},
		{"wrong password", []byte{5, 1, 2, 1, 5, 'a', 'g', 'e', 'n', 't', 2, 'n', 'o'}, []byte{1, 1}, errSocksAuth},
		{"unknown user", []byte{5, 1, 2, 1, 3, 'b', 'o', 'b', 2, 'p', 'w'}, []byte{1, 1}, errSocksAuth},
		{"bind command", socks(5, 2, 0, 1, 1, 2, 3, 4, 0, 80), []byte{5, socksCmdNotSupported}, nil},
		{"udp associate", socks(5, 3, 0, 1, 1, 2, 3, 4, 0, 80), []byte{5, socksCmdNotSupported}, nil},
		{"bad address type", socks(5, 1, 0, 9, 1, 2), []byte{5, socksAtypNotSupported}, nil},
		{"port zero", socks(5, 1, 0, 3, 1, 'a', 0, 0), []byte{5, socksGeneralFailure}, nil},
		{"socks4", []byte{4, 1, 0, 80}, nil, nil},
		{"empty domain", socks(5, 1, 0, 3, 0, 0, 80), nil, nil},
		{"truncated domain", socks(5, 1, 0, 3, 9, 'a'), nil, nil},
		{"truncated greeting", []byte{5, 3, 2}, nil, nil},
		{"empty username", []byte{5, 1, 2, 1, 0, 2, 'p', 'w'}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := socksHandshake(bufio.NewReader(bytes.NewReader(tt.in)), &out, allow)
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantReply != nil && !replyHas(out.Bytes(), tt.wantReply) {
				t.Fatalf("server wrote %v, want it to contain %v", out.Bytes(), tt.wantReply)
			}
			if strings.Contains(err.Error(), "pw") || strings.Contains(err.Error(), "agent") {
				t.Fatalf("error %q leaks credentials", err)
			}
		})
	}
}

func replyHas(out, want []byte) bool { return bytes.Contains(out, want) }

func connectReq(target, auth string) string {
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if auth != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(auth)) + "\r\n"
	}
	return req + "\r\n"
}

func TestHTTPConnectHandshake(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		want       wire.Open
		wantStatus string // empty means success, nothing written
	}{
		{"ok", connectReq("reddit.com:443", "agent:pw"), wire.Open{Host: "reddit.com", Port: 443}, ""},
		{"ipv6", connectReq("[2001:db8::1]:443", "agent:pw"), wire.Open{Host: "2001:db8::1", Port: 443}, ""},
		{"no credentials", connectReq("reddit.com:443", ""), wire.Open{}, "407"},
		{"wrong password", connectReq("reddit.com:443", "agent:nope"), wire.Open{}, "407"},
		{"plain GET without credentials", "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", wire.Open{}, "407"},
		{"absolute https is not a proxy request", "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", wire.Open{}, "400"},
		{"origin-form request", "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", wire.Open{}, "400"},
		{"missing port", connectReq("reddit.com", "agent:pw"), wire.Open{}, "400"},
		{"port zero", connectReq("reddit.com:0", "agent:pw"), wire.Open{}, "400"},
		{"port too big", connectReq("reddit.com:70000", "agent:pw"), wire.Open{}, "400"},
		{"garbage", "\x16\x03\x01 not http\r\n\r\n", wire.Open{}, "400"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			got, _, err := httpConnectHandshake(bufio.NewReader(strings.NewReader(tt.in)), &out, allow)
			if tt.wantStatus == "" {
				if err != nil {
					t.Fatal(err)
				}
				if got != tt.want {
					t.Fatalf("got %+v, want %+v", got, tt.want)
				}
				if out.Len() != 0 {
					t.Fatalf("handshake wrote %q before the dial", out.String())
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.HasPrefix(out.String(), "HTTP/1.1 "+tt.wantStatus) {
				t.Fatalf("response %q, want status %s", out.String(), tt.wantStatus)
			}
			if tt.wantStatus == "407" && !strings.Contains(out.String(), "Proxy-Authenticate: Basic") {
				t.Fatal("407 without Proxy-Authenticate")
			}
		})
	}
}

func TestPlainHTTPRequestForForwarding(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("agent:pw"))
	in := "GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic " + auth + "\r\nProxy-Connection: keep-alive\r\n\r\n"
	dst, req, err := httpConnectHandshake(bufio.NewReader(strings.NewReader(in)), &bytes.Buffer{}, allow)
	if err != nil || req == nil || dst != (wire.Open{Host: "example.com", Port: 80}) {
		t.Fatalf("got %+v, %v, %v", dst, req, err)
	}
	var out bytes.Buffer
	if err := forwardRequest(&out, req); err != nil {
		t.Fatal(err)
	}
	sent := out.String()
	if !strings.HasPrefix(sent, "GET /a?b=1 HTTP/1.1\r\n") {
		t.Fatalf("request line not rewritten to origin form: %q", sent)
	}
	if strings.Contains(sent, "Proxy-") || strings.Contains(sent, auth) {
		t.Fatalf("proxy credentials forwarded to the site: %q", sent)
	}
	if !strings.Contains(sent, "Connection: close") {
		t.Fatalf("not one request per connection: %q", sent)
	}
}

func TestHTTPConnectPasswordWithColon(t *testing.T) {
	check := func(user, pass string) bool { return user == "agent" && pass == "p:w" }
	got, _, err := httpConnectHandshake(bufio.NewReader(strings.NewReader(connectReq("a.com:443", "agent:p:w"))), &bytes.Buffer{}, check)
	if err != nil || got.Host != "a.com" {
		t.Fatalf("password containing ':' was not kept whole: %+v, %v", got, err)
	}
}

func TestHTTPConnectErrorsDoNotQuoteInput(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("agent:pw"))
	for _, in := range []string{
		"CONNECT a.com:443 HTTP/1.1\r\nProxy-Authorization: Basic " + secret + "\x00\r\n\r\n",
		"CONNECT /secret-path?token=" + secret + " HTTP/1.1\r\nProxy-Authorization: Basic " + secret + "\r\n\r\n",
	} {
		_, _, err := httpConnectHandshake(bufio.NewReader(strings.NewReader(in)), &bytes.Buffer{}, allow)
		if err == nil {
			t.Fatal("expected error")
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "secret-path") {
			t.Fatalf("error %q quotes the request", err)
		}
	}
}

func TestHTTPConnectKeepsEarlyData(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(connectReq("a.com:443", "agent:pw") + "EARLY"))
	if _, _, err := httpConnectHandshake(br, &bytes.Buffer{}, allow); err != nil {
		t.Fatal(err)
	}
	rest := make([]byte, 5)
	if _, err := br.Read(rest); err != nil || string(rest) != "EARLY" {
		t.Fatalf("bytes after the request = %q, %v; want EARLY", rest, err)
	}
}

func TestHandshakeLimit(t *testing.T) {
	l := &handshakeLimit{r: strings.NewReader(strings.Repeat("x", 100)), remaining: 10}
	buf := make([]byte, 100)
	n, _ := l.Read(buf)
	if n != 10 {
		t.Fatalf("read %d bytes under a 10-byte limit", n)
	}
	if _, err := l.Read(buf); err == nil {
		t.Fatal("read past the limit")
	}
	l.lift()
	if n, err := l.Read(buf); err != nil || n != 90 {
		t.Fatalf("after lift read %d, %v; want 90", n, err)
	}
}
