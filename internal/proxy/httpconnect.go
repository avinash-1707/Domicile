package proxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/avinash-1707/domicile/internal/wire"
)

var (
	errHTTPAuth = errors.New("http connect: authentication failed")
	// errHTTPMalformed replaces net/http's parse errors, which quote the raw
	// request line or header (a Proxy-Authorization value, a URL with its
	// query) and would put them in the logs.
	errHTTPMalformed = errors.New("http connect: malformed request")
)

// httpConnectHandshake reads one proxy request and returns its destination.
// For CONNECT the returned request is nil and the caller tunnels raw bytes.
// For a plain-HTTP request in absolute form (`GET http://host/path`) the
// request is returned for the caller to forward. On a protocol or auth error
// it writes the matching response. Credentials never appear in errors.
func httpConnectHandshake(r *bufio.Reader, w io.Writer, check func(user, pass string) bool) (wire.Open, *http.Request, error) {
	// r is read directly: bytes the client sends right after the request
	// (an early TLS ClientHello) stay buffered in r and are forwarded.
	req, err := http.ReadRequest(r)
	if err != nil {
		_ = writeHTTPStatus(w, http.StatusBadRequest, "")
		return wire.Open{}, nil, errHTTPMalformed
	}
	forward := req.Method != http.MethodConnect
	if forward && (req.URL.Scheme != "http" || req.URL.Host == "") {
		// HTTPS goes through CONNECT; anything else is not a proxy request.
		_ = writeHTTPStatus(w, http.StatusBadRequest, "")
		return wire.Open{}, nil, errors.New("http proxy: only CONNECT or absolute http:// requests are supported")
	}

	user, pass, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !ok || !check(user, pass) {
		_ = writeHTTPStatus(w, http.StatusProxyAuthRequired, "Proxy-Authenticate: Basic realm=\"domicile\"\r\n")
		return wire.Open{}, nil, errHTTPAuth
	}

	authority := req.Host
	if forward {
		authority = req.URL.Host
		if req.URL.Port() == "" {
			authority = net.JoinHostPort(req.URL.Hostname(), "80")
		}
	}
	dst, err := parseAuthority(authority)
	if err != nil {
		_ = writeHTTPStatus(w, http.StatusBadRequest, "")
		return wire.Open{}, nil, fmt.Errorf("http connect: %w", err)
	}
	if !forward {
		return dst, nil, nil
	}
	return dst, req, nil
}

// forwardRequest sends one plain-HTTP request to st, rewritten to origin
// form, with the proxy's own headers removed. Connection: close keeps it to
// one request per connection, so a client cannot steer a later request on
// the same connection to a different host than the one routed.
func forwardRequest(st io.Writer, req *http.Request) error {
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.RequestURI = ""
	req.Close = true
	return req.Write(st)
}

// parseProxyAuth decodes a "Basic base64(user:pass)" header value.
func parseProxyAuth(v string) (user, pass string, ok bool) {
	scheme, enc, found := strings.Cut(v, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok && user != ""
}

// parseAuthority parses a CONNECT target, "host:port" or "[v6]:port".
func parseAuthority(authority string) (wire.Open, error) {
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		return wire.Open{}, errors.New("target is not host:port")
	}
	if host == "" || len(host) > wire.MaxField {
		return wire.Open{}, fmt.Errorf("target host must be 1 to %d bytes", wire.MaxField)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return wire.Open{}, errors.New("target port invalid")
	}
	return wire.Open{Host: host, Port: uint16(port)}, nil
}

// writeHTTPStatus writes a minimal HTTP/1.1 response with no body. extra
// holds additional header lines, each ending in CRLF.
func writeHTTPStatus(w io.Writer, code int, extra string) error {
	// Connection: close tells clients not to retry on this socket; the
	// proxy closes it after any error.
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n%sConnection: close\r\nContent-Length: 0\r\n\r\n", code, http.StatusText(code), extra)
	return err
}
