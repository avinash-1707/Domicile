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

// httpConnectHandshake reads one CONNECT request and returns its destination.
// On a protocol or auth error it writes the matching response. Credentials
// never appear in returned errors.
func httpConnectHandshake(r *bufio.Reader, w io.Writer, check func(user, pass string) bool) (wire.Open, error) {
	// r is read directly: bytes the client sends right after the request
	// (an early TLS ClientHello) stay buffered in r and are forwarded.
	req, err := http.ReadRequest(r)
	if err != nil {
		_ = writeHTTPStatus(w, http.StatusBadRequest, "")
		return wire.Open{}, errHTTPMalformed
	}
	if req.Method != http.MethodConnect {
		_ = writeHTTPStatus(w, http.StatusMethodNotAllowed, "Allow: CONNECT\r\n")
		return wire.Open{}, fmt.Errorf("http connect: method %.16q not supported", req.Method)
	}

	user, pass, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !ok || !check(user, pass) {
		_ = writeHTTPStatus(w, http.StatusProxyAuthRequired, "Proxy-Authenticate: Basic realm=\"domicile\"\r\n")
		return wire.Open{}, errHTTPAuth
	}

	dst, err := parseAuthority(req.Host)
	if err != nil {
		_ = writeHTTPStatus(w, http.StatusBadRequest, "")
		return wire.Open{}, fmt.Errorf("http connect: %w", err)
	}
	return dst, nil
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
