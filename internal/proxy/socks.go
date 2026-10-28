package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/avinash-1707/domicile/internal/wire"
)

// SOCKS5 constants from RFC 1928 and RFC 1929.
const (
	socksVersion       = 0x05
	socksAuthVersion   = 0x01
	socksMethodUserPwd = 0x02
	socksMethodNone    = 0xFF // "no acceptable methods"
	socksCmdConnect    = 0x01
	socksAtypIPv4      = 0x01
	socksAtypDomain    = 0x03
	socksAtypIPv6      = 0x04
)

// SOCKS5 reply codes (RFC 1928 section 6).
const (
	socksSucceeded          = 0x00
	socksGeneralFailure     = 0x01
	socksNotAllowed         = 0x02
	socksNetworkUnreachable = 0x03
	socksHostUnreachable    = 0x04
	socksConnRefused        = 0x05
	socksTTLExpired         = 0x06
	socksCmdNotSupported    = 0x07
	socksAtypNotSupported   = 0x08
)

var errSocksAuth = errors.New("socks: authentication failed")

// socksHandshake runs method negotiation, username/password authentication
// and the request, returning the destination. On a protocol error it writes
// the matching reply where RFC 1928 defines one. Credentials are checked
// with check; they never appear in returned errors.
func socksHandshake(r *bufio.Reader, w io.Writer, check func(user, pass string) bool) (wire.Open, error) {
	if err := socksNegotiate(r, w); err != nil {
		return wire.Open{}, err
	}
	if err := socksAuthenticate(r, w, check); err != nil {
		return wire.Open{}, err
	}
	return socksRequest(r, w)
}

func socksNegotiate(r *bufio.Reader, w io.Writer) error {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("socks greeting: %w", err)
	}
	if hdr[0] != socksVersion {
		return fmt.Errorf("socks: version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return fmt.Errorf("socks methods: %w", err)
	}
	for _, m := range methods {
		if m == socksMethodUserPwd {
			_, err := w.Write([]byte{socksVersion, socksMethodUserPwd})
			return err
		}
	}
	// Credentials are mandatory, so a client offering only "no auth" is
	// refused (security rule: never an open proxy).
	_, _ = w.Write([]byte{socksVersion, socksMethodNone})
	return errors.New("socks: client did not offer username/password auth")
}

func socksAuthenticate(r *bufio.Reader, w io.Writer, check func(user, pass string) bool) error {
	ver, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("socks auth: %w", err)
	}
	if ver != socksAuthVersion {
		return fmt.Errorf("socks auth: version %d", ver)
	}
	user, err := readSocksString(r)
	if err != nil {
		return fmt.Errorf("socks auth user: %w", err)
	}
	pass, err := readSocksString(r)
	if err != nil {
		return fmt.Errorf("socks auth password: %w", err)
	}
	if !check(user, pass) {
		_, _ = w.Write([]byte{socksAuthVersion, 0x01})
		return errSocksAuth
	}
	_, err = w.Write([]byte{socksAuthVersion, 0x00})
	return err
}

func socksRequest(r *bufio.Reader, w io.Writer) (wire.Open, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return wire.Open{}, fmt.Errorf("socks request: %w", err)
	}
	if hdr[0] != socksVersion {
		return wire.Open{}, fmt.Errorf("socks request: version %d", hdr[0])
	}
	if hdr[1] != socksCmdConnect {
		_ = socksReply(w, socksCmdNotSupported)
		return wire.Open{}, fmt.Errorf("socks: command %d not supported", hdr[1])
	}

	var host string
	switch hdr[3] {
	case socksAtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return wire.Open{}, fmt.Errorf("socks ipv4: %w", err)
		}
		host = netip.AddrFrom4(b).String()
	case socksAtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return wire.Open{}, fmt.Errorf("socks ipv6: %w", err)
		}
		host = netip.AddrFrom16(b).String()
	case socksAtypDomain:
		// Passed on unresolved: the exit resolves it (socks5h semantics), so
		// the VPS never leaks a datacenter DNS lookup.
		d, err := readSocksString(r)
		if err != nil {
			return wire.Open{}, fmt.Errorf("socks domain: %w", err)
		}
		host = d
	default:
		_ = socksReply(w, socksAtypNotSupported)
		return wire.Open{}, fmt.Errorf("socks: address type %d not supported", hdr[3])
	}

	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return wire.Open{}, fmt.Errorf("socks port: %w", err)
	}
	dst := wire.Open{Host: host, Port: binary.BigEndian.Uint16(port[:])}
	if dst.Port == 0 {
		_ = socksReply(w, socksGeneralFailure)
		return wire.Open{}, errors.New("socks: port 0")
	}
	return dst, nil
}

// socksReply writes a reply with an all-zero bound address; clients of a
// CONNECT proxy do not use it.
func socksReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{socksVersion, code, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// readSocksString reads a one-byte length followed by that many bytes, and
// rejects empty values.
func readSocksString(r *bufio.Reader) (string, error) {
	n, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", errors.New("empty field")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}
