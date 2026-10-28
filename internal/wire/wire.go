// Package wire encodes the small control frames sent at the start of tunnel
// streams. Request frames start with a version byte so the two sides can be
// upgraded independently; replies are a single status byte, which every
// version reads the same way.
//
// Hello (exit → server, first stream of a session):
//
//	version | nameLen u8 | name | tokenLen u8 | token
//
// HelloReply (server → exit): status u8
//
// Open (server → exit, first bytes of every proxied stream):
//
//	version | hostLen u8 | host | port u16 big-endian
//
// OpenReply (exit → server): status u8, followed by raw proxied bytes on ok.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is the frame format version this build speaks.
const Version = 1

// ErrVersion means the peer speaks a different frame version.
var ErrVersion = errors.New("wire: unsupported frame version")

// Hello authenticates an exit to the server.
type Hello struct {
	Name  string
	Token string
}

// WriteHello writes h as one frame.
func WriteHello(w io.Writer, h Hello) error {
	if err := checkField("exit name", h.Name); err != nil {
		return err
	}
	if err := checkField("token", h.Token); err != nil {
		return err
	}
	buf := make([]byte, 0, 3+len(h.Name)+len(h.Token))
	buf = append(buf, Version, byte(len(h.Name)))
	buf = append(buf, h.Name...)
	buf = append(buf, byte(len(h.Token)))
	buf = append(buf, h.Token...)
	_, err := w.Write(buf)
	return err
}

// ReadHello reads one Hello frame.
func ReadHello(r io.Reader) (Hello, error) {
	if err := readVersion(r); err != nil {
		return Hello{}, err
	}
	name, err := readField(r, "exit name")
	if err != nil {
		return Hello{}, err
	}
	token, err := readField(r, "token")
	if err != nil {
		return Hello{}, err
	}
	return Hello{Name: name, Token: token}, nil
}

// HelloStatus is the server's answer to a Hello.
type HelloStatus byte

const (
	HelloOK HelloStatus = iota
	HelloUnauthorized
	// HelloUnsupportedVersion means the server does not speak the exit's
	// frame version; the exit must be upgraded.
	HelloUnsupportedVersion
)

func (s HelloStatus) String() string {
	switch s {
	case HelloOK:
		return "ok"
	case HelloUnauthorized:
		return "unauthorized"
	case HelloUnsupportedVersion:
		return "unsupported_version"
	default:
		return fmt.Sprintf("unknown(%d)", byte(s))
	}
}

// WriteHelloReply writes the server's answer.
func WriteHelloReply(w io.Writer, s HelloStatus) error {
	_, err := w.Write([]byte{byte(s)})
	return err
}

// ReadHelloReply reads the server's answer.
func ReadHelloReply(r io.Reader) (HelloStatus, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return HelloStatus(b[0]), nil
}

// Open asks the exit to connect to Host:Port. Host is a hostname or an IP
// literal; the exit resolves it.
type Open struct {
	Host string
	Port uint16
}

// WriteOpen writes o as one frame.
func WriteOpen(w io.Writer, o Open) error {
	if err := checkField("host", o.Host); err != nil {
		return err
	}
	if o.Port == 0 {
		return errors.New("wire: port 0")
	}
	buf := make([]byte, 0, 4+len(o.Host))
	buf = append(buf, Version, byte(len(o.Host)))
	buf = append(buf, o.Host...)
	buf = binary.BigEndian.AppendUint16(buf, o.Port)
	_, err := w.Write(buf)
	return err
}

// ReadOpen reads one Open frame.
func ReadOpen(r io.Reader) (Open, error) {
	if err := readVersion(r); err != nil {
		return Open{}, err
	}
	host, err := readField(r, "host")
	if err != nil {
		return Open{}, err
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Open{}, err
	}
	o := Open{Host: host, Port: binary.BigEndian.Uint16(port[:])}
	if o.Port == 0 {
		return Open{}, errors.New("wire: port 0")
	}
	return o, nil
}

// OpenStatus is the exit's result for an Open.
type OpenStatus byte

const (
	OpenOK OpenStatus = iota
	OpenDNSFail
	// OpenDenied means the exit's deny list refused the destination.
	OpenDenied
	OpenRefused
	OpenTimeout
	OpenUnreachable
)

func (s OpenStatus) String() string {
	switch s {
	case OpenOK:
		return "ok"
	case OpenDNSFail:
		return "dns_fail"
	case OpenDenied:
		return "denied"
	case OpenRefused:
		return "refused"
	case OpenTimeout:
		return "timeout"
	case OpenUnreachable:
		return "unreachable"
	default:
		return fmt.Sprintf("unknown(%d)", byte(s))
	}
}

// OpenError reports a non-ok OpenReply.
type OpenError struct {
	Status OpenStatus
}

func (e *OpenError) Error() string { return "exit could not connect: " + e.Status.String() }

// WriteOpenReply writes the exit's result.
func WriteOpenReply(w io.Writer, s OpenStatus) error {
	_, err := w.Write([]byte{byte(s)})
	return err
}

// ReadOpenReply reads the exit's result. A non-ok status is returned as an
// *OpenError.
func ReadOpenReply(r io.Reader) error {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if s := OpenStatus(b[0]); s != OpenOK {
		return &OpenError{Status: s}
	}
	return nil
}

func readVersion(r io.Reader) error {
	var v [1]byte
	if _, err := io.ReadFull(r, v[:]); err != nil {
		return err
	}
	if v[0] != Version {
		return fmt.Errorf("%w: %d", ErrVersion, v[0])
	}
	return nil
}

// MaxField is the longest exit name, token or host a frame can carry.
const MaxField = 255

// checkField enforces the u8 length prefix and rejects empty values.
func checkField(name, v string) error {
	if v == "" {
		return fmt.Errorf("wire: empty %s", name)
	}
	if len(v) > MaxField {
		return fmt.Errorf("wire: %s longer than %d bytes", name, MaxField)
	}
	return nil
}

func readField(r io.Reader, name string) (string, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return "", err
	}
	if n[0] == 0 {
		return "", fmt.Errorf("wire: empty %s", name)
	}
	b := make([]byte, n[0])
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}
