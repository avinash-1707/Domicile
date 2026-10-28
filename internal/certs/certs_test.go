package certs

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedClientConfig(t *testing.T) {
	serverCert, err := SelfSigned("domicile")
	if err != nil {
		t.Fatal(err)
	}
	otherCert, err := SelfSigned("domicile")
	if err != nil {
		t.Fatal(err)
	}
	goodPin, err := FingerprintOf(serverCert)
	if err != nil {
		t.Fatal(err)
	}
	wrongPin, err := FingerprintOf(otherCert)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		pin     Fingerprint
		wantErr bool
	}{
		{"matching pin", goodPin, false},
		{"different certificate", wrongPin, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handshake(t, ServerConfig(serverCert, "test"), PinnedClientConfig(tt.pin, "test"))
			if (err != nil) != tt.wantErr {
				t.Fatalf("handshake error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func handshake(t *testing.T, serverConf, clientConf *tls.Config) error {
	t.Helper()
	// A real socket, not net.Pipe: an unbuffered pipe deadlocks when the
	// client aborts mid-handshake while the server is still writing.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// The server's result is irrelevant; the client's verdict is under test.
		_ = tls.Server(conn, serverConf).Handshake()
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return tls.Client(conn, clientConf).Handshake()
}

func TestFingerprintOfEmpty(t *testing.T) {
	if _, err := FingerprintOf(tls.Certificate{}); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

func TestLoadOrCreate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := FingerprintOf(first)
	b, _ := FingerprintOf(second)
	if a != b {
		t.Fatal("reloaded certificate has a different fingerprint; exits would lose their pin")
	}

	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode = %o, want 600", perm)
	}

	if err := os.Remove(filepath.Join(dir, certFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("created a new identity while the old key still exists")
	}
}

func TestParseFingerprint(t *testing.T) {
	cert, err := SelfSigned("domicile")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := FingerprintOf(cert)
	got, err := ParseFingerprint(want.String())
	if err != nil || got != want {
		t.Fatalf("round trip = %v, %v", got, err)
	}
	for _, bad := range []string{"", "zz", want.String()[:10]} {
		if _, err := ParseFingerprint(bad); err == nil {
			t.Fatalf("ParseFingerprint(%q) accepted bad input", bad)
		}
	}
}
