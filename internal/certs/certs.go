// Package certs creates the server's self-signed certificate and the pinned
// TLS configs both sides use. Exits trust the server by certificate
// fingerprint, delivered with the registration token, so no CA is involved.
package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Fingerprint is the SHA-256 of a certificate's DER encoding.
type Fingerprint [sha256.Size]byte

// SelfSigned creates an ECDSA P-256 certificate valid for ten years. Validity
// is long because trust comes from the pinned fingerprint, not expiry.
func SelfSigned(commonName string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{commonName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// FingerprintOf returns the fingerprint of the leaf certificate.
func FingerprintOf(cert tls.Certificate) (Fingerprint, error) {
	if len(cert.Certificate) == 0 {
		return Fingerprint{}, errors.New("certificate chain is empty")
	}
	return sha256.Sum256(cert.Certificate[0]), nil
}

// ServerConfig returns a TLS 1.3 server config presenting cert.
func ServerConfig(cert tls.Certificate, alpn string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
		MinVersion:   tls.VersionTLS13,
	}
}

// PinnedClientConfig returns a TLS 1.3 client config that accepts only a
// server whose leaf certificate matches pin.
func PinnedClientConfig(pin Fingerprint, alpn string) *tls.Config {
	return &tls.Config{
		NextProtos: []string{alpn},
		MinVersion: tls.VersionTLS13,
		// Chain and hostname verification are replaced by the pin check below.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !bytes.Equal(got[:], pin[:]) {
				return errors.New("server certificate does not match pinned fingerprint")
			}
			return nil
		},
	}
}

// String returns the fingerprint as lowercase hex, the form users copy into
// the exit's configuration.
func (f Fingerprint) String() string { return hex.EncodeToString(f[:]) }

// ParseFingerprint parses the hex form produced by Fingerprint.String.
func ParseFingerprint(s string) (Fingerprint, error) {
	var f Fingerprint
	b, err := hex.DecodeString(s)
	if err != nil {
		return f, fmt.Errorf("fingerprint is not hex: %w", err)
	}
	if len(b) != len(f) {
		return f, fmt.Errorf("fingerprint is %d bytes, want %d", len(b), len(f))
	}
	copy(f[:], b)
	return f, nil
}

const (
	certFile = "server.crt"
	keyFile  = "server.key"
)

// LoadOrCreate loads the server certificate from dir, creating dir and a new
// certificate on first run. The certificate must survive restarts: every
// exit pins its fingerprint. If only one of the two files exists it returns
// an error rather than replace the identity exits already trust.
func LoadOrCreate(dir string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load server certificate: %w", err)
		}
		return cert, nil
	case !errors.Is(certErr, fs.ErrNotExist) || !errors.Is(keyErr, fs.ErrNotExist):
		return tls.Certificate{}, fmt.Errorf("server certificate in %s is incomplete or unreadable (cert: %v, key: %v); restore it or remove both files to create a new identity (exits must then be re-paired)", dir, certErr, keyErr)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("create state dir: %w", err)
	}
	cert, err := SelfSigned("domicile")
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("encode key: %w", err)
	}
	// The key is written first so a crash in between leaves no certificate
	// without its key.
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeNew(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})); err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

// writeNew creates path with owner-only permissions and fails if it exists.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	return f.Close()
}
