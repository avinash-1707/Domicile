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
	"errors"
	"fmt"
	"math/big"
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
