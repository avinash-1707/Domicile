// Package secret compares credentials without leaking them through timing.
package secret

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// Digest is the stored form of a generated secret: hex SHA-256. Secrets
// are 256-bit random values, so a fast hash is enough.
func Digest(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}

// MatchesDigest reports, in constant time, whether got hashes to digest.
func MatchesDigest(got, digest string) bool {
	return Equal(Digest(got), digest)
}

// Equal reports whether got equals want in time that depends on neither
// value. Hashing first gives both sides a fixed length, which
// subtle.ConstantTimeCompare needs to be constant time.
func Equal(got, want string) bool {
	g, w := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}
