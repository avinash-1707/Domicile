// Package secret compares credentials without leaking them through timing.
package secret

import (
	"crypto/sha256"
	"crypto/subtle"
)

// Equal reports whether got equals want in time that depends on neither
// value. Hashing first gives both sides a fixed length, which
// subtle.ConstantTimeCompare needs to be constant time.
func Equal(got, want string) bool {
	g, w := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}

// Check reports whether creds holds name with value got. Unknown names are
// compared too, so timing does not reveal which names exist.
func Check(creds map[string]string, name, got string) bool {
	want, ok := creds[name]
	return Equal(got, want) && ok
}
