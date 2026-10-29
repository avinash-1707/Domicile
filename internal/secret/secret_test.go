package secret

import "testing"

func TestMatchesDigest(t *testing.T) {
	d := Digest("correct horse")
	if !MatchesDigest("correct horse", d) {
		t.Fatal("matching secret rejected")
	}
	for _, bad := range []string{"correct hors", "", "correct horse "} {
		if MatchesDigest(bad, d) {
			t.Fatalf("%q accepted", bad)
		}
	}
	if MatchesDigest("anything", "") {
		t.Fatal("empty digest (unknown name) accepted a secret")
	}
}
