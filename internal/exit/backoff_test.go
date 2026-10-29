package exit

import (
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	low := &backoff{jitter: func(int64) int64 { return 0 }}
	high := &backoff{jitter: func(n int64) int64 { return n - 1 }}

	wantCaps := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, c := range wantCaps {
		if got := low.next(); got != c/2 {
			t.Fatalf("attempt %d: low = %v, want %v", i, got, c/2)
		}
		if got := high.next(); got != c-1 {
			t.Fatalf("attempt %d: high = %v, want %v", i, got, c-1)
		}
	}

	for range 100 {
		low.next() // must not overflow after many attempts
	}
	if got := low.next(); got != backoffMax/2 {
		t.Fatalf("after many attempts = %v, want %v", got, backoffMax/2)
	}
	low.reset()
	if got := low.next(); got != backoffMin/2 {
		t.Fatalf("after reset = %v, want %v", got, backoffMin/2)
	}
}
