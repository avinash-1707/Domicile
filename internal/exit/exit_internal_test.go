package exit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/avinash-1707/domicile/internal/wire"
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

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	refusedAddr := closedPort(t)
	_, refusedErr := net.Dial("tcp", refusedAddr)

	tests := []struct {
		name string
		err  error
		want wire.OpenStatus
	}{
		{"nil", nil, wire.OpenOK},
		{"dns not found", &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}, wire.OpenDNSFail},
		{"dns timeout counts as dns", &net.DNSError{Err: "timeout", IsTimeout: true}, wire.OpenDNSFail},
		{"real refused", refusedErr, wire.OpenRefused},
		{"context deadline", fmt.Errorf("dial: %w", context.DeadlineExceeded), wire.OpenTimeout},
		{"net timeout", &net.OpError{Op: "dial", Err: timeoutErr{}}, wire.OpenTimeout},
		{"other", errors.New("no route to host"), wire.OpenUnreachable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.err); got != tt.want {
				t.Fatalf("classify(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// closedPort returns a localhost address with nothing listening.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
