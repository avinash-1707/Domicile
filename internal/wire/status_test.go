package wire

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestDialStatus(t *testing.T) {
	refusedAddr := closedPort(t)
	_, refusedErr := net.Dial("tcp", refusedAddr)

	tests := []struct {
		name string
		err  error
		want OpenStatus
	}{
		{"nil", nil, OpenOK},
		{"dns not found", &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}, OpenDNSFail},
		{"dns timeout counts as dns", &net.DNSError{Err: "timeout", IsTimeout: true}, OpenDNSFail},
		{"real refused", refusedErr, OpenRefused},
		{"context deadline", fmt.Errorf("dial: %w", context.DeadlineExceeded), OpenTimeout},
		{"net timeout", &net.OpError{Op: "dial", Err: timeoutErr{}}, OpenTimeout},
		{"other", errors.New("no route to host"), OpenUnreachable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DialStatus(tt.err); got != tt.want {
				t.Fatalf("DialStatus(%v) = %v, want %v", tt.err, got, tt.want)
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
