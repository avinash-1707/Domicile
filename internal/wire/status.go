package wire

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// DialStatus maps a destination dial error to the status reported for it.
// The order matters: a DNS error can also be a timeout, and DNS failures are
// reported as such.
func DialStatus(err error) OpenStatus {
	if err == nil {
		return OpenOK
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return OpenDNSFail
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return OpenRefused
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return OpenTimeout
	}
	return OpenUnreachable
}
