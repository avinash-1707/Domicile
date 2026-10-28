package exit

import (
	"context"
	"errors"
	"net"
	"syscall"

	"github.com/avinash-1707/domicile/internal/wire"
)

// classify maps a destination dial error to the status reported to the
// server. The order matters: a DNS error can also be a timeout, and DNS
// failures are reported as such.
func classify(err error) wire.OpenStatus {
	if err == nil {
		return wire.OpenOK
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return wire.OpenDNSFail
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return wire.OpenRefused
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return wire.OpenTimeout
	}
	return wire.OpenUnreachable
}
