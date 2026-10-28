package main

import (
	"context"
	"crypto/tls"

	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/quictun"
)

type transport struct {
	listen func(addr string, tlsConf *tls.Config) (tunnel.Listener, error)
	dial   func(ctx context.Context, addr string, tlsConf *tls.Config) (tunnel.Session, error)
}

// transports lists what the harness can measure. QUIC was chosen over yamux
// over TLS with this harness; a TCP fallback, if one is ever added, is
// registered here for comparison.
var transports = map[string]transport{
	"quic": {
		listen: func(addr string, tlsConf *tls.Config) (tunnel.Listener, error) {
			return quictun.Listen(addr, tlsConf, quicConfig)
		},
		dial: func(ctx context.Context, addr string, tlsConf *tls.Config) (tunnel.Session, error) {
			return quictun.Dial(ctx, addr, tlsConf, quicConfig)
		},
	},
}

var quicConfig = quictun.Config{
	MaxStreamReceiveWindow:     6 << 20,
	MaxConnectionReceiveWindow: 15 << 20,
}
