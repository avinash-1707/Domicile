package quictun

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/tunnel/tunneltest"
)

func TestContract(t *testing.T) {
	tunneltest.Run(t,
		func(tlsConf *tls.Config) (tunnel.Listener, error) {
			return Listen("127.0.0.1:0", tlsConf, Config{})
		},
		func(ctx context.Context, addr string, tlsConf *tls.Config) (tunnel.Session, error) {
			return Dial(ctx, addr, tlsConf, Config{})
		},
	)
}
