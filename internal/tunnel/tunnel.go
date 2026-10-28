// Package tunnel defines the long-lived link between the VPS server and a
// home exit. The exit dials the server; the server opens one stream per
// proxied connection; the exit accepts each stream and dials the destination.
//
// Transport implementations live in subpackages.
package tunnel

import (
	"context"
	"io"
	"net"
)

// ALPN is the TLS application protocol both transports negotiate.
const ALPN = "domicile/1"

// Stream is one proxied connection inside a Session.
//
// Read returns io.EOF only after the peer called CloseWrite. If the stream
// is aborted or the session dies, Read returns a different error, so a cut
// connection is never mistaken for a complete response.
type Stream interface {
	io.ReadWriter

	// CloseWrite tells the peer no more data will be sent. Reads keep working
	// until the peer closes its side.
	CloseWrite() error

	// Close aborts the stream in both directions and may be called
	// concurrently with Read and Write. Pending and later calls fail; a
	// Write already past its flow-control wait may still complete. Unless
	// CloseWrite was called first, the peer sees an abort rather than a
	// clean end.
	Close() error
}

// Session is one connection between the server and an exit, carrying many
// streams concurrently.
type Session interface {
	OpenStream(ctx context.Context) (Stream, error)
	AcceptStream(ctx context.Context) (Stream, error)

	// Done is closed when the session ends, from either side.
	Done() <-chan struct{}

	// RemoteAddr is the peer's network address.
	RemoteAddr() net.Addr

	Close() error
}

// Listener accepts sessions from exits on the server side.
type Listener interface {
	Accept(ctx context.Context) (Session, error)
	Addr() net.Addr

	// Close stops accepting and releases the address immediately. Sessions
	// it accepted are terminated without notifying the peer, so close them
	// first for a clean shutdown.
	Close() error
}
