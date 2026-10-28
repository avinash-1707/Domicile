package tunnel

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// HalfCloser is a connection that can end its write side alone, such as
// *net.TCPConn.
type HalfCloser interface {
	net.Conn
	CloseWrite() error
}

// DefaultStallTimeout is how long Pipe waits for a TCP peer that has stopped
// reading before giving up on the connection.
const DefaultStallTimeout = 2 * time.Minute

var copyBufs = sync.Pool{New: func() any { return new([32 << 10]byte) }}

// Pipe copies between st and c until both directions finish, then closes
// both. A clean end in one direction is passed on as a half-close. An error
// in either direction aborts both sides (a stream reset, a TCP RST), so
// neither peer mistakes a cut connection for a complete one. It returns the
// first error.
//
// Cancelling ctx aborts both sides; callers tie it to the session so a lost
// tunnel always tears down its connections. A write to c that makes no
// progress for stallTimeout fails, which bounds how long a peer that stopped
// reading can hold the stream.
func Pipe(ctx context.Context, st Stream, c HalfCloser, stallTimeout time.Duration) error {
	var once sync.Once
	abortBoth := func() { once.Do(func() { abort(st, c) }) }
	stop := context.AfterFunc(ctx, abortBoth)

	errc := make(chan error, 2)
	go func() { errc <- copyHalf(stallWriter{c, stallTimeout}, st, c.CloseWrite) }()
	go func() { errc <- copyHalf(st, c, st.CloseWrite) }()

	var first error
	for range 2 {
		if err := <-errc; err != nil && first == nil {
			first = err
			abortBoth()
		}
	}
	if !stop() {
		// ctx fired: the abort ran or is running, even if both directions
		// had just finished, so closing cleanly here would race it.
		if first == nil {
			first = ctx.Err()
		}
		return first
	}
	if first == nil {
		// Both directions ended cleanly; this only releases resources.
		st.Close()
		c.Close()
	}
	return first
}

// stallWriter fails a Write that cannot hand its data to the kernel within
// timeout.
type stallWriter struct {
	c       net.Conn
	timeout time.Duration
}

func (w stallWriter) Write(p []byte) (int, error) {
	if err := w.c.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		return 0, err
	}
	return w.c.Write(p)
}

func copyHalf(dst io.Writer, src io.Reader, closeWrite func() error) error {
	buf := copyBufs.Get().(*[32 << 10]byte)
	defer copyBufs.Put(buf)
	// The struct wrappers hide ReadFrom/WriteTo so the pooled buffer is
	// used; TCP's fast paths cannot splice from a QUIC stream anyway and
	// would allocate a fresh buffer per copy.
	_, err := io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, buf[:])
	if err != nil {
		return err
	}
	return closeWrite()
}

func abort(st Stream, c HalfCloser) {
	st.Close()
	if l, ok := c.(interface{ SetLinger(int) error }); ok {
		// Linger 0 makes Close send RST instead of FIN.
		_ = l.SetLinger(0)
	}
	c.Close()
}
