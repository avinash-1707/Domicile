package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
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

// lingerTimeout bounds how long Pipe drains c before closing it after the
// stream refused c's data. Closing a socket with unread input sends RST,
// which would discard data still on its way to that peer.
const lingerTimeout = 5 * time.Second

var copyBufs = sync.Pool{New: func() any { return new([32 << 10]byte) }}

// PipeError reports which direction of a Pipe failed first.
type PipeError struct {
	// ToConn is true when copying from the stream to the connection failed,
	// false when copying from the connection to the stream failed.
	ToConn bool
	// Write is true when writing to the direction's receiver failed, false
	// when reading from its sender did. With ToConn it says which peer
	// failed: (ToConn && Write) or (!ToConn && !Write) means c.
	Write bool
	// OtherDone is true when the opposite direction finished cleanly, so
	// everything sent that way was delivered. A web server that stops
	// reading after its response, while the client's last bytes are in
	// flight, ends this way.
	OtherDone bool
	Err       error
}

func (e *PipeError) Error() string {
	dir := "connection to stream"
	if e.ToConn {
		dir = "stream to connection"
	}
	return dir + ": " + e.Err.Error()
}

func (e *PipeError) Unwrap() error { return e.Err }

// ConnFailed reports whether the failure was on c's side rather than the
// stream's.
func (e *PipeError) ConnFailed() bool { return e.ToConn == e.Write }

// Pipe copies between st and c until both directions finish, then closes
// both. A clean end in one direction is passed on as a half-close.
//
// Failures are handled by what they mean for the data:
//   - A write into the stream refused with ErrPeerStoppedReading means the
//     far end's TCP peer went away after a normal exchange (the far Pipe
//     signals that with StopReading). That direction stops, but the other
//     carries on: the far end may still be sending a complete response (a
//     web server that closes after answering, while the client's last bytes
//     are in flight). A TCP peer that closes and one that resets mid-upload
//     look the same at this level; both count as a stop.
//   - Any other failure (a read error, a lost tunnel, or c refusing or
//     stalling on writes) means data was cut or a peer is gone. Both sides are aborted (a
//     stream reset, a TCP RST) so neither peer mistakes the cut for a
//     complete transfer.
//
// It returns nil, a *PipeError for the first failed direction, or ctx's
// error. Cancelling ctx aborts both sides; callers tie it to the session so
// a lost tunnel always tears down its connections. A write to c that makes no
// progress for stallTimeout fails, which bounds how long a peer that stopped
// reading can hold the stream.
func Pipe(ctx context.Context, st Stream, c HalfCloser, stallTimeout time.Duration) error {
	var once sync.Once
	abortBoth := func() { once.Do(func() { abort(st, c) }) }
	stop := context.AfterFunc(ctx, abortBoth)

	type half struct {
		toConn bool
		res    copyResult
	}
	results := make(chan half, 2)
	go func() { results <- half{toConn: true, res: copyHalf(stallWriter{c, stallTimeout}, st, c.CloseWrite)} }()
	go func() { results <- half{toConn: false, res: copyHalf(st, c, st.CloseWrite)} }()

	var first *PipeError
	var clean [2]bool // indexed by toConn
	var drained chan struct{}
	for range 2 {
		h := <-results
		idx := 0
		if h.toConn {
			idx = 1
		}
		if h.res.err == nil {
			clean[idx] = true
			continue
		}
		if first == nil {
			first = &PipeError{ToConn: h.toConn, Write: h.res.write, Err: h.res.err}
		}
		if h.res.write && !h.toConn && errors.Is(h.res.err, ErrPeerStoppedReading) {
			// The stream's far end refused this direction; nothing to undo.
			// Keep reading c and discard it, so the final close is a FIN
			// rather than a RST, and let the other direction finish.
			drained = make(chan struct{})
			go func() {
				defer close(drained)
				_, _ = io.Copy(io.Discard, struct{ io.Reader }{c})
			}()
			continue
		}
		if h.res.write && h.toConn && !errors.Is(h.res.err, os.ErrDeadlineExceeded) {
			// c went away (closed or reset), not stalled. Tell the stream's
			// far end it was a stop, so what it already sent the other way
			// is not discarded; the abort below then keeps that signal.
			st.StopReading()
		}
		abortBoth()
	}
	if first != nil {
		other := 1
		if first.ToConn {
			other = 0
		}
		first.OtherDone = clean[other]
	}

	if !stop() {
		// ctx fired: the abort ran or is running, even if both directions
		// had just finished, so closing cleanly here would race it.
		if first != nil {
			return first
		}
		return ctx.Err()
	}
	if drained != nil {
		// Give c a moment to finish its side so closing loses nothing. If it
		// does not, its data is being thrown away, so it gets a RST rather
		// than a FIN that would look like a clean end.
		select {
		case <-drained:
		case <-time.After(lingerTimeout):
			abortBoth()
			return first
		}
	}
	// Releases resources. After a clean end in both directions these are
	// no-ops for the peers; after a refused stream write they finish the
	// teardown.
	st.Close()
	c.Close()
	if first != nil {
		return first
	}
	return nil
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

// copyResult is a copy's outcome; write tells a failure to deliver (the
// receiver stopped reading) from a failure to receive (the sender aborted).
type copyResult struct {
	err   error
	write bool
}

// copyHalf copies src to dst with a pooled buffer, then half-closes dst.
func copyHalf(dst io.Writer, src io.Reader, closeWrite func() error) copyResult {
	buf := copyBufs.Get().(*[32 << 10]byte)
	defer copyBufs.Put(buf)
	for {
		n, rerr := src.Read(buf[:])
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return copyResult{err: werr, write: true}
			}
		}
		if rerr == io.EOF {
			if err := closeWrite(); err != nil {
				return copyResult{err: err, write: true}
			}
			return copyResult{}
		}
		if rerr != nil {
			return copyResult{err: rerr, write: false}
		}
	}
}

func abort(st Stream, c HalfCloser) {
	st.Close()
	if l, ok := c.(interface{ SetLinger(int) error }); ok {
		// Linger 0 makes Close send RST instead of FIN.
		_ = l.SetLinger(0)
	}
	c.Close()
}
