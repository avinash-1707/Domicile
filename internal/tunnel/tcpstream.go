package tunnel

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// TCPStream adapts a TCP connection to Stream, so traffic that bypasses the
// tunnel (the direct path) goes through the same Pipe with the same failure
// rules as the exit applies to its destinations:
//   - A write the peer refuses because it closed or reset (EPIPE,
//     ECONNRESET) reports ErrPeerStoppedReading. A TCP peer that closes after
//     answering and one that resets mid-upload look the same here; both
//     count as a stop, so a complete response is not cut short. One limit is
//     below us: if the peer's reset arrives while part of its response is
//     still unread in our socket, the kernel discards that part.
//   - A write that makes no progress for stallTimeout fails, so a peer that
//     stops reading cannot hold the connection forever.
func TCPStream(c *net.TCPConn, stallTimeout time.Duration) Stream {
	return &tcpStream{c: c, stall: stallTimeout}
}

type tcpStream struct {
	c           *net.TCPConn
	stall       time.Duration
	closedWrite atomic.Bool
}

func (s *tcpStream) Read(p []byte) (int, error) { return s.c.Read(p) }

func (s *tcpStream) Write(p []byte) (int, error) {
	if err := s.c.SetWriteDeadline(time.Now().Add(s.stall)); err != nil {
		return 0, err
	}
	n, err := s.c.Write(p)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) &&
		(errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)) {
		err = fmt.Errorf("%w: %w", ErrPeerStoppedReading, err)
	}
	return n, err
}

func (s *tcpStream) CloseWrite() error {
	if err := s.c.CloseWrite(); err != nil {
		return err
	}
	s.closedWrite.Store(true)
	return nil
}

func (s *tcpStream) StopReading() { _ = s.c.CloseRead() }

// Close sends RST unless the write side already ended cleanly, matching the
// QUIC stream: an abort must not look like a complete transfer.
func (s *tcpStream) Close() error {
	if !s.closedWrite.Load() {
		_ = s.c.SetLinger(0)
	}
	return s.c.Close()
}
