package main

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/tunnel"
)

type options struct {
	label          string
	openIters      int
	pageIters      int
	pageStreams    int
	pageObjectSize int
	bulkDuration   time.Duration
}

type percentiles struct{ p50, p95 time.Duration }

type result struct {
	open     percentiles
	page     percentiles
	bulkMbps float64
}

// bulkSize asks the responder to send until the stream is torn down.
const bulkSize = 1 << 62

// run connects one server/exit pair over t and measures, in order, stream
// open latency, page-style loads and bulk throughput. Bulk runs last because
// it leaves a stalled stream behind.
func run(ctx context.Context, t transport, opts options) (result, error) {
	l, server, exit, err := connect(ctx, t)
	if err != nil {
		return result{}, err
	}
	// Deferred calls run in reverse: sessions close before the listener,
	// which would otherwise cut them off without notice.
	defer l.Close()
	defer server.Close()
	defer exit.Close()
	go respond(exit)

	// A real tunnel is long-lived, so measure with warm congestion state.
	if _, err := pageLoad(ctx, server, opts); err != nil {
		return result{}, fmt.Errorf("warmup: %w", err)
	}

	var res result
	open := make([]time.Duration, 0, opts.openIters)
	for range opts.openIters {
		start := time.Now()
		if err := fetch(ctx, server, 1); err != nil {
			return result{}, fmt.Errorf("open: %w", err)
		}
		open = append(open, time.Since(start))
	}
	res.open = summarize(open)

	pages := make([]time.Duration, 0, opts.pageIters)
	for range opts.pageIters {
		d, err := pageLoad(ctx, server, opts)
		if err != nil {
			return result{}, fmt.Errorf("page: %w", err)
		}
		pages = append(pages, d)
	}
	res.page = summarize(pages)

	res.bulkMbps, err = bulk(ctx, server, opts.bulkDuration)
	if err != nil {
		return result{}, fmt.Errorf("bulk: %w", err)
	}
	return res, nil
}

// connect returns the listener too: closing it ends the sessions, so it must
// stay open until they are done.
func connect(ctx context.Context, t transport) (l tunnel.Listener, server, exit tunnel.Session, err error) {
	cert, err := certs.SelfSigned("domicile")
	if err != nil {
		return nil, nil, nil, err
	}
	pin, err := certs.FingerprintOf(cert)
	if err != nil {
		return nil, nil, nil, err
	}
	l, err = t.listen("127.0.0.1:0", certs.ServerConfig(cert, tunnel.ALPN))
	if err != nil {
		return nil, nil, nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	type accepted struct {
		s   tunnel.Session
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		s, err := l.Accept(ctx)
		ch <- accepted{s: s, err: err}
	}()

	exit, err = t.dial(ctx, l.Addr().String(), certs.PinnedClientConfig(pin, tunnel.ALPN))
	if err != nil {
		l.Close()
		return nil, nil, nil, err
	}
	a := <-ch
	if a.err != nil {
		exit.Close()
		l.Close()
		return nil, nil, nil, a.err
	}
	return l, a.s, exit, nil
}

// pageLoad fetches pageStreams objects in parallel and returns the time until
// the last byte of the last object arrived.
func pageLoad(ctx context.Context, s tunnel.Session, opts options) (time.Duration, error) {
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, opts.pageStreams)
	for range opts.pageStreams {
		wg.Go(func() {
			if err := fetch(ctx, s, uint64(opts.pageObjectSize)); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// fetch opens a stream, requests size bytes and reads all of them.
func fetch(ctx context.Context, s tunnel.Session, size uint64) error {
	st, err := s.OpenStream(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := writeRequest(st, size); err != nil {
		return err
	}
	n, err := io.Copy(io.Discard, st)
	if err != nil {
		return err
	}
	if uint64(n) != size {
		return fmt.Errorf("received %d of %d bytes", n, size)
	}
	return nil
}

func bulk(ctx context.Context, s tunnel.Session, d time.Duration) (float64, error) {
	st, err := s.OpenStream(ctx)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	if err := writeRequest(st, bulkSize); err != nil {
		return 0, err
	}

	buf := make([]byte, 64<<10)
	var total int64
	start := time.Now()
	// Checking elapsed time after each read avoids needing read deadlines,
	// which the tunnel.Stream interface does not expose.
	for time.Since(start) < d {
		n, err := st.Read(buf)
		total += int64(n)
		if err != nil {
			return 0, err
		}
	}
	return float64(total*8) / time.Since(start).Seconds() / 1e6, nil
}

func writeRequest(st tunnel.Stream, size uint64) error {
	var req [8]byte
	binary.BigEndian.PutUint64(req[:], size)
	if _, err := st.Write(req[:]); err != nil {
		return err
	}
	return st.CloseWrite()
}

// respond plays the exit side: for each stream, read the requested size and
// send that many bytes.
func respond(s tunnel.Session) {
	zeros := make([]byte, 64<<10)
	for {
		st, err := s.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer st.Close()
			var req [8]byte
			if _, err := io.ReadFull(st, req[:]); err != nil {
				return
			}
			remaining := binary.BigEndian.Uint64(req[:])
			for remaining > 0 {
				chunk := zeros[:min(uint64(len(zeros)), remaining)]
				n, err := st.Write(chunk)
				if err != nil {
					return
				}
				remaining -= uint64(n)
			}
			_ = st.CloseWrite()
		}()
	}
}

type spread[T cmp.Ordered] struct{ median, min, max T }

// spreadOf uses the lower middle element as the median for even counts.
func spreadOf[T cmp.Ordered](vs []T) spread[T] {
	if len(vs) == 0 {
		return spread[T]{}
	}
	s := slices.Clone(vs)
	slices.Sort(s)
	return spread[T]{median: s[(len(s)-1)/2], min: s[0], max: s[len(s)-1]}
}

type trialSummary struct {
	openP50 time.Duration
	pageP50 time.Duration
	pageP95 spread[time.Duration]
	bulk    spread[float64]
}

func summarizeTrials(rs []result) trialSummary {
	var openP50, pageP50, pageP95 []time.Duration
	var bulk []float64
	for _, r := range rs {
		openP50 = append(openP50, r.open.p50)
		pageP50 = append(pageP50, r.page.p50)
		pageP95 = append(pageP95, r.page.p95)
		bulk = append(bulk, r.bulkMbps)
	}
	return trialSummary{
		openP50: spreadOf(openP50).median,
		pageP50: spreadOf(pageP50).median,
		pageP95: spreadOf(pageP95),
		bulk:    spreadOf(bulk),
	}
}

func summarize(ds []time.Duration) percentiles {
	if len(ds) == 0 {
		return percentiles{}
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	return percentiles{p50: percentile(s, 0.50), p95: percentile(s, 0.95)}
}

// percentile uses the nearest-rank method on sorted input.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p*float64(len(sorted)))) - 1
	return sorted[max(0, min(rank, len(sorted)-1))]
}
