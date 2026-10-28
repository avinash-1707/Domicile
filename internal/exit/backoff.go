package exit

import (
	"math/rand/v2"
	"time"
)

const (
	backoffMin = 500 * time.Millisecond
	backoffMax = 30 * time.Second
)

// backoff doubles the reconnect delay up to backoffMax. Each delay is drawn
// from [d/2, d) so many exits restarting together (a server reboot) do not
// reconnect in lockstep, while a delay never collapses to zero.
type backoff struct {
	attempt int
	// jitter returns a value in [0, n); replaced in tests.
	jitter func(n int64) int64
}

func newBackoff() *backoff {
	return &backoff{jitter: rand.Int64N}
}

func (b *backoff) next() time.Duration {
	d := backoffMax
	if b.attempt < 16 { // 500ms << 16 is far above the cap; avoids overflow
		d = min(backoffMin<<b.attempt, backoffMax)
	}
	b.attempt++
	half := d / 2
	return half + time.Duration(b.jitter(int64(half)))
}

func (b *backoff) reset() { b.attempt = 0 }
