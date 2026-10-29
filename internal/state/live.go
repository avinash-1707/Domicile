package state

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/avinash-1707/domicile/internal/secret"
)

// Live is the server's in-memory view of the state file. Reload picks up
// changes made by the CLI; lookups never touch the disk.
type Live struct {
	path string
	cur  atomic.Pointer[State]
	gen  atomic.Uint64

	mu  sync.Mutex // serialises Reload
	sum [sha256.Size]byte

	lastMiss atomic.Int64 // unix nanos of the last miss-triggered reload
}

// missReloadEvery bounds re-reads triggered by failed logins, so a stream of
// wrong passwords cannot make the server hammer the disk.
const missReloadEvery = 250 * time.Millisecond

// OpenLive loads path and returns a view of it.
func OpenLive(path string) (*Live, error) {
	l := &Live{path: path}
	if err := l.Reload(); err != nil {
		return nil, err
	}
	return l, nil
}

// Reload re-reads the file and, if its content changed, swaps in the new
// state and bumps Generation. The file is a few KB, so comparing a hash of
// the bytes is cheap and, unlike inode or mtime, cannot miss a change.
func (l *Live) Reload() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := os.ReadFile(l.path)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotInitialized
	}
	if err != nil {
		return fmt.Errorf("read state: %w", err)
	}
	sum := sha256.Sum256(data)
	if l.cur.Load() != nil && bytes.Equal(sum[:], l.sum[:]) {
		return nil
	}
	st, err := parse(l.path, data)
	if err != nil {
		return err
	}
	l.cur.Store(&st)
	l.sum = sum
	l.gen.Add(1)
	return nil
}

// Generation increases every time Reload picks up new content, whoever
// called it. A watcher compares it with the last value it acted on, so a
// change absorbed by another caller's Reload is never missed.
func (l *Live) Generation() uint64 { return l.gen.Load() }

// State returns the current snapshot. Callers must not modify it.
func (l *Live) State() *State { return l.cur.Load() }

// ExitCredential returns the stored credential digest for a paired exit.
func (l *Live) ExitCredential(name string) (string, bool) {
	e, ok := l.cur.Load().Exits[name]
	if !ok || e.CredentialSHA256 == "" {
		return "", false
	}
	return e.CredentialSHA256, true
}

// CheckUser reports whether user/pass is a valid proxy login. Unknown
// users are compared too, so timing does not reveal which exist. On a miss it
// re-reads the state once before refusing: a credential the CLI wrote a
// moment ago (`run`, `connect`, `user add`) must work on its first use, not
// after the next periodic reload.
func (l *Live) CheckUser(user, pass string) bool {
	if l.checkUser(user, pass) {
		return true
	}
	now := time.Now().UnixNano()
	last := l.lastMiss.Load()
	if now-last < int64(missReloadEvery) || !l.lastMiss.CompareAndSwap(last, now) {
		return false
	}
	if err := l.Reload(); err != nil {
		return false
	}
	return l.checkUser(user, pass)
}

func (l *Live) checkUser(user, pass string) bool {
	u, ok := l.cur.Load().Users[user]
	return secret.MatchesDigest(pass, u.PasswordSHA256) && ok && u.PasswordSHA256 != ""
}

// Join consumes a join token (see the package-level Join) and refreshes the
// view so the new credential is visible at once.
func (l *Live) Join(exit, token string) (string, error) {
	cred, err := Join(l.path, exit, token, time.Now())
	if err != nil {
		return "", err
	}
	if err := l.Reload(); err != nil {
		return "", err
	}
	return cred, nil
}
