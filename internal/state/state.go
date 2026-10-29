// Package state holds the server's secrets: exit credentials, pending
// one-time join tokens and proxy users. Only SHA-256 digests are stored, and
// every secret is generated here with 256 bits of randomness, so a fast hash
// is enough; nothing user-chosen is ever stored.
//
// The CLI (add, remove, user) and the running server both write the file,
// so every change goes through Update, which holds an exclusive lock while it
// reads, modifies and atomically replaces the file.
package state

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/avinash-1707/domicile/internal/secret"
)

// ErrNotInitialized means no state file exists yet.
var ErrNotInitialized = errors.New("no server state; run `domicile init` first")

// ErrInvalidToken covers every failed join: unknown exit, wrong, expired or
// already used token. Callers log it without saying which.
var ErrInvalidToken = errors.New("join token invalid, expired or already used")

// State is the server's state file.
type State struct {
	// PublicAddr is the host:port exits dial, put into join codes.
	PublicAddr string          `json:"public_addr,omitempty"`
	Exits      map[string]Exit `json:"exits"`
	Users      map[string]User `json:"proxy_users"`
}

// Exit is one paired (or pairing) exit.
type Exit struct {
	// CredentialSHA256 is empty until the exit has joined.
	CredentialSHA256 string     `json:"credential_sha256,omitempty"`
	Join             *JoinToken `json:"join,omitempty"`
	Created          time.Time  `json:"created"`
}

// JoinToken is a pending one-time token.
type JoinToken struct {
	SHA256  string    `json:"sha256"`
	Expires time.Time `json:"expires"`
}

// User is a proxy client.
type User struct {
	PasswordSHA256 string    `json:"password_sha256"`
	Created        time.Time `json:"created"`
}

// NewSecret returns 32 random bytes, base64url-encoded (43 characters).
func NewSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Load reads the state file.
func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, ErrNotInitialized
	}
	if err != nil {
		return State{}, fmt.Errorf("read state: %w", err)
	}
	return parse(path, data)
}

func parse(path string, data []byte) (State, error) {
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if st.Exits == nil {
		st.Exits = make(map[string]Exit)
	}
	if st.Users == nil {
		st.Users = make(map[string]User)
	}
	return st, nil
}

// Create writes a fresh state file, failing if one exists.
func Create(path string, st State) error {
	return withLock(path, func() error {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists", path)
		}
		return save(path, st)
	})
}

// Update applies fn to the current state under an exclusive lock and saves
// the result. If fn returns an error nothing is written.
func Update(path string, fn func(*State) error) error {
	return withLock(path, func() error {
		st, err := Load(path)
		if err != nil {
			return err
		}
		if err := fn(&st); err != nil {
			return err
		}
		return save(path, st)
	})
}

// Join consumes exit's one-time token and stores a new long-lived
// credential, which it returns. It runs under the state lock, so a token can
// be used only once even if two joins race.
func Join(path, exit, token string, now time.Time) (string, error) {
	cred, err := NewSecret()
	if err != nil {
		return "", err
	}
	err = Update(path, func(st *State) error {
		e, ok := st.Exits[exit]
		// Compare even when the exit or token is missing, so timing does
		// not reveal which exits exist.
		want := ""
		if ok && e.Join != nil {
			want = e.Join.SHA256
		}
		match := secret.MatchesDigest(token, want)
		if !ok || e.Join == nil || !match || !now.Before(e.Join.Expires) {
			return ErrInvalidToken
		}
		e.CredentialSHA256 = secret.Digest(cred)
		e.Join = nil
		st.Exits[exit] = e
		return nil
	})
	if err != nil {
		return "", err
	}
	return cred, nil
}

// lockTimeout bounds the wait for the state lock. It is well inside the
// server's hello timeout, so a stuck holder (a hung CLI) fails joins quickly
// instead of pinning their handshake slots.
const lockTimeout = 2 * time.Second

// withLock holds an exclusive flock on path+".lock" while fn runs. The lock
// file is separate because the state file itself is replaced by rename.
func withLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	unlock, err := lockFile(path+".lock", lockTimeout)
	if err != nil {
		return fmt.Errorf("lock state: %w", err)
	}
	defer unlock()
	return fn()
}

// LockFile takes an exclusive flock on path, retrying until timeout; zero
// means try once. The returned func releases it.
func LockFile(path string, timeout time.Duration) (func(), error) {
	return lockFile(path, timeout)
}

// LockDir takes an exclusive flock on directory dir itself, so a lock
// creates no file next to data that is meant to be committed.
func LockDir(dir string, timeout time.Duration) (func(), error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	return flockWait(f, dir, timeout)
}

func lockFile(path string, timeout time.Duration) (func(), error) {
	lf, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return flockWait(lf, path, timeout)
}

func flockWait(lf *os.File, path string, timeout time.Duration) (func(), error) {
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
				lf.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || !time.Now().Before(deadline) {
			lf.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, fmt.Errorf("%s is held by another process", path)
			}
			return nil, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func save(path string, st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// WriteFileAtomic replaces path with data, so a crash leaves either the old
// or the new file, never half of one.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// Sync the directory so the rename itself survives a crash; otherwise a
	// committed join could vanish while the exit already holds its credential.
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer dir.Close()
	return dir.Sync()
}

// Agent is what a paired exit remembers about its server.
type Agent struct {
	Name       string `json:"name"`
	Server     string `json:"server"`
	PinSHA256  string `json:"server_fingerprint"`
	Credential string `json:"credential"`
}

// LoadAgent reads the exit's saved pairing.
func LoadAgent(path string) (Agent, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Agent{}, errors.New("this device is not paired; run `domicile agent join <code>` with the code from `domicile add`")
	}
	if err != nil {
		return Agent{}, fmt.Errorf("read agent state: %w", err)
	}
	var a Agent
	if err := json.Unmarshal(data, &a); err != nil {
		return Agent{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return a, nil
}

// SaveAgent writes the pairing with owner-only permissions; it holds the
// exit's credential.
func SaveAgent(path string, a Agent) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(data, '\n'), 0o600)
}
