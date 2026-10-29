package state

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/avinash-1707/domicile/internal/secret"
)

func newState(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "state.json")
	if err := Create(path, State{Exits: map[string]Exit{}, Users: map[string]User{}}); err != nil {
		t.Fatal(err)
	}
	return path
}

func addToken(t *testing.T, path, exit string, expires time.Time) string {
	t.Helper()
	tok, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	err = Update(path, func(st *State) error {
		st.Exits[exit] = Exit{Join: &JoinToken{SHA256: secret.Digest(tok), Expires: expires}, Created: time.Now()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestJoinTokenWorksOnce(t *testing.T) {
	path := newState(t)
	tok := addToken(t, path, "home", time.Now().Add(time.Hour))

	cred, err := Join(path, "home", tok, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st, _ := Load(path)
	if st.Exits["home"].CredentialSHA256 != secret.Digest(cred) || st.Exits["home"].Join != nil {
		t.Fatalf("after join: %+v", st.Exits["home"])
	}
	if _, err := Join(path, "home", tok, time.Now()); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("second use = %v, want ErrInvalidToken", err)
	}
}

func TestJoinRejects(t *testing.T) {
	path := newState(t)
	tok := addToken(t, path, "home", time.Now().Add(time.Hour))
	expired := addToken(t, path, "old", time.Now().Add(-time.Second))
	for name, try := range map[string]func() error{
		"wrong token":     func() error { _, err := Join(path, "home", tok+"x", time.Now()); return err },
		"wrong exit":      func() error { _, err := Join(path, "office", tok, time.Now()); return err },
		"expired":         func() error { _, err := Join(path, "old", expired, time.Now()); return err },
		"token for other": func() error { _, err := Join(path, "old", tok, time.Now()); return err },
	} {
		if err := try(); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v, want ErrInvalidToken", name, err)
		}
	}
	// The failed attempts must not have consumed the valid token.
	if _, err := Join(path, "home", tok, time.Now()); err != nil {
		t.Fatalf("valid token stopped working after failed attempts: %v", err)
	}
}

func TestConcurrentJoinUsesTokenOnce(t *testing.T) {
	path := newState(t)
	tok := addToken(t, path, "home", time.Now().Add(time.Hour))
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 8 {
		wg.Go(func() {
			if _, err := Join(path, "home", tok, time.Now()); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("token used %d times, want exactly once", wins)
	}
}

func TestUpdateIsSerialised(t *testing.T) {
	path := newState(t)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			err := Update(path, func(st *State) error {
				st.Users[string(rune('a'+i))] = User{PasswordSHA256: "x"}
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	st, _ := Load(path)
	if len(st.Users) != 20 {
		t.Fatalf("%d of 20 concurrent updates survived", len(st.Users))
	}
}

func TestFilesArePrivate(t *testing.T) {
	path := newState(t)
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %o, want 600", info.Mode().Perm())
	}
	ap := filepath.Join(t.TempDir(), "agent", "agent.json")
	if err := SaveAgent(ap, Agent{Name: "home", Credential: "c"}); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(ap)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("agent state mode %o, want 600", info.Mode().Perm())
	}
	if err := Create(path, State{}); err == nil {
		t.Fatal("Create overwrote an existing state file")
	}
}

func TestLiveReload(t *testing.T) {
	path := newState(t)
	l, err := OpenLive(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.ExitCredential("home"); ok {
		t.Fatal("unknown exit has a credential")
	}
	tok := addToken(t, path, "home", time.Now().Add(time.Hour))
	if _, ok := l.ExitCredential("home"); ok {
		t.Fatal("an exit that has not joined must have no credential")
	}
	cred, err := l.Join("home", tok)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := l.ExitCredential("home"); !ok || !secret.MatchesDigest(cred, d) {
		t.Fatal("joined credential not visible right after Join")
	}

	gen := l.Generation()
	Update(path, func(st *State) error { delete(st.Exits, "home"); return nil })
	if err := l.Reload(); err != nil || l.Generation() == gen {
		t.Fatalf("Reload = %v, generation %d -> %d; want a change", err, gen, l.Generation())
	}
	if _, ok := l.ExitCredential("home"); ok {
		t.Fatal("removed exit still has a credential")
	}
	gen = l.Generation()
	l.Reload()
	if l.Generation() != gen {
		t.Fatal("Reload counted a change for an untouched file")
	}
}

func TestJoinDoesNotHideOtherChanges(t *testing.T) {
	// A join's own reload must still let a watcher see a removal made in
	// the same instant: the watcher compares generations, not "did my
	// Reload change anything".
	path := newState(t)
	Update(path, func(st *State) error {
		st.Exits["office"] = Exit{CredentialSHA256: secret.Digest("c")}
		return nil
	})
	l, _ := OpenLive(path)
	seen := l.Generation()
	tok := addToken(t, path, "home", time.Now().Add(time.Hour))
	Update(path, func(st *State) error { delete(st.Exits, "office"); return nil })
	if _, err := l.Join("home", tok); err != nil {
		t.Fatal(err)
	}
	l.Reload() // the watcher's tick: nothing new on disk
	if l.Generation() == seen {
		t.Fatal("watcher cannot tell that office was removed")
	}
	if _, ok := l.ExitCredential("office"); ok {
		t.Fatal("removed exit still valid")
	}
}

func TestCheckUser(t *testing.T) {
	path := newState(t)
	Update(path, func(st *State) error {
		st.Users["agent"] = User{PasswordSHA256: secret.Digest("pw")}
		st.Users["broken"] = User{}
		return nil
	})
	l, _ := OpenLive(path)
	tests := []struct {
		user, pass string
		want       bool
	}{
		{"agent", "pw", true},
		{"agent", "wrong", false},
		{"agent", "", false},
		{"nobody", "pw", false},
		{"nobody", "", false},
		{"broken", "", false}, // an empty stored digest must never match
	}
	for _, tt := range tests {
		if got := l.CheckUser(tt.user, tt.pass); got != tt.want {
			t.Errorf("CheckUser(%q, %q) = %v, want %v", tt.user, tt.pass, got, tt.want)
		}
	}
}

func TestLockTimesOut(t *testing.T) {
	path := newState(t)
	unlock, err := LockFile(path+".lock", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	start := time.Now()
	err = Update(path, func(*State) error { return nil })
	if err == nil {
		t.Fatal("Update ran while another process held the lock")
	}
	if d := time.Since(start); d > lockTimeout+time.Second {
		t.Fatalf("waited %v for a held lock, want about %v", d, lockTimeout)
	}
}

func TestCheckUserSeesNewCredentialAtOnce(t *testing.T) {
	path := newState(t)
	l, _ := OpenLive(path)
	// The CLI adds a user while the server runs, and the client uses it at
	// once, before any periodic reload.
	Update(path, func(st *State) error {
		st.Users["run"] = User{PasswordSHA256: secret.Digest("fresh")}
		return nil
	})
	if !l.CheckUser("run", "fresh") {
		t.Fatal("a just-written credential was refused on first use")
	}
	// Wrong passwords right after do not each trigger a re-read.
	gen := l.Generation()
	for range 50 {
		l.CheckUser("run", "wrong")
	}
	if l.Generation() != gen {
		t.Fatal("failed logins forced reloads of an unchanged file")
	}
}
