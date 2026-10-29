package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/state"
)

func TestJoinCodeRoundTrip(t *testing.T) {
	want := joinCode{Server: "vps.example.com:443", Pin: strings.Repeat("ab", 32), Name: "home", Token: "tok"}
	code, err := encodeJoinCode(want)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(code, " \n'\"") {
		t.Fatalf("code %q is not safe to paste into a shell", code)
	}
	got, err := decodeJoinCode("  " + code + "\n")
	if err != nil || got != want {
		t.Fatalf("got %+v, %v", got, err)
	}
	for _, bad := range []string{"", "dj1.", "dj1.!!!", "dj2." + code[4:], code[:len(code)-6]} {
		if _, err := decodeJoinCode(bad); err == nil {
			t.Errorf("decodeJoinCode(%q) accepted a bad code", bad)
		}
	}
}

func TestInitAddRemoveUser(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	run := func(f func([]string, *bytes.Buffer) error, args ...string) (string, error) {
		var out bytes.Buffer
		err := f(append(args, "-state-dir", dir), &out)
		return out.String(), err
	}
	initCmd := func(a []string, o *bytes.Buffer) error { return runInit(a, o) }
	addCmd := func(a []string, o *bytes.Buffer) error { return runAdd(a, o) }
	removeCmd := func(a []string, o *bytes.Buffer) error { return runRemove(a, o) }
	userCmd := func(a []string, o *bytes.Buffer) error { return runUser(a, o) }

	out, err := run(initCmd, "-public-addr", "vps.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	pw := regexp.MustCompile(`socks5h://agent:([A-Za-z0-9_-]+)@`).FindStringSubmatch(out)
	if pw == nil {
		t.Fatalf("init did not print a proxy URL: %q", out)
	}
	if _, err := run(initCmd); err == nil {
		t.Fatal("second init overwrote existing state")
	}

	st, _ := state.Load(statePath(dir))
	raw, _ := os.ReadFile(statePath(dir))
	if bytes.Contains(raw, []byte(pw[1])) {
		t.Fatal("state file stores the proxy password in plain text")
	}
	if len(st.Users) != 1 {
		t.Fatalf("users = %v", st.Users)
	}

	out, err = run(addCmd, "home")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`domicile agent join (dj1\.\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("add did not print a join command: %q", out)
	}
	c, err := decodeJoinCode(m[1])
	if err != nil || c.Server != "vps.example.com:443" || c.Name != "home" {
		t.Fatalf("join code = %+v, %v", c, err)
	}
	raw, _ = os.ReadFile(statePath(dir))
	if bytes.Contains(raw, []byte(c.Token)) {
		t.Fatal("state file stores the join token in plain text")
	}

	if _, err := run(addCmd, "office", "-addr", "not-a-hostport"); err == nil {
		t.Fatal("bad -addr accepted")
	}
	if _, err := run(addCmd, "bad name"); err == nil {
		t.Fatal("name with a space accepted")
	}

	// A rule still pointing at a removed exit is called out.
	rules.Config{Rules: []rules.Rule{{Match: "reddit.com", Via: "home"}}}.Save(filepath.Join(dir, configFile))
	out, err = run(removeCmd, "home")
	if err != nil || !strings.Contains(out, "reddit.com") {
		t.Fatalf("remove = %q, %v; want a warning about the rule", out, err)
	}
	if _, err := run(removeCmd, "home"); err == nil {
		t.Fatal("removing a missing exit succeeded")
	}

	if _, err := run(userCmd, "add", "ci"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(userCmd, "add", "ci"); err == nil {
		t.Fatal("duplicate user accepted")
	}
	if _, err := run(userCmd, "add", "a:b"); err == nil {
		t.Fatal("user with ':' accepted")
	}
	out, _ = run(userCmd, "list")
	if out != "agent\nci\n" {
		t.Fatalf("user list = %q", out)
	}
	if _, err := run(userCmd, "remove", "ci"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(userCmd, "remove", "agent"); err == nil {
		t.Fatal("removed the last proxy user")
	}
}

func TestAddWithoutAddress(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := runInit([]string{"-state-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	err := runAdd([]string{"home", "-state-dir", dir}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "-addr") {
		t.Fatalf("add without any address = %v, want a hint about -addr", err)
	}
}

func TestCheckName(t *testing.T) {
	for _, ok := range []string{"home", "office-2", "pi_4", strings.Repeat("a", 64)} {
		if err := checkName(ok); err != nil {
			t.Errorf("checkName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "a@b", "a/b", "a%b", "a\rb", "a:b", strings.Repeat("a", 65)} {
		if err := checkName(bad); err == nil {
			t.Errorf("checkName(%q) accepted", bad)
		}
	}
}

func TestOneAgentPerDevice(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockAgent(dir); err == nil {
		t.Fatal("a second agent got the lock")
	}
	unlock()
	again, err := lockAgent(dir)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	again()
}
