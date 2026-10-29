package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avinash-1707/domicile/internal/rules"
)

func TestRuleCommands(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "domicile.json")
	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := runRule(append(args, "-config", conf), &out)
		return out.String(), err
	}

	if _, err := run("add", "Reddit.com", "-via", "home", "-note", "blocks VPS"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("add", "-via", "office", "-fallback-direct", "example.org"); err != nil {
		t.Fatalf("flags before the domain: %v", err)
	}
	if _, err := run("add", "reddit.com", "-via", "office"); err != nil {
		t.Fatal(err)
	}
	c, err := rules.Load(conf)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 2 || c.Rules[0].Match != "reddit.com" || c.Rules[0].Via != "office" || c.Rules[0].Note != "" {
		t.Fatalf("re-adding should update in place: %+v", c.Rules)
	}
	if c.Rules[1].OnExitDown != rules.FallbackDirect {
		t.Fatalf("-fallback-direct not stored: %+v", c.Rules[1])
	}

	out, err := run("add", "old.reddit.com", "-via", "home")
	if err != nil || !strings.Contains(out, "has no effect") {
		t.Fatalf("shadowed rule not warned about: %q, %v", out, err)
	}
	if !strings.Contains(out, "wrote "+conf) {
		t.Fatalf("output does not name the file written: %q", out)
	}
	if _, err := run("remove", "old.reddit.com"); err != nil {
		t.Fatal(err)
	}

	out, err = run("list")
	if err != nil || !strings.Contains(out, "reddit.com (and subdomains)") || !strings.Contains(out, "(anything else)") {
		t.Fatalf("list = %q, %v", out, err)
	}
	if _, err := run("remove", "reddit.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("remove", "reddit.com"); err == nil {
		t.Fatal("removing a missing rule succeeded")
	}

	for _, bad := range [][]string{
		{"add", "reddit.com"},                         // no -via
		{"add", "https://reddit.com", "-via", "home"}, // a URL
		{"add", "a.com", "b.com", "-via", "home"},     // two domains
		{"frobnicate"},
	} {
		if _, err := run(bad...); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
