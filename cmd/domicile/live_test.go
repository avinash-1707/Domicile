package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avinash-1707/domicile/internal/route"
	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/wire"
)

// nopExits accepts every dial without a stream; only the chosen path matters.
type nopExits struct{}

func (nopExits) Dial(context.Context, string, wire.Open) (tunnel.Stream, error) { return nil, nil }

// pathFor returns the path the router picks for host. A direct pick really
// dials, so the context is short: only the path name matters here.
func pathFor(t *testing.T, r *route.Router, host string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, path, _ := r.Dial(ctx, wire.Open{Host: host, Port: 1})
	return path
}

func TestLiveRulesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domicile.json")
	router := route.New(rules.NewTable(rules.Config{}), nopExits{}, nil, route.Options{})
	lr := &liveRules{path: path, router: router, known: func(string) bool { return true }, log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// A rule added while the server runs takes effect on the next reload.
	if err := (rules.Config{Rules: []rules.Rule{{Match: "reddit.com", Via: "home"}}}).Save(path); err != nil {
		t.Fatal(err)
	}
	lr.reload()
	if got := pathFor(t, router, "www.reddit.com"); got != "home" {
		t.Fatalf("after adding a rule: path %q, want home", got)
	}

	// A broken file keeps the previous rules and reports why.
	os.WriteFile(path, []byte(`{"rules": [`), 0o644)
	lr.reload()
	if got := pathFor(t, router, "www.reddit.com"); got != "home" {
		t.Fatalf("broken file changed routing: path %q", got)
	}
	if _, rerr := lr.snapshot(); rerr == "" {
		t.Fatal("broken file not reported")
	}

	// Reverting the broken edit clears the warning.
	if err := (rules.Config{Rules: []rules.Rule{{Match: "reddit.com", Via: "home"}}}).Save(path); err != nil {
		t.Fatal(err)
	}
	lr.reload()
	if _, rerr := lr.snapshot(); rerr != "" {
		t.Fatalf("warning kept after the file was reverted: %s", rerr)
	}

	// A file briefly missing (git pull, an editor's rename-on-save) keeps
	// the rules instead of sending ruled traffic direct.
	os.Remove(path)
	lr.reload()
	if got := pathFor(t, router, "www.reddit.com"); got != "home" {
		t.Fatalf("missing file changed routing to %q", got)
	}
	if _, rerr := lr.snapshot(); rerr == "" {
		t.Fatal("missing file not reported")
	}

	// A rule for an exit that has not been added is refused, as at startup.
	lr.known = func(exit string) bool { return exit == "home" }
	(rules.Config{Rules: []rules.Rule{{Match: "reddit.com", Via: "hmoe", OnExitDown: rules.FallbackDirect}}}).Save(path)
	lr.reload()
	if got := pathFor(t, router, "www.reddit.com"); got != "home" {
		t.Fatalf("rule for an unknown exit was applied: path %q", got)
	}
	if _, rerr := lr.snapshot(); !strings.Contains(rerr, "hmoe") {
		t.Fatalf("unknown exit not reported: %q", rerr)
	}

	// Clearing rules on purpose still works.
	(rules.Config{}).Save(path)
	lr.reload()
	if got := pathFor(t, router, "www.reddit.com"); got != route.Direct {
		t.Fatalf("after clearing: path %q, want direct", got)
	}
}

func TestRuleLockLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "domicile.json")
	if err := runRule([]string{"add", "a.com", "-via", "home", "-config", conf}, io.Discard); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("rule add left %v next to the rules file", names)
	}
}

func TestConcurrentRuleAddsAllSurvive(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "domicile.json")
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			if err := runRule([]string{"add", fmt.Sprintf("site%d.com", i), "-via", "home", "-config", conf}, io.Discard); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	c, err := rules.Load(conf)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 10 {
		t.Fatalf("%d of 10 concurrent rule adds survived", len(c.Rules))
	}
}
