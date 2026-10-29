package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func table(t *testing.T, rs ...Rule) *Table {
	t.Helper()
	c := Config{Rules: rs}
	if err := c.normalize(); err != nil {
		t.Fatal(err)
	}
	return NewTable(c)
}

func TestMatch(t *testing.T) {
	tb := table(t,
		Rule{Match: "accounts.google.com", Exact: true, Via: "office"},
		Rule{Match: "Reddit.COM.", Via: "home"},
		Rule{Match: "google.com", Via: "home"},
		Rule{Match: "old.reddit.com", Via: "office"}, // shadowed by reddit.com above
		Rule{Match: "93.184.216.34", Via: "home"},
		Rule{Match: "2001:db8::1", Via: "home"},
	)
	tests := []struct {
		host    string
		wantVia string // empty means no match
	}{
		{"reddit.com", "home"},
		{"www.reddit.com", "home"},
		{"WWW.Reddit.Com.", "home"},
		{"a.b.c.reddit.com", "home"},
		{"old.reddit.com", "home"}, // first match in config order wins
		{"notreddit.com", ""},      // a suffix match must be on a label boundary
		{"reddit.com.evil.net", ""},
		{"accounts.google.com", "office"}, // exact rule listed first
		{"x.accounts.google.com", "home"}, // exact does not cover subdomains
		{"mail.google.com", "home"},
		{"example.com", ""},
		{"com", ""},
		{"93.184.216.34", "home"},
		{"93.184.216.35", ""},
		{"2001:db8::1", "home"},
		{"", ""},
	}
	for _, tt := range tests {
		r, ok := tb.Match(tt.host)
		got := ""
		if ok {
			got = r.Via
		}
		if got != tt.wantVia {
			t.Errorf("Match(%q) = %q, want %q", tt.host, got, tt.wantVia)
		}
	}
}

func TestMatchOrderPrefersEarlierSuffix(t *testing.T) {
	tb := table(t,
		Rule{Match: "old.reddit.com", Via: "office"},
		Rule{Match: "reddit.com", Via: "home"},
	)
	if r, _ := tb.Match("x.old.reddit.com"); r.Via != "office" {
		t.Fatalf("got %q; the earlier, more specific rule should win", r.Via)
	}
	if r, _ := tb.Match("www.reddit.com"); r.Via != "home" {
		t.Fatalf("got %q", r.Via)
	}
}

func TestNormalizeRejects(t *testing.T) {
	for _, bad := range []string{"", "  ", ".", "https://reddit.com", "reddit.com/r/golang", "*.reddit.com", "reddit.com:443", "user@reddit.com", strings.Repeat("a", 254), "reddit..com", "bücher.de", "reddit com", "a.com,b.com"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("NormalizeDomain(%q) accepted bad input", bad)
		}
	}
}

func TestNormalizeAccepts(t *testing.T) {
	for in, want := range map[string]string{
		".Reddit.com.":       "reddit.com",
		"xn--bcher-kva.de":   "xn--bcher-kva.de",
		"_dmarc.example.com": "_dmarc.example.com",
		"2001:DB8:0:0::1":    "2001:db8::1",
		"::ffff:1.2.3.4":     "1.2.3.4",
		"1.2.3.4.":           "1.2.3.4",
	} {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestMatchCanonicalIPs(t *testing.T) {
	tb := table(t, Rule{Match: "2001:db8::1", Via: "home"}, Rule{Match: "1.2.3.4", Via: "home"})
	for _, host := range []string{"2001:db8:0:0::1", "2001:DB8::1", "::ffff:1.2.3.4", "1.2.3.4."} {
		if _, ok := tb.Match(host); !ok {
			t.Errorf("Match(%q) missed an equivalent IP rule", host)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		c    Config
	}{
		{"no via", Config{Rules: []Rule{{Match: "a.com"}}}},
		{"bad on_exit_down", Config{Rules: []Rule{{Match: "a.com", Via: "home", OnExitDown: "retry"}}}},
		{"duplicate after normalising", Config{Rules: []Rule{{Match: "a.com", Via: "home"}, {Match: "A.com.", Via: "office"}}}},
	}
	for _, tt := range tests {
		if err := tt.c.normalize(); err == nil {
			t.Errorf("%s: accepted", tt.name)
		}
	}
	ok := Config{Rules: []Rule{{Match: "a.com", Via: "home"}, {Match: "a.com", Exact: true, Via: "office"}}}
	if err := ok.normalize(); err != nil {
		t.Fatalf("exact and suffix rules for one domain rejected: %v", err)
	}
	if ok.Rules[0].OnExitDown != FailClosed {
		t.Fatalf("default on_exit_down = %q, want fail_closed", ok.Rules[0].OnExitDown)
	}
}

func TestLoadSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conf", "domicile.json")

	c, err := Load(path)
	if err != nil || len(c.Rules) != 0 {
		t.Fatalf("missing file = %+v, %v; want empty config", c, err)
	}

	want := Config{Rules: []Rule{
		{Match: "reddit.com", Via: "home", Note: "blocks datacenter IPs"},
		{Match: "example.org", Via: "home", OnExitDown: FallbackDirect},
	}}
	if err := want.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 2 || got.Rules[0].Note != "blocks datacenter IPs" || got.Rules[1].OnExitDown != FallbackDirect || got.Rules[0].OnExitDown != FailClosed {
		t.Fatalf("round trip = %+v", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("save left %d files behind, want only the config", len(entries))
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %o, want 644", info.Mode().Perm())
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domicile.json")
	os.WriteFile(path, []byte(`{"rules":[{"match":"a.com","via":"home","on_exit_dwn":"fallback_direct"}]}`), 0o644)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "on_exit_dwn") {
		t.Fatalf("typo in a field name not reported: %v", err)
	}
}
