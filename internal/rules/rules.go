// Package rules decides which destinations go through a home exit. Rules are
// ordered, the first match wins, and anything unmatched goes direct.
package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// OnExitDown says what a rule does when its exit is not connected.
type OnExitDown string

const (
	// FailClosed refuses the connection. The default: silently using the
	// VPS's datacenter IP is the failure users care about.
	FailClosed OnExitDown = "fail_closed"
	// FallbackDirect connects from the VPS instead, and logs it every time.
	FallbackDirect OnExitDown = "fallback_direct"
)

// Rule routes a domain (and, unless Exact, its subdomains) through an exit.
type Rule struct {
	Match      string     `json:"match"`
	Exact      bool       `json:"exact,omitempty"`
	Via        string     `json:"via"`
	OnExitDown OnExitDown `json:"on_exit_down,omitempty"`
	// Note says why the rule exists; the file has no comments.
	Note string `json:"note,omitempty"`
}

// Config is the rules file.
type Config struct {
	Rules []Rule `json:"rules"`
}

// Load reads path. A missing file is an empty config: every destination goes
// direct.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read rules: %w", err)
	}
	return Parse(data, path)
}

// Parse decodes and validates a rules file's bytes; name is used in errors.
// Callers that also hash the file parse the same bytes they hashed.
func Parse(data []byte, name string) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	// A typo in a field name must not silently drop a rule's intent.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", name, err)
	}
	if err := c.normalize(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", name, err)
	}
	if c.Rules == nil {
		c.Rules = []Rule{}
	}
	return c, nil
}

// Save writes c to path atomically, so a crash never leaves a half-written
// rules file behind.
func (c Config) Save(path string) error {
	if err := c.normalize(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	// 0700 like the rest of the state dir, which also holds the TLS key.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rules-*.json")
	if err != nil {
		return fmt.Errorf("save rules: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("save rules: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("save rules: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("save rules: %w", err)
	}
	// The file holds no secrets and is meant to be committed.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("save rules: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}

// normalize validates every rule and canonicalises its fields in place.
func (c *Config) normalize() error {
	seen := make(map[string]bool)
	for i := range c.Rules {
		r := &c.Rules[i]
		m, err := NormalizeDomain(r.Match)
		if err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
		r.Match = m
		if !validExit(r.Via) {
			return fmt.Errorf("rule %d (%s): \"via\" must be an exit name (letters, digits, '-' or '_')", i+1, m)
		}
		switch r.OnExitDown {
		case "":
			r.OnExitDown = FailClosed
		case FailClosed, FallbackDirect:
		default:
			return fmt.Errorf("rule %d (%s): on_exit_down must be %q or %q", i+1, m, FailClosed, FallbackDirect)
		}
		key := ruleKey(m, r.Exact)
		if seen[key] {
			return fmt.Errorf("rule %d: %s is listed twice", i+1, m)
		}
		seen[key] = true
	}
	return nil
}

// NormalizeDomain lowercases a rule's domain, strips a trailing dot and one
// leading dot (the NO_PROXY habit), and canonicalises IP literals. It rejects
// anything a client could never send as a host, so a rule is never accepted
// and then silently dead: URLs, ports, wildcards, empty labels and non-ASCII
// names (clients send the punycode form).
func NormalizeDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if ip, ok := canonicalIP(d); ok {
		return ip, nil
	}
	d = strings.TrimPrefix(d, ".")
	switch {
	case d == "":
		return "", errors.New("empty domain")
	case strings.Contains(d, "://") || strings.ContainsAny(d, "/?#@"):
		return "", fmt.Errorf("%q is a URL; give only the domain, e.g. reddit.com", d)
	case strings.Contains(d, "*"):
		return "", fmt.Errorf("%q: no wildcards; %q already matches all subdomains", d, strings.TrimPrefix(strings.TrimPrefix(d, "*"), "."))
	case strings.Contains(d, ":"):
		return "", fmt.Errorf("%q: no ports; rules match hosts on every port", d)
	case len(d) > 253:
		return "", fmt.Errorf("%q is longer than a domain can be", d)
	}
	for label := range strings.SplitSeq(d, ".") {
		if label == "" {
			return "", fmt.Errorf("%q has an empty label", d)
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			case c > 127:
				return "", fmt.Errorf("%q: use the punycode form (xn--…) that clients send", d)
			default:
				return "", fmt.Errorf("%q: %q is not allowed in a domain", d, c)
			}
		}
	}
	return d, nil
}

func validExit(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// canonicalIP returns s in the one form every client path produces, so
// "2001:db8:0::1" and "::ffff:1.2.3.4" match rules for "2001:db8::1" and
// "1.2.3.4".
func canonicalIP(s string) (string, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	return addr.Unmap().WithZone("").String(), true
}

func ruleKey(match string, exact bool) string {
	if exact {
		return "=" + match
	}
	return match
}

// Table answers which rule, if any, applies to a host.
type Table struct {
	rules []Rule
	// index maps a ruleKey to the position of the first rule with it.
	index map[string]int
}

// NewTable indexes c's rules. c must have come from Load or passed Save.
func NewTable(c Config) *Table {
	t := &Table{rules: c.Rules, index: make(map[string]int, len(c.Rules))}
	for i, r := range c.Rules {
		k := ruleKey(r.Match, r.Exact)
		if _, ok := t.index[k]; !ok {
			t.index[k] = i
		}
	}
	return t
}

// Match returns the first rule, in config order, matching host. An exact
// rule matches only host itself; a suffix rule matches host and every
// subdomain. IP literals match only rules for that exact IP.
func (t *Table) Match(host string) (Rule, bool) {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	ip, isIP := canonicalIP(h)
	if isIP {
		h = ip
	}
	best := -1
	consider := func(k string) {
		if i, ok := t.index[k]; ok && (best < 0 || i < best) {
			best = i
		}
	}
	consider("=" + h)
	consider(h)
	if !isIP {
		// Walk parent suffixes: a.b.reddit.com → b.reddit.com → reddit.com → com.
		for i := strings.IndexByte(h, '.'); i >= 0; i = strings.IndexByte(h, '.') {
			h = h[i+1:]
			consider(h)
		}
	}
	if best < 0 {
		return Rule{}, false
	}
	return t.rules[best], true
}
