package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/state"
)

// configFile is the rules file's name inside the state directory.
const configFile = "domicile.json"

func defaultConfigPath() string { return filepath.Join(defaultStateDir(), configFile) }

func runRule(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: domicile rule add|remove|list")
	}
	switch args[0] {
	case "add":
		return ruleAdd(args[1:], out)
	case "remove":
		return ruleRemove(args[1:], out)
	case "list":
		return ruleList(args[1:], out)
	default:
		return fmt.Errorf("unknown rule command %q; use add, remove or list", args[0])
	}
}

func ruleAdd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("rule add", flag.ContinueOnError)
	via := fs.String("via", "", "exit that carries this domain (required)")
	exact := fs.Bool("exact", false, "match only this domain, not its subdomains")
	fallback := fs.Bool("fallback-direct", false, "go direct from the VPS when the exit is down (default: refuse)")
	note := fs.String("note", "", "why this rule exists")
	configPath := fs.String("config", defaultConfigPath(), "rules file")
	domain, err := positionalAndFlags(fs, args, "rule add <domain> -via <exit>")
	if err != nil {
		return err
	}
	if *via == "" {
		return errors.New("-via is required: which exit should carry " + domain)
	}

	unlock, err := lockRules(*configPath)
	if err != nil {
		return err
	}
	defer unlock()
	c, err := rules.Load(*configPath)
	if err != nil {
		return err
	}
	r := rules.Rule{Match: domain, Exact: *exact, Via: *via, OnExitDown: rules.FailClosed, Note: *note}
	if *fallback {
		r.OnExitDown = rules.FallbackDirect
	}
	if r.Match, err = rules.NormalizeDomain(r.Match); err != nil {
		return err
	}
	verb := "added"
	pos := findRule(c, r.Match, r.Exact)
	if pos >= 0 {
		c.Rules[pos] = r // keep its place: order decides which rule wins
		verb = "updated"
	} else {
		pos = len(c.Rules)
		c.Rules = append(c.Rules, r)
	}
	if err := c.Save(*configPath); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s rule: %s via %s (%s)\n", verb, describe(r), r.Via, r.OnExitDown)
	if earlier, ok := rules.NewTable(rules.Config{Rules: c.Rules[:pos]}).Match(r.Match); ok {
		fmt.Fprintf(out, "warning: the earlier rule %s matches first, so this rule has no effect; rules are first-match\n", describe(earlier))
	}
	fmt.Fprintf(out, "wrote %s\nA running server applies it within a second (it reads -config, default <state-dir>/%s).\n", absPath(*configPath), configFile)
	return nil
}

func ruleRemove(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("rule remove", flag.ContinueOnError)
	exact := fs.Bool("exact", false, "remove the exact-match rule rather than the domain rule")
	configPath := fs.String("config", defaultConfigPath(), "rules file")
	domain, err := positionalAndFlags(fs, args, "rule remove <domain>")
	if err != nil {
		return err
	}
	if domain, err = rules.NormalizeDomain(domain); err != nil {
		return err
	}
	unlock, err := lockRules(*configPath)
	if err != nil {
		return err
	}
	defer unlock()
	c, err := rules.Load(*configPath)
	if err != nil {
		return err
	}
	i := findRule(c, domain, *exact)
	if i < 0 {
		return fmt.Errorf("no rule for %s", describe(rules.Rule{Match: domain, Exact: *exact}))
	}
	c.Rules = append(c.Rules[:i], c.Rules[i+1:]...)
	if err := c.Save(*configPath); err != nil {
		return err
	}
	fmt.Fprintf(out, "removed rule: %s\nwrote %s\nA running server applies it within a second.\n", describe(rules.Rule{Match: domain, Exact: *exact}), absPath(*configPath))
	return nil
}

func ruleList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("rule list", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "rules file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := rules.Load(*configPath)
	if err != nil {
		return err
	}
	if len(c.Rules) == 0 {
		fmt.Fprintln(out, "No rules: every destination goes direct from the VPS.")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "MATCH\tVIA\tIF EXIT DOWN\tNOTE")
	for _, r := range c.Rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", describe(r), r.Via, r.OnExitDown, printable(r.Note))
	}
	fmt.Fprintln(tw, "(anything else)\tdirect\t\t")
	return tw.Flush()
}

// positionalAndFlags accepts one positional argument anywhere among the
// flags, so both the documented `rule add reddit.com -via home` and `rule add
// -via home reddit.com` work; the flag package alone stops at the first
// non-flag. usage is the command line shown on error.
func positionalAndFlags(fs *flag.FlagSet, args []string, usage string) (string, error) {
	var domain string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return "", err
			}
			return "", errUsage
		}
		if fs.NArg() == 0 {
			break
		}
		if domain != "" {
			return "", fmt.Errorf("unexpected argument %q; usage: domicile %s", fs.Arg(0), usage)
		}
		domain, args = fs.Arg(0), fs.Args()[1:]
	}
	if domain == "" {
		return "", errors.New("usage: domicile " + usage)
	}
	return domain, nil
}

// lockRules serialises read-modify-write of the rules file, so two `rule`
// commands at once cannot lose an update. It locks the directory, leaving no
// lock file beside a rules file that may be committed.
func lockRules(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return state.LockDir(filepath.Dir(path), 2*time.Second)
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func findRule(c rules.Config, match string, exact bool) int {
	for i, r := range c.Rules {
		if r.Match == match && r.Exact == exact {
			return i
		}
	}
	return -1
}

func describe(r rules.Rule) string {
	if r.Exact {
		return r.Match + " (exact)"
	}
	return r.Match + " (and subdomains)"
}
