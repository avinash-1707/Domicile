package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/avinash-1707/domicile/internal/control"
	"github.com/avinash-1707/domicile/internal/verify"
)

// errChecksFailed makes `domicile verify` exit 1 without printing an extra
// error: the report already says what failed. Any other error means verify
// could not run and exits 3, so scripts can tell the two apart.
var errChecksFailed = errors.New("verify: checks failed")

// verifyFailed marks an error from verify that is not a check failure.
type verifyFailed struct{ err error }

func (e verifyFailed) Error() string { return e.err.Error() }
func (e verifyFailed) Unwrap() error { return e.err }

func runVerify(ctx context.Context, args []string, out io.Writer) error {
	asJSON := false
	err := verifyCmd(ctx, args, out, &asJSON)
	if err == nil || errors.Is(err, errChecksFailed) || errors.Is(err, flag.ErrHelp) || errors.Is(err, errUsage) {
		return err
	}
	if asJSON {
		// Scripts parsing stdout get a well-formed answer either way.
		_ = json.NewEncoder(out).Encode(map[string]string{"error": err.Error()})
	}
	return verifyFailed{err}
}

func verifyCmd(ctx context.Context, args []string, out io.Writer, jsonOut *bool) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for server state")
	controlPath := fs.String("control", "", "control socket of the running server (default <state-dir>/control.sock)")
	only := fs.String("exit", "", "check only this exit")
	asJSON := fs.Bool("json", false, "print the report as JSON (exit 0 all pass, 1 a check failed, 3 verify could not run)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	*jsonOut = *asJSON
	if *controlPath == "" {
		*controlPath = defaultControlPath(*stateDir)
	}
	cl := control.Client{Path: *controlPath}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	reports, err := checkExits(ctx, cl, *only)
	if err != nil {
		return err
	}
	if len(reports) == 0 {
		return errors.New("no exits configured; add one with `domicile add`")
	}

	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return err
		}
	} else {
		printReports(out, reports)
	}
	for _, r := range reports {
		if !r.OK {
			return errChecksFailed
		}
	}
	return nil
}

func filterExit(exits []control.ExitStatus, name string) []control.ExitStatus {
	for _, e := range exits {
		if e.Name == name {
			return []control.ExitStatus{e}
		}
	}
	return nil
}

func notConnected(e control.ExitStatus) string {
	if !e.Paired {
		return "not paired yet; run the `domicile agent join` command from `domicile add " + e.Name + "` on the device"
	}
	return "not connected; is `domicile agent` running on the device?"
}

func printReports(out io.Writer, reports []verify.Report) {
	for i, r := range reports {
		if i > 0 {
			fmt.Fprintln(out)
		}
		verdict := "PASS"
		if !r.OK {
			verdict = "FAIL"
		}
		fmt.Fprintf(out, "%s  %s\n", printable(r.Exit), verdict)
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, c := range r.Checks {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.Result, c.Name, printable(c.Detail))
		}
		tw.Flush()
	}
}

// printable drops control characters. Details include text from ip-api's
// unauthenticated answers, and an escape sequence there could redraw the
// terminal (turn "FAIL" into "PASS"). JSON output escapes them already.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		// Also drops format characters (bidi overrides, zero-width) and
		// line/paragraph separators, which can disguise text.
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
}
