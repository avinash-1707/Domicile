package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/avinash-1707/domicile/internal/control"
)

func runStatus(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for server state")
	controlPath := fs.String("control", "", "control socket of the running server (default <state-dir>/control.sock)")
	asJSON := fs.Bool("json", false, "print the status as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *controlPath == "" {
		*controlPath = defaultControlPath(*stateDir)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := control.Client{Path: *controlPath}.Status(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	printStatus(out, st, time.Now())
	return nil
}

func printStatus(out io.Writer, st control.Status, now time.Time) {
	fmt.Fprintf(out, "server up %s, tunnel %s, proxy %s\n\n", now.Sub(st.Started).Round(time.Second), st.TunnelAddr, st.ProxyAddr)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "EXIT\tSTATE\tSINCE")
	for _, e := range st.Exits {
		state, since := "disconnected", ""
		switch {
		case e.Connected && e.ConnectedSince != nil:
			state = "connected"
			since = fmt.Sprintf("%s (%s ago)", e.ConnectedSince.Local().Format("2006-01-02 15:04:05"), now.Sub(*e.ConnectedSince).Round(time.Second))
		case !e.Paired:
			state = "not paired"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", printable(e.Name), state, since)
	}
	if len(st.Exits) == 0 {
		fmt.Fprintln(tw, "(none; add one with `domicile add`)\t\t")
	}
	tw.Flush()

	fmt.Fprintf(out, "\nRules from %s:\n", printable(st.RulesFile))
	if st.RulesError != "" {
		fmt.Fprintf(out, "  WARNING: the file changed but could not be loaded; still using the rules below: %s\n", printable(st.RulesError))
	}
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  MATCH\tVIA\tIF EXIT DOWN")
	for _, r := range st.Rules {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", describe(r), printable(r.Via), r.OnExitDown)
	}
	fmt.Fprintln(tw, "  (anything else)\tdirect\t")
	tw.Flush()
}
