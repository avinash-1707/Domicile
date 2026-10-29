// Command domicile gives agents on a VPS a home-network exit. One binary has
// both roles: `domicile server` on the VPS and `domicile agent` on the home
// device.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const usage = `domicile gives agents on a VPS a home-network exit.

Usage:
  On the VPS:
  domicile init [-public-addr host:port]   create state, certificate, first proxy user
  domicile add <exit> [-addr host:port]     print a one-time join code for a home device
  domicile remove <exit>                    revoke an exit (disconnects it within a second)
  domicile user add|remove|list             manage proxy users
  domicile server [flags]                   run the VPS side
  domicile verify [-exit name] [-json]      check what sites see through each exit
  domicile rule add <domain> -via <exit> [flags]
  domicile rule remove <domain> [-exact]
  domicile rule list

  On the home device:
  domicile agent join <code>                pair with the server, then run
  domicile agent                            run (after pairing)

Run "domicile <command> -h" for a command's flags.
`

// errUsage marks errors already explained by a flag set's usage output.
var errUsage = errors.New("usage")

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "server":
		err = runServer(ctx, args, log)
	case "agent":
		err = runAgent(ctx, args, log)
	case "rule":
		err = runRule(args, os.Stdout)
	case "verify":
		err = runVerify(ctx, args, os.Stdout)
	case "init":
		err = runInit(args, os.Stdout)
	case "add":
		err = runAdd(args, os.Stdout)
	case "remove":
		err = runRemove(args, os.Stdout)
	case "user":
		err = runUser(args, os.Stdout)
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "domicile: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if errors.Is(err, errUsage) {
		os.Exit(2)
	}
	if errors.Is(err, errChecksFailed) {
		os.Exit(1)
	}
	var vf verifyFailed
	if errors.As(err, &vf) {
		log.Error("verify could not run", "err", vf.err)
		os.Exit(3)
	}
	if err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

// parseFlags runs fs.Parse and rejects stray positional arguments.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return errUsage
	}
	return nil
}
