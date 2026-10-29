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
  domicile server [flags]   run the VPS side
  domicile agent [flags]    run the exit on a home device
  domicile rule add <domain> -via <exit> [flags]
  domicile rule remove <domain> [-exact]
  domicile rule list

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
