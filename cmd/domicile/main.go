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
	"runtime/debug"
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
  domicile status [-json]                   show exits, connections and active rules
  domicile verify [-exit name] [-json]      check what sites see through each exit
  domicile connect playwright-mcp|agent-browser|shell [-undo]
                                            point a tool at the proxy
  domicile run -- <command>                 run a command with the proxy in its environment
  domicile mcp                              read-only tools for AI agents, over stdio
  domicile service install|uninstall server|agent
                                            run domicile under systemd (Linux) or launchd (macOS)
  domicile version
  domicile rule add <domain> -via <exit> [flags]
  domicile rule remove <domain> [-exact]
  domicile rule list

  On the home device:
  domicile agent join <code>                pair with the server, then run
  domicile agent                            run (after pairing)

Run "domicile <command> -h" for a command's flags.
`

// version is set at build time by the release workflow:
// -ldflags "-X main.version=v1.2.3". It must stay a plain string for -X.
var version = "dev"

// buildVersion is version, falling back to the module version for builds the
// release ldflags never reach.
func buildVersion() string {
	if version == "dev" {
		return moduleVersion(debug.ReadBuildInfo())
	}
	return version
}

// moduleVersion is the version Go records for `go install module@v1.2.3`
// builds, which the release ldflags never reach.
func moduleVersion(bi *debug.BuildInfo, ok bool) string {
	if ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// errUsage marks errors already explained by a flag set's usage output.
var errUsage = errors.New("usage")

func main() {
	os.Exit(run())
}

// run is main's body, returning the process exit status so main exits once.
func run() int {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return 2
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
	case "service":
		err = runService(args, os.Stdin, os.Stdout)
	case "version", "-version", "--version":
		fmt.Println("domicile", buildVersion())
		return 0
	case "connect":
		err = runConnect(args, os.Stdout)
	case "run":
		err = runRun(ctx, args, os.Stdout)
	case "mcp":
		err = runMCP(ctx, args, os.Stdin, os.Stdout)
	case "status":
		err = runStatus(ctx, args, os.Stdout)
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
		return 0
	default:
		fmt.Fprintf(os.Stderr, "domicile: unknown command %q\n\n%s", cmd, usage)
		return 2
	}

	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if errors.Is(err, errUsage) {
		return 2
	}
	if errors.Is(err, errChecksFailed) {
		return 1
	}
	var code exitCode
	if errors.As(err, &code) {
		return int(code)
	}
	var rv revoked
	if errors.As(err, &rv) {
		log.Error("exiting", "err", rv.err)
		// launchd cannot skip one exit status: KeepAlive restarts on any
		// failure. Under our launchd job a revoked agent exits 0 to stay down.
		if os.Getenv("XPC_SERVICE_NAME") == launchdLabel("agent") {
			return 0
		}
		return exitRevoked
	}
	var vf verifyFailed
	if errors.As(err, &vf) {
		log.Error("verify could not run", "err", vf.err)
		return 3
	}
	if err != nil {
		log.Error("exiting", "err", err)
		return 1
	}
	return 0
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
