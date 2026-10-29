package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"
)

// exitRevoked is how `domicile agent` exits when the server rejects its
// credential or join code. Service managers are told not to restart on it,
// since retrying cannot help.
const exitRevoked = 4

// systemdUnit is a hardened unit that runs domicile as the invoking user
// (decision S-23). The server alone gets CAP_NET_BIND_SERVICE, to listen on
// UDP 443; nothing else is granted.
var systemdUnit = template.Must(template.New("unit").Parse(`[Unit]
Description=domicile {{.Role}}
Documentation=https://github.com/avinash-1707/domicile
After=network-online.target
Wants=network-online.target

[Service]
User={{.User}}
ExecStart={{.Binary}} {{.Role}} -state-dir {{.StateDir}}
Restart=on-failure
RestartSec=5
# 2: bad flags; 4: credential revoked. Restarting cannot fix either.
RestartPreventExitStatus=2 {{.Revoked}}
{{- if eq .Role "server"}}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
{{- else}}
CapabilityBoundingSet=
{{- end}}
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={{.StateDir}}
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
# AF_NETLINK lets the exit list its own interfaces for the deny list.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
`))

// launchdPlist runs the agent on a Mac while its user is logged in.
var launchdPlist = template.Must(template.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Binary}}</string>
		<string>{{.Role}}</string>
		<string>-state-dir</string>
		<string>{{.StateDir}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>StandardErrorPath</key>
	<string>{{.StateDir}}/{{.Role}}.log</string>
</dict>
</plist>
`))

type serviceSpec struct {
	Role, User, UID, Binary, StateDir, Label string
	Revoked                                  int
}

func launchdLabel(role string) string { return "dev.domicile." + role }

// errRootUser refuses services that would run as root (decision S-23).
var errRootUser = errors.New("refusing to run domicile as root: create a normal user, run `domicile init` or `domicile agent join` as them, then rerun this with sudo or -user <them>")

// serviceFile returns where the service definition goes, its contents and
// the commands that load it.
func serviceFile(goos string, s serviceSpec, home string) (path, body string, load []string, err error) {
	var b strings.Builder
	switch goos {
	case "linux":
		if err := systemdUnit.Execute(&b, s); err != nil {
			return "", "", nil, err
		}
		name := "domicile-" + s.Role + ".service"
		// restart, not start, so a reinstall picks up a new unit or binary.
		return "/etc/systemd/system/" + name, b.String(), []string{"systemctl daemon-reload", "systemctl enable " + name, "systemctl restart " + name}, nil
	case "darwin":
		s.Label = launchdLabel(s.Role)
		if err := launchdPlist.Execute(&b, s); err != nil {
			return "", "", nil, err
		}
		p := filepath.Join(home, "Library", "LaunchAgents", s.Label+".plist")
		return p, b.String(), []string{"launchctl bootstrap gui/" + s.UID + " " + p}, nil
	default:
		return "", "", nil, fmt.Errorf("services are supported on Linux (systemd) and macOS (launchd), not %s", goos)
	}
}

func runService(args []string, in io.Reader, out io.Writer) error {
	if len(args) < 2 || (args[0] != "install" && args[0] != "uninstall") || (args[1] != "server" && args[1] != "agent") {
		return errors.New("usage: domicile service install|uninstall server|agent [flags]")
	}
	action, role := args[0], args[1]
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	asUser := fs.String("user", "", "user the service runs as (default: you, or $SUDO_USER under sudo)")
	stateDir := fs.String("state-dir", "", "state directory the service uses (default: that user's)")
	yes := fs.Bool("yes", false, "do not ask before writing the file and running the commands")
	printOnly := fs.Bool("print", false, "print the service file and commands, change nothing")
	if err := parseFlags(fs, args[2:]); err != nil {
		return err
	}

	if runtime.GOOS == "darwin" && os.Getuid() == 0 {
		return errors.New("on macOS the agent runs in your login session: run this without sudo")
	}
	u, err := serviceUser(*asUser)
	// Removing a unit runs nothing as root, so a root login may uninstall.
	if err != nil && !(errors.Is(err, errRootUser) && action == "uninstall") {
		return err
	}
	if *stateDir == "" {
		*stateDir = filepath.Join(u.HomeDir, ".local", "state", "domicile")
		if u.Uid == strconv.Itoa(os.Getuid()) {
			*stateDir = defaultStateDir() // the same directory init and join used
		}
	}
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		return err
	}
	spec := serviceSpec{Role: role, User: u.Username, UID: u.Uid, Binary: bin, StateDir: absPath(*stateDir), Revoked: exitRevoked}
	for _, p := range []string{spec.Binary, spec.StateDir} {
		if err := checkServicePath(p); err != nil {
			return err
		}
	}
	path, body, load, err := serviceFile(runtime.GOOS, spec, u.HomeDir)
	if err != nil {
		return err
	}

	if action == "uninstall" {
		return uninstallService(runtime.GOOS, role, u.Uid, path, in, out, *yes, *printOnly)
	}

	// A unit pointing at a directory without state crash-loops forever.
	need := map[string]string{"server": stateFile, "agent": agentFile}[role]
	if _, err := os.Stat(filepath.Join(spec.StateDir, need)); err != nil {
		return fmt.Errorf("no %s in %s: run `domicile %s` there first, or pass -state-dir", need, spec.StateDir, map[string]string{"server": "init", "agent": "agent join"}[role])
	}
	fmt.Fprintf(out, "This will write %s:\n\n%s\nand run:\n  %s\n", path, body, strings.Join(load, "\n  "))
	if *printOnly || !confirm(in, out, *yes) {
		return nil
	}
	if runtime.GOOS == "darwin" {
		_ = runShell(launchdStop(u.Uid, role), io.Discard) // replace a loaded older version; fails when none is
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("%w (system services need root: run it with sudo)", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("%w (system services need root: run it with sudo)", err)
	}
	for _, c := range load {
		if err := runShell(c, out); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Installed and started domicile %s.\n", role)
	return nil
}

func launchdStop(uid, role string) string {
	return "launchctl bootout gui/" + uid + "/" + launchdLabel(role)
}

func uninstallService(goos, role, uid, path string, in io.Reader, out io.Writer, yes, printOnly bool) error {
	stop := "systemctl disable --now domicile-" + role + ".service"
	if goos == "darwin" {
		stop = launchdStop(uid, role)
	}
	fmt.Fprintf(out, "This will run:\n  %s\nand remove %s\n", stop, path)
	if printOnly || !confirm(in, out, yes) {
		return nil
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(out, "Not installed.")
		return nil
	}
	// launchctl also fails when the agent is installed but not loaded, so
	// only systemd's answer is trusted; a denied disable must not leave a
	// running service without its unit file.
	if err := runShell(stop, out); err != nil && goos != "darwin" {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if goos != "darwin" {
		if err := runShell("systemctl daemon-reload", out); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Removed %s.\n", path)
	return nil
}

// serviceUser picks who the service runs as: the flag, else the user who
// ran sudo, else the current user. Root is refused with errRootUser, and
// the user is still returned for callers that can allow it.
func serviceUser(name string) (*user.User, error) {
	if name == "" {
		name = os.Getenv("SUDO_USER")
	}
	var u *user.User
	var err error
	if name == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(name)
	}
	if err != nil {
		return nil, err
	}
	if u.Uid == "0" {
		return u, errRootUser
	}
	return u, nil
}

// checkServicePath rejects paths the unit or plist cannot hold verbatim:
// systemd splits on whitespace and expands %, and the plist is XML.
// runShell splits commands on whitespace for the same reason.
func checkServicePath(p string) error {
	if i := strings.IndexFunc(p, func(r rune) bool { return r <= ' ' || r == 0x7f || strings.ContainsRune(`%"'\&<>`, r) }); i >= 0 {
		return fmt.Errorf("%q: services cannot use a path containing %q; move it or pass -state-dir", p, p[i])
	}
	return nil
}

func confirm(in io.Reader, out io.Writer, yes bool) bool {
	if yes {
		return true
	}
	fmt.Fprint(out, "\nProceed? [y/N] ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	ok := strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
	if !ok {
		fmt.Fprintln(out, "Nothing changed.")
	}
	return ok
}

func runShell(command string, out io.Writer) error {
	f := strings.Fields(command)
	c := exec.Command(f[0], f[1:]...)
	c.Stdout, c.Stderr = out, out
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s: %w", command, err)
	}
	return nil
}
