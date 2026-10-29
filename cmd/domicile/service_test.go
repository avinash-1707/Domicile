package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceFiles(t *testing.T) {
	spec := serviceSpec{Role: "server", User: "alice", UID: "501", Binary: "/usr/local/bin/domicile", StateDir: "/home/alice/.local/state/domicile", Revoked: exitRevoked}
	path, body, load, err := serviceFile("linux", spec, "/home/alice")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/etc/systemd/system/domicile-server.service" || !strings.Contains(strings.Join(load, ";"), "systemctl restart domicile-server.service") {
		t.Fatalf("path %s load %v", path, load)
	}
	for _, want := range []string{
		"User=alice",
		"ExecStart=/usr/local/bin/domicile server -state-dir /home/alice/.local/state/domicile",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"NoNewPrivileges=yes", "ProtectSystem=strict",
		"ReadWritePaths=/home/alice/.local/state/domicile",
		"RestartPreventExitStatus=2 4",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("server unit lacks %q:\n%s", want, body)
		}
	}

	spec.Role = "agent"
	_, body, _, _ = serviceFile("linux", spec, "/home/alice")
	if strings.Contains(body, "CAP_NET_BIND_SERVICE") || !strings.Contains(body, "CapabilityBoundingSet=\n") {
		t.Fatalf("agent unit must have no capabilities:\n%s", body)
	}
	if !strings.Contains(body, "AF_NETLINK") {
		t.Fatal("agent cannot list interfaces for its deny list without AF_NETLINK")
	}

	path, body, load, err = serviceFile("darwin", spec, "/Users/alice")
	if err != nil || path != "/Users/alice/Library/LaunchAgents/dev.domicile.agent.plist" || !strings.Contains(body, "<string>agent</string>") || !strings.Contains(load[0], "launchctl bootstrap gui/501 ") {
		t.Fatalf("darwin: %s %v %v\n%s", path, load, err, body)
	}
	if _, _, _, err := serviceFile("windows", spec, ""); err == nil {
		t.Fatal("unsupported OS accepted")
	}
}

// serviceArgs adds -user nobody when the tests run as root (CI
// containers), since a root service is refused.
func serviceArgs(args ...string) []string {
	if os.Getuid() == 0 {
		return append(args, "-user", "nobody")
	}
	return args
}

func TestServicePrintChangesNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, agentFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runService(serviceArgs("install", "agent", "-print", "-state-dir", dir), strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "This will write") {
		t.Fatalf("output %q", out.String())
	}
}

func TestServiceInstallNeedsState(t *testing.T) {
	// A unit pointing at an empty directory would crash-loop at boot.
	err := runService(serviceArgs("install", "agent", "-print", "-state-dir", t.TempDir()), strings.NewReader(""), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "agent join") {
		t.Fatalf("err = %v, want a pointer to `agent join`", err)
	}
}

func TestServiceRefusesRoot(t *testing.T) {
	if _, err := serviceUser("root"); !errors.Is(err, errRootUser) {
		t.Fatalf("serviceUser(root) err = %v", err)
	}
}

func TestCheckServicePath(t *testing.T) {
	for p, ok := range map[string]bool{
		"/home/alice/.local/state/domicile": true,
		"/srv/my state":                     false,
		"/srv/100%":                         false,
		"/srv/a&b":                          false,
		"/srv/a\nExecStartPre=/bin/x":       false,
	} {
		if err := checkServicePath(p); (err == nil) != ok {
			t.Errorf("checkServicePath(%q) = %v", p, err)
		}
	}
}

func TestConfirm(t *testing.T) {
	for in, want := range map[string]bool{"y\n": true, "YES\n": true, "\n": false, "n\n": false, "": false} {
		if got := confirm(strings.NewReader(in), &bytes.Buffer{}, false); got != want {
			t.Errorf("confirm(%q) = %v", in, got)
		}
	}
	if !confirm(strings.NewReader(""), &bytes.Buffer{}, true) {
		t.Fatal("-yes did not skip the question")
	}
}
