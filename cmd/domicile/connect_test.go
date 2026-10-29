package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avinash-1707/domicile/internal/control"
	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/secret"
	"github.com/avinash-1707/domicile/internal/state"
)

func initState(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := runInit([]string{"-state-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	return dir
}

const sampleMCP = `{
  "mcpServers": {
    "playwright": {"command": "npx", "args": ["@playwright/mcp@latest", "--headless", "--proxy-server=http://old:1"], "env": {"PLAYWRIGHT_MCP_PROXY_SERVER": "http://old:2", "KEEP": "a&b"}},
    "github": {"command": "npx", "args": ["@modelcontextprotocol/server-github"]}
  }
}
`

func TestConnectPlaywrightAndUndo(t *testing.T) {
	dir := initState(t)
	mcpFile := filepath.Join(t.TempDir(), ".mcp.json")
	os.WriteFile(mcpFile, []byte(sampleMCP), 0o644)

	var out bytes.Buffer
	if err := runConnect([]string{toolPlaywright, "-state-dir", dir, "-file", mcpFile}, &out); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		MCPServers map[string]struct {
			Args []string `json:"args"`
		} `json:"mcpServers"`
	}
	data, _ := os.ReadFile(mcpFile)
	json.Unmarshal(data, &doc)
	conf := filepath.Join(dir, "playwright-mcp.json")
	got := doc.MCPServers["playwright"].Args
	want := []string{"@playwright/mcp@latest", "--headless", "--config", absPath(conf)}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("playwright args = %v, want %v", got, want)
	}
	if len(doc.MCPServers["github"].Args) != 1 {
		t.Fatal("an unrelated server was changed")
	}
	if strings.Contains(string(data), "PLAYWRIGHT_MCP_PROXY_SERVER") || !strings.Contains(string(data), `"KEEP": "a&b"`) {
		t.Fatalf("env not cleaned, or other env mangled:\n%s", data)
	}

	// The Playwright config carries credentials that the proxy accepts.
	var pc struct {
		Browser struct {
			LaunchOptions struct {
				Proxy struct{ Server, Username, Password string }
				Args  []string
			}
		}
	}
	raw, _ := os.ReadFile(conf)
	json.Unmarshal(raw, &pc)
	p := pc.Browser.LaunchOptions.Proxy
	st, _ := state.Load(statePath(dir))
	if p.Server != "http://127.0.0.1:1080" || p.Username != toolPlaywright || !secret.MatchesDigest(p.Password, st.Users[toolPlaywright].PasswordSHA256) {
		t.Fatalf("proxy config = %+v", p)
	}
	if info, _ := os.Stat(conf); info.Mode().Perm() != 0o600 {
		t.Fatalf("config holding a password is %o", info.Mode().Perm())
	}
	if strings.Join(pc.Browser.LaunchOptions.Args, " ") != webRTCFlag {
		t.Fatalf("WebRTC flag missing: %v", pc.Browser.LaunchOptions.Args)
	}

	// Connecting twice keeps the original for undo.
	if err := runConnect([]string{toolPlaywright, "-state-dir", dir, "-file", mcpFile}, &out); err != nil {
		t.Fatal(err)
	}
	if err := runConnect([]string{toolPlaywright, "-undo", "-state-dir", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(mcpFile); string(data) != sampleMCP {
		t.Fatalf("undo did not restore the file byte for byte:\n%s", data)
	}
	st, _ = state.Load(statePath(dir))
	if _, ok := st.Users[toolPlaywright]; ok {
		t.Fatal("undo left the tool's proxy user")
	}
	if _, err := os.Stat(conf); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("undo left the Playwright config with its password")
	}
}

func TestUndoRefusesEditedFile(t *testing.T) {
	dir := initState(t)
	mcpFile := filepath.Join(t.TempDir(), ".mcp.json")
	os.WriteFile(mcpFile, []byte(sampleMCP), 0o644)
	if err := runConnect([]string{toolPlaywright, "-state-dir", dir, "-file", mcpFile}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(mcpFile, []byte(`{"mcpServers":{}}`), 0o644) // the user edited it since
	if err := runConnect([]string{toolPlaywright, "-undo", "-state-dir", dir}, &bytes.Buffer{}); err == nil {
		t.Fatal("undo overwrote a file the user changed")
	}
	if data, _ := os.ReadFile(mcpFile); string(data) != `{"mcpServers":{}}` {
		t.Fatal("the user's edit was lost")
	}
	// The credential and its secret file are revoked anyway.
	st, _ := state.Load(statePath(dir))
	if _, ok := st.Users[toolPlaywright]; ok {
		t.Fatal("refused undo left the credential")
	}
	if _, err := os.Stat(filepath.Join(dir, "playwright-mcp.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused undo left the password file")
	}
}

func TestConnectPlaywrightDefaultPrintsLocalScopeCommand(t *testing.T) {
	dir := initState(t)
	var out bytes.Buffer
	if err := runConnect([]string{toolPlaywright, "-state-dir", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "claude mcp add -s local playwright") {
		t.Fatalf("no local-scope command:\n%s", out.String())
	}
}

func TestConnectPlaywrightRefusesUnsafeEntries(t *testing.T) {
	dir := initState(t)
	for name, doc := range map[string]string{
		"own config":    `{"mcpServers":{"p":{"command":"npx","args":["@playwright/mcp","--config=/mine.json"]}}}`,
		"attach":        `{"mcpServers":{"p":{"command":"npx","args":["@playwright/mcp","--cdp-endpoint","http://x:9222"]}}}`,
		"no playwright": `{"mcpServers":{"p":{"command":"/home/x/playwright-tools/run.sh","args":["@playwright/mcp-foo"]}}}`,
	} {
		f := filepath.Join(t.TempDir(), ".mcp.json")
		os.WriteFile(f, []byte(doc), 0o644)
		if err := runConnect([]string{toolPlaywright, "-state-dir", dir, "-file", f}, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: connect accepted it", name)
		}
		if data, _ := os.ReadFile(f); string(data) != doc {
			t.Errorf("%s: file changed although connect refused", name)
		}
	}
	st, _ := state.Load(statePath(dir))
	if _, ok := st.Users[toolPlaywright]; ok {
		t.Fatal("a refused connect still issued a credential")
	}
}

func TestUndoRestoresEveryConnectedFile(t *testing.T) {
	dir := initState(t)
	a := filepath.Join(t.TempDir(), ".mcp.json")
	b := filepath.Join(t.TempDir(), ".mcp.json")
	os.WriteFile(a, []byte(sampleMCP), 0o644)
	other := strings.Replace(sampleMCP, "--headless", "--isolated", 1)
	os.WriteFile(b, []byte(other), 0o644)
	runConnect([]string{toolPlaywright, "-state-dir", dir, "-file", a}, &bytes.Buffer{})
	runConnect([]string{toolPlaywright, "-state-dir", dir, "-file", b}, &bytes.Buffer{})
	if err := runConnect([]string{toolPlaywright, "-undo", "-state-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(a); string(data) != sampleMCP {
		t.Fatal("the first project's file was not restored")
	}
	if data, _ := os.ReadFile(b); string(data) != other {
		t.Fatal("the second project's file was not restored")
	}
}

func TestReconnectAfterUserEditKeepsTheEdit(t *testing.T) {
	dir := initState(t)
	f := filepath.Join(t.TempDir(), ".mcp.json")
	os.WriteFile(f, []byte(sampleMCP), 0o644)
	runConnect([]string{toolPlaywright, "-state-dir", dir, "-file", f}, &bytes.Buffer{})
	edited, _ := os.ReadFile(f)
	edited = bytes.Replace(edited, []byte(`"--headless"`), []byte(`"--headless", "--isolated"`), 1)
	os.WriteFile(f, edited, 0o644)
	runConnect([]string{toolPlaywright, "-state-dir", dir, "-file", f}, &bytes.Buffer{})
	runConnect([]string{toolPlaywright, "-undo", "-state-dir", dir}, &bytes.Buffer{})
	if data, _ := os.ReadFile(f); string(data) != string(edited) {
		t.Fatalf("undo rewound past the user's edit:\n%s", data)
	}
}

func TestConnectAgentBrowserKeepsOtherSettings(t *testing.T) {
	dir := initState(t)
	file := filepath.Join(t.TempDir(), "ab", "config.json")
	os.MkdirAll(filepath.Dir(file), 0o700)
	original := `{"headed": true, "proxyBypass": "localhost"}`
	os.WriteFile(file, []byte(original), 0o644)

	if err := runConnect([]string{toolAgentBrowser, "-state-dir", dir, "-file", file}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	data, _ := os.ReadFile(file)
	json.Unmarshal(data, &doc)
	if doc["headed"] != true || doc["proxyBypass"] != nil || !strings.HasPrefix(doc["proxy"].(string), "http://agent-browser:") {
		t.Fatalf("config = %v", doc)
	}
	if info, _ := os.Stat(file); info.Mode().Perm() != 0o600 {
		t.Fatalf("config holding a password is %o", info.Mode().Perm())
	}
	if err := runConnect([]string{toolAgentBrowser, "-undo", "-state-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(file); string(data) != original {
		t.Fatalf("undo = %s", data)
	}

	// When connect created the file, undo removes it.
	fresh := filepath.Join(t.TempDir(), "config.json")
	if err := runConnect([]string{toolAgentBrowser, "-state-dir", dir, "-file", fresh}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("connect did not create the file: %v", err)
	}
	if err := runConnect([]string{toolAgentBrowser, "-undo", "-state-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("undo left a file connect had created")
	}
}

func TestConnectShellWritesPrivateEnvFile(t *testing.T) {
	dir := initState(t)
	var out bytes.Buffer
	if err := runConnect([]string{toolShell, "-state-dir", dir}, &out); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "shell.env")
	first, _ := os.ReadFile(env)
	if info, _ := os.Stat(env); info.Mode().Perm() != 0o600 || !strings.Contains(string(first), "NODE_USE_ENV_PROXY=1") {
		t.Fatalf("env file %o %q", info.Mode().Perm(), first)
	}
	if strings.Contains(out.String(), "shell:") {
		t.Fatal("the password was printed instead of kept in the file")
	}
	runConnect([]string{toolShell, "-state-dir", dir}, &bytes.Buffer{})
	if again, _ := os.ReadFile(env); string(again) != string(first) {
		t.Fatal("a second connect rotated the password and broke open shells")
	}
	runConnect([]string{toolShell, "-rotate", "-state-dir", dir}, &bytes.Buffer{})
	if rotated, _ := os.ReadFile(env); string(rotated) == string(first) {
		t.Fatal("-rotate did not rotate")
	}
}

func TestReservedUserNames(t *testing.T) {
	dir := initState(t)
	for _, name := range []string{toolPlaywright, toolAgentBrowser, toolShell, toolRun} {
		if err := runUser([]string{"add", name, "-state-dir", dir}, &bytes.Buffer{}); err == nil {
			t.Errorf("user add %s accepted a reserved name", name)
		}
	}
}

func TestRunPassesProxyAndExitCode(t *testing.T) {
	dir := initState(t)
	var out bytes.Buffer
	err := runRun(context.Background(), []string{"-state-dir", dir, "--", "sh", "-c", `echo "$NODE_USE_ENV_PROXY $HTTPS_PROXY"; exit 3`}, &out)
	var code exitCode
	if !errors.As(err, &code) || code != 3 {
		t.Fatalf("exit = %v, want the command's status 3", err)
	}
	if !strings.HasPrefix(out.String(), "1 http://run:") || !strings.Contains(out.String(), "@127.0.0.1:1080") {
		t.Fatalf("child environment = %q", out.String())
	}

	// The credential is stable across runs and valid for the proxy.
	pw1, _ := runCredential(dir)
	pw2, _ := runCredential(dir)
	st, _ := state.Load(statePath(dir))
	if pw1 != pw2 || !secret.MatchesDigest(pw1, st.Users[toolRun].PasswordSHA256) {
		t.Fatal("run credential not stable or not valid")
	}
	if err := runRun(context.Background(), []string{"-state-dir", dir, "sh"}, &out); err == nil {
		t.Fatal("run without -- accepted")
	}
}

func TestProxyEnvReplacesExisting(t *testing.T) {
	env := proxyEnv([]string{"PATH=/bin", "https_proxy=http://evil:1", "NO_PROXY=*"}, "127.0.0.1:1080", "pw")
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "evil") || strings.Contains(joined, "NO_PROXY=*") || !strings.Contains(joined, "PATH=/bin") {
		t.Fatalf("env = %v", env)
	}
}

func TestBlockedHostSuggestions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	state.Create(path, state.State{Exits: map[string]state.Exit{}, Users: map[string]state.User{}})
	live, _ := state.OpenLive(path)
	lr := &liveRules{conf: rules.Config{Rules: []rules.Rule{{Match: "reddit.com", Via: "home"}}}}
	h := controlHandler{blocked: &blockedHosts{hosts: map[string]*control.Blocked{}}, live: live, rules: lr}

	if err := h.ReportBlocked("WWW.Example.COM.", "HTTP 403"); err != nil {
		t.Fatal(err)
	}
	h.ReportBlocked("www.example.com", "again")
	h.ReportBlocked("old.reddit.com", "challenge")
	if err := h.ReportBlocked("https://x.com/login", "403"); err == nil {
		t.Fatal("a URL was accepted as a host")
	}
	got := map[string]control.Blocked{}
	for _, b := range h.Blocked() {
		got[b.Host] = b
	}
	if got["www.example.com"].Count != 2 || !strings.HasPrefix(got["www.example.com"].Suggest, "domicile rule add www.example.com") {
		t.Fatalf("example = %+v", got["www.example.com"])
	}
	if !strings.Contains(got["old.reddit.com"].Suggest, "already routed") {
		t.Fatalf("a host already covered by a rule was suggested again: %+v", got["old.reddit.com"])
	}
}
