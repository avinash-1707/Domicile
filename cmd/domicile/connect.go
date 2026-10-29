package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/avinash-1707/domicile/internal/secret"
	"github.com/avinash-1707/domicile/internal/state"
)

// Each tool gets its own proxy user, so one can be revoked without the
// others (`domicile user remove <tool>` or `connect -undo`). These names are
// reserved: `user add` refuses them.
const (
	toolPlaywright   = "playwright-mcp"
	toolAgentBrowser = "agent-browser"
	toolShell        = "shell"
)

var reservedUsers = map[string]bool{toolPlaywright: true, toolAgentBrowser: true, toolShell: true, toolRun: true}

// webRTCFlag stops Chromium from using UDP outside the proxy, which would
// reveal the VPS's address to WebRTC-capable pages.
const webRTCFlag = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"

// toolSecrets are the files under the state dir that hold a tool's password.
var toolSecrets = map[string][]string{
	toolPlaywright: {"playwright-mcp.json"},
	toolShell:      {"shell.env"},
}

func runConnect(args []string, out io.Writer) error {
	tool := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		tool, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for server state")
	proxyAddr := fs.String("proxy", defaultProxyAddr, "address of domicile's proxy, as passed to `domicile server -proxy`")
	undo := fs.Bool("undo", false, "restore every file connect changed for this tool and revoke its proxy user")
	file := fs.String("file", "", "config file to change: an MCP client's JSON for playwright-mcp (default: print the `claude mcp add` command instead), the agent-browser config (default ~/.agent-browser/config.json)")
	rotate := fs.Bool("rotate", false, "shell: issue a new password even if the env file exists")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	switch tool {
	case toolPlaywright, toolAgentBrowser, toolShell:
	default:
		return fmt.Errorf("usage: domicile connect playwright-mcp|agent-browser|shell [flags]")
	}
	if *undo {
		return disconnect(tool, *stateDir, out)
	}
	if _, _, err := net.SplitHostPort(*proxyAddr); err != nil {
		return fmt.Errorf("-proxy: %w", err)
	}

	switch tool {
	case toolPlaywright:
		// Check the MCP file before issuing a credential, so a refused
		// change leaves nothing behind.
		var plan *fileChange
		if *file != "" {
			p, err := planPlaywright(*file, playwrightConfPath(*stateDir))
			if err != nil {
				return err
			}
			plan = p
		}
		password, err := rotateToolUser(*stateDir, tool)
		if err != nil {
			return err
		}
		return connectPlaywright(*stateDir, *proxyAddr, password, plan, out)
	case toolAgentBrowser:
		password, err := rotateToolUser(*stateDir, tool)
		if err != nil {
			return err
		}
		return connectAgentBrowser(*stateDir, *proxyAddr, password, *file, out)
	default:
		return connectShell(*stateDir, *proxyAddr, *rotate, out)
	}
}

// rotateToolUser gives tool a proxy user with a fresh password. A running
// server accepts it at once (state.Live re-reads the file on a login miss).
func rotateToolUser(stateDir, tool string) (string, error) {
	password, err := state.NewSecret()
	if err != nil {
		return "", err
	}
	err = state.Update(statePath(stateDir), func(st *state.State) error {
		st.Users[tool] = state.User{PasswordSHA256: secret.Digest(password), Created: time.Now().UTC()}
		return nil
	})
	return password, err
}

func proxyURL(scheme, addr, user, password string) string {
	return (&url.URL{Scheme: scheme, User: url.UserPassword(user, password), Host: addr}).String()
}

func shellExports(addr, user, password string) string {
	h := proxyURL("http", addr, user, password)
	return fmt.Sprintf("export ALL_PROXY=%q\nexport HTTPS_PROXY=%q\nexport HTTP_PROXY=%q\nexport NO_PROXY=localhost,127.0.0.1,::1\nexport NODE_USE_ENV_PROXY=1\n",
		proxyURL("socks5h", addr, user, password), h, h)
}

// connectShell keeps the exports in a 0600 file to source, so the password
// never goes into a shell profile, and reuses it so every open shell keeps
// working; -rotate issues a new one.
func connectShell(stateDir, addr string, rotate bool, out io.Writer) error {
	path := filepath.Join(stateDir, "shell.env")
	if _, err := os.Stat(path); err != nil || rotate {
		password, err := rotateToolUser(stateDir, toolShell)
		if err != nil {
			return err
		}
		if err := state.WriteFileAtomic(path, []byte(shellExports(addr, toolShell, password)), 0o600); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Load the proxy settings into a shell with:\n  . %s\n(the file is private to you; add that line to your shell profile to load it automatically)\n", absPath(path))
	return nil
}

// fileChange is a planned edit to a tool's config file.
type fileChange struct {
	path     string // symlinks resolved, so the link itself is kept
	original []byte
	existed  bool
	entries  int
	apply    func(confPath string) ([]byte, error)
}

func playwrightConfPath(stateDir string) string {
	return absPath(filepath.Join(stateDir, "playwright-mcp.json"))
}

// planPlaywright checks an MCP client file and prepares the edit that points
// its @playwright/mcp entries at domicile's Playwright config (ours: a
// --config already pointing there is replaced, not refused).
func planPlaywright(file, ours string) (*fileChange, error) {
	path, err := resolve(file)
	if err != nil {
		return nil, err
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := decodeJSON(original)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	servers, _ := doc["mcpServers"].(map[string]any)
	n := 0
	for name, v := range servers {
		entry, ok := v.(map[string]any)
		if !ok || !isPlaywright(entry) {
			continue
		}
		args, _ := entry["args"].([]any)
		for i, a := range args {
			s, _ := a.(string)
			flagName, value, inline := strings.Cut(s, "=")
			if !inline && i+1 < len(args) {
				value, _ = args[i+1].(string)
			}
			switch flagName {
			case "--config":
				if value == ours {
					continue // a previous connect; replaced below
				}
				// Playwright MCP takes one config file; replacing the user's
				// would silently drop their settings.
				return nil, fmt.Errorf("%s: server %q already uses --config; add the proxy to that file instead (browser.launchOptions.proxy with server, username, password), or run connect without -file for a config to copy from", file, name)
			case "--cdp-endpoint", "--extension", "--endpoint", "--remote-endpoint":
				// Attaching to an existing browser ignores launch options, so
				// the proxy would not apply and traffic would go direct.
				return nil, fmt.Errorf("%s: server %q attaches to an existing browser (%s), where the proxy would not apply", file, name, flagName)
			}
		}
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("%s has no @playwright/mcp server", file)
	}
	return &fileChange{path: path, original: original, existed: true, entries: n, apply: func(confPath string) ([]byte, error) {
		for _, v := range servers {
			entry, ok := v.(map[string]any)
			if !ok || !isPlaywright(entry) {
				continue
			}
			args, _ := entry["args"].([]any)
			var kept []any
			for i := 0; i < len(args); i++ {
				s, _ := args[i].(string)
				switch {
				case s == "--proxy-server" || s == "--proxy-bypass" || s == "--config":
					i++ // drop the flag and its value (only our own --config reaches here)
				case strings.HasPrefix(s, "--proxy-server=") || strings.HasPrefix(s, "--proxy-bypass=") || strings.HasPrefix(s, "--config="):
				default:
					kept = append(kept, args[i])
				}
			}
			entry["args"] = append(kept, "--config", confPath)
			// Environment equivalents would override the config file.
			if env, ok := entry["env"].(map[string]any); ok {
				for k := range env {
					if strings.HasPrefix(k, "PLAYWRIGHT_MCP_PROXY") || k == "PLAYWRIGHT_MCP_CONFIG" {
						delete(env, k)
					}
				}
			}
		}
		return encodeJSON(doc)
	}}, nil
}

var playwrightPackage = regexp.MustCompile(`^@playwright/mcp(@[^/\s]+)?$`)

// isPlaywright matches the official package spec or its binary exactly.
func isPlaywright(entry map[string]any) bool {
	if c, _ := entry["command"].(string); filepath.Base(c) == "playwright-mcp" {
		return true
	}
	args, _ := entry["args"].([]any)
	for _, a := range args {
		if s, _ := a.(string); playwrightPackage.MatchString(s) {
			return true
		}
	}
	return false
}

// connectPlaywright writes a Playwright MCP config holding the proxy and its
// credentials (Chromium ignores credentials in --proxy-server, decision
// S-20). With a planned file change it also points that MCP client at it.
func connectPlaywright(stateDir, addr, password string, plan *fileChange, out io.Writer) error {
	confPath := playwrightConfPath(stateDir)
	conf := map[string]any{
		"browser": map[string]any{
			"launchOptions": map[string]any{
				"proxy": map[string]string{"server": "http://" + addr, "username": toolPlaywright, "password": password},
				"args":  []string{webRTCFlag},
			},
		},
	}
	data, err := encodeJSON(conf)
	if err != nil {
		return err
	}
	if err := state.WriteFileAtomic(confPath, data, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "Wrote %s (proxy user %q; private to you, it holds the password).\n", confPath, toolPlaywright)

	if plan == nil {
		// A project .mcp.json is often committed; a machine-specific path in
		// it would break it for everyone else, so default to local scope.
		fmt.Fprintf(out, "\nAdd it to Claude Code (this machine only):\n  claude mcp add -s local playwright -- npx @playwright/mcp@latest --config %s\nOther MCP clients: run @playwright/mcp with --config %s\n", confPath, confPath)
		return nil
	}
	updated, err := plan.apply(confPath)
	if err != nil {
		return err
	}
	if err := applyChange(stateDir, toolPlaywright, plan, updated, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "Updated %d Playwright server entr%s in %s. Restart your MCP client.\nUndo with: domicile connect playwright-mcp -undo\n", plan.entries, plural(plan.entries, "y", "ies"), plan.path)
	return nil
}

// connectAgentBrowser sets agent-browser's user-level "proxy" key, which
// accepts credentials in the URL.
func connectAgentBrowser(stateDir, addr, password, file string, out io.Writer) error {
	if file == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		file = filepath.Join(home, ".agent-browser", "config.json")
	}
	path, err := resolve(file)
	if err != nil {
		return err
	}
	original, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	existed := err == nil
	doc := map[string]any{}
	if len(bytes.TrimSpace(original)) > 0 {
		if doc, err = decodeJSON(original); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
	}
	doc["proxy"] = proxyURL("http", addr, toolAgentBrowser, password)
	delete(doc, "proxyBypass") // domicile's rules decide what bypasses home
	updated, err := encodeJSON(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// The file now holds a proxy password.
	change := &fileChange{path: path, original: original, existed: existed}
	if err := applyChange(stateDir, toolAgentBrowser, change, updated, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "Set the proxy in %s (proxy user %q).\nUndo with: domicile connect agent-browser -undo\n", path, toolAgentBrowser)
	return nil
}

func decodeJSON(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // keep large numbers exact
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep & < > in URLs as written
	enc.SetIndent("", "  ")
	err := enc.Encode(v)
	return buf.Bytes(), err
}

// resolve follows symlinks, so a write replaces the target and keeps the link.
func resolve(file string) (string, error) {
	abs := absPath(file)
	p, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return p, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return abs, nil
	}
	return "", err
}

// backup remembers what connect changed in one file so -undo can put it back
// exactly. Contents are stored as strings so the file is readable by hand.
type backup struct {
	File     string `json:"file"`
	Existed  bool   `json:"existed"`
	Original string `json:"original"`
	Written  string `json:"written"`
}

func backupDir(stateDir, tool string) string { return filepath.Join(stateDir, "connect", tool) }

// backupPath is per file: connecting a second project must not lose the
// first one's original.
func backupPath(stateDir, tool, file string) string {
	sum := sha256.Sum256([]byte(file))
	return filepath.Join(backupDir(stateDir, tool), hex.EncodeToString(sum[:8])+".json")
}

// applyChange records a backup, then writes updated to the file.
func applyChange(stateDir, tool string, c *fileChange, updated []byte, perm os.FileMode) error {
	b := backup{File: c.path, Existed: c.existed, Original: string(c.original), Written: string(updated)}
	if prev, err := loadBackup(backupPath(stateDir, tool, c.path)); err == nil && string(c.original) == prev.Written {
		// Connecting again over our own last write: keep the first original
		// so undo returns to the file as it was before domicile touched it.
		// If the user edited the file since, their version is the new one.
		b.Existed, b.Original = prev.Existed, prev.Original
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(backupDir(stateDir, tool), 0o700); err != nil {
		return err
	}
	if err := state.WriteFileAtomic(backupPath(stateDir, tool, c.path), data, 0o600); err != nil {
		return err
	}
	return state.WriteFileAtomic(c.path, updated, perm)
}

func loadBackup(path string) (backup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return backup{}, err
	}
	var b backup
	err = json.Unmarshal(data, &b)
	return b, err
}

// disconnect restores every file connect changed for the tool and revokes its
// proxy user. A file changed since connect wrote it is left alone and named,
// but the credential is revoked regardless.
func disconnect(tool, stateDir string, out io.Writer) error {
	entries, err := os.ReadDir(backupDir(stateDir, tool))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var skipped []string
	for _, e := range entries {
		bp := filepath.Join(backupDir(stateDir, tool), e.Name())
		b, err := loadBackup(bp)
		if err != nil {
			return err
		}
		cur, err := os.ReadFile(b.File)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		switch {
		case string(cur) != b.Written:
			skipped = append(skipped, fmt.Sprintf("%s (changed since connect; its original is in %s)", b.File, bp))
			continue
		case b.Existed:
			if err := state.WriteFileAtomic(b.File, []byte(b.Original), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(out, "Restored %s.\n", b.File)
		default:
			if err := os.Remove(b.File); err != nil {
				return err
			}
			fmt.Fprintf(out, "Removed %s, which connect had created.\n", b.File)
		}
		if err := os.Remove(bp); err != nil {
			return err
		}
	}
	for _, f := range toolSecrets[tool] {
		if err := os.Remove(filepath.Join(stateDir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	err = state.Update(statePath(stateDir), func(st *state.State) error {
		delete(st.Users, tool)
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Revoked proxy user %q.\n", tool)
	if len(skipped) > 0 {
		return fmt.Errorf("left unchanged, restore by hand: %s", strings.Join(skipped, "; "))
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
