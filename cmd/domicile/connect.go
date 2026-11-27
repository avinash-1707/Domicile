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
	toolPlaywright:   {"playwright-mcp.json", toolPlaywright + ".secret"},
	toolAgentBrowser: {toolAgentBrowser + ".secret"},
	toolShell:        {"shell.env", toolShell + ".secret"},
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
	rotate := fs.Bool("rotate", false, "issue a new password instead of reusing the tool's current one")
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

	// Every tool's file is checked before its credential is touched, so a
	// refused change leaves the working setup as it was.
	switch tool {
	case toolPlaywright:
		var plan *fileChange
		if *file != "" {
			p, err := planPlaywright(*file, playwrightConfPath(*stateDir))
			if err != nil {
				return err
			}
			plan = p
		}
		return withCredential(*stateDir, tool, *rotate, func(password string) error {
			return connectPlaywright(*stateDir, *proxyAddr, password, plan, out)
		})
	case toolAgentBrowser:
		plan, err := planAgentBrowser(*file)
		if err != nil {
			return err
		}
		return withCredential(*stateDir, tool, *rotate, func(password string) error {
			return connectAgentBrowser(*stateDir, *proxyAddr, password, plan, out)
		})
	default:
		return withCredential(*stateDir, tool, *rotate, func(password string) error {
			return connectShell(*stateDir, *proxyAddr, password, out)
		})
	}
}

// withCredential runs write with tool's password. If write fails after a new
// password was issued, the previous one is restored, so configs still
// holding it keep working.
func withCredential(stateDir, tool string, rotate bool, write func(password string) error) error {
	password, restore, err := toolCredential(stateDir, tool, rotate)
	if err != nil {
		return err
	}
	if err := write(password); err != nil {
		if rerr := restore(); rerr != nil {
			return errors.Join(err, fmt.Errorf("restore the previous %s credential: %w", tool, rerr))
		}
		return err
	}
	return nil
}

func proxyURL(scheme, addr, user, password string) string {
	return (&url.URL{Scheme: scheme, User: url.UserPassword(user, password), Host: addr}).String()
}

func shellExports(addr, user, password string) string {
	var b strings.Builder
	for _, v := range proxyVars(addr, user, password) {
		fmt.Fprintf(&b, "export %s=%q\n", v[0], v[1])
	}
	return b.String()
}

// connectShell keeps the exports in a 0600 file to source, so the password
// never goes into a shell profile. The file is rewritten every time, so a
// new -proxy address takes effect; the password is reused unless -rotate,
// so every open shell keeps working.
func connectShell(stateDir, addr, password string, out io.Writer) error {
	path := filepath.Join(stateDir, "shell.env")
	if err := state.WriteFileAtomic(path, []byte(shellExports(addr, toolShell, password)), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "Load the proxy settings into a shell with:\n  . %s\n(the file is private to you; add that line to your shell profile to load it automatically)\n", absPath(path))
	return nil
}

// fileChange is a planned edit to a tool's config file.
type fileChange struct {
	path     string // symlinks resolved, so the link itself is kept
	original []byte
	existed  bool
	mode     os.FileMode // of the original; kept when connect rewrites it
	entries  int
	// apply returns the edited file, given what connect points the tool at:
	// the Playwright config path, or the agent-browser proxy URL.
	apply func(target string) ([]byte, error)
}

// readOriginal reads a tool's config file and its permissions.
func readOriginal(path string) (data []byte, mode os.FileMode, existed bool, err error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	data, err = os.ReadFile(path)
	return data, info.Mode().Perm(), err == nil, err
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
	original, mode, existed, err := readOriginal(path)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, fmt.Errorf("%s: %w", file, os.ErrNotExist)
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
	return &fileChange{path: path, original: original, existed: true, mode: mode, entries: n, apply: func(confPath string) ([]byte, error) {
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
	if plan != nil {
		// The MCP file only names the config, so it is changed first: if
		// that fails, the config still holds the password the server
		// accepts once the credential is restored.
		updated, err := plan.apply(confPath)
		if err != nil {
			return err
		}
		if err := applyChange(stateDir, toolPlaywright, plan, updated, false); err != nil {
			return err
		}
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
	fmt.Fprintf(out, "Updated %d Playwright server entr%s in %s. Restart your MCP client.\nUndo with: domicile connect playwright-mcp -undo\n", plan.entries, plural(plan.entries, "y", "ies"), plan.path)
	return nil
}

// planAgentBrowser checks agent-browser's config and prepares the edit that
// sets its user-level "proxy" key, which accepts credentials in the URL.
func planAgentBrowser(file string) (*fileChange, error) {
	if file == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		file = filepath.Join(home, ".agent-browser", "config.json")
	}
	path, err := resolve(file)
	if err != nil {
		return nil, err
	}
	original, mode, existed, err := readOriginal(path)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{}
	if len(bytes.TrimSpace(original)) > 0 {
		if doc, err = decodeJSON(original); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
	}
	return &fileChange{path: path, original: original, existed: existed, mode: mode, apply: func(proxy string) ([]byte, error) {
		doc["proxy"] = proxy
		delete(doc, "proxyBypass") // domicile's rules decide what bypasses home
		return encodeJSON(doc)
	}}, nil
}

func connectAgentBrowser(stateDir, addr, password string, plan *fileChange, out io.Writer) error {
	updated, err := plan.apply(proxyURL("http", addr, toolAgentBrowser, password))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(plan.path), 0o700); err != nil {
		return err
	}
	// The file now holds a proxy password.
	if err := applyChange(stateDir, toolAgentBrowser, plan, updated, true); err != nil {
		return err
	}
	fmt.Fprintf(out, "Set the proxy in %s (proxy user %q).\nUndo with: domicile connect agent-browser -undo\n", plan.path, toolAgentBrowser)
	return nil
}

func decodeJSON(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // keep large numbers exact
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, errors.New("not a JSON object")
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
	File    string `json:"file"`
	Existed bool   `json:"existed"`
	// Mode is the original file's permissions, restored by undo. Backups
	// written before it existed have 0: undo then keeps the current mode.
	Mode     os.FileMode `json:"mode,omitempty"`
	Original string      `json:"original"`
	Written  string      `json:"written"`
}

func backupDir(stateDir, tool string) string { return filepath.Join(stateDir, "connect", tool) }

// backupPath is per file: connecting a second project must not lose the
// first one's original.
func backupPath(stateDir, tool, file string) string {
	sum := sha256.Sum256([]byte(file))
	return filepath.Join(backupDir(stateDir, tool), hex.EncodeToString(sum[:8])+".json")
}

// applyChange records a backup, then writes updated to the file. The file
// keeps its permissions, so an owner-only config holding other tools' keys
// stays owner-only; private forces 0600 because updated holds a password.
func applyChange(stateDir, tool string, c *fileChange, updated []byte, private bool) error {
	b := backup{File: c.path, Existed: c.existed, Mode: c.mode, Original: string(c.original), Written: string(updated)}
	if prev, err := loadBackup(backupPath(stateDir, tool, c.path)); err == nil && string(c.original) == prev.Written {
		// Connecting again over our own last write: keep the first original
		// so undo returns to the file as it was before domicile touched it.
		// If the user edited the file since, their version is the new one.
		b.Existed, b.Mode, b.Original = prev.Existed, prev.Mode, prev.Original
	}
	perm := c.mode
	switch {
	case private:
		perm = 0o600
	case !c.existed:
		perm = 0o644
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
			mode := b.Mode
			if mode == 0 {
				info, err := os.Stat(b.File)
				if err != nil {
					return err
				}
				mode = info.Mode().Perm()
			}
			if err := state.WriteFileAtomic(b.File, []byte(b.Original), mode); err != nil {
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
