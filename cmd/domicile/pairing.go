package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/avinash-1707/domicile/internal/certs"
	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/secret"
	"github.com/avinash-1707/domicile/internal/state"
)

const (
	stateFile        = "state.json"
	defaultUser      = "agent"
	defaultJoinTTL   = time.Hour
	joinCodePrefix   = "dj1."
	defaultProxyPort = "1080"
)

func statePath(dir string) string { return filepath.Join(dir, stateFile) }

// runInit creates the server's state, certificate and first proxy user.
func runInit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for server state")
	publicAddr := fs.String("public-addr", "", "host:port exits dial to reach this server, e.g. vps.example.com:443 (can also be given to `add`)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *publicAddr != "" {
		if err := checkHostPort(*publicAddr); err != nil {
			return fmt.Errorf("-public-addr: %w", err)
		}
	}

	cert, err := certs.LoadOrCreate(*stateDir)
	if err != nil {
		return err
	}
	pin, err := certs.FingerprintOf(cert)
	if err != nil {
		return err
	}
	password, err := state.NewSecret()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	err = state.Create(statePath(*stateDir), state.State{
		PublicAddr: *publicAddr,
		Exits:      map[string]state.Exit{},
		Users:      map[string]state.User{defaultUser: {PasswordSHA256: secret.Digest(password), Created: now}},
	})
	if err != nil {
		return fmt.Errorf("%w; this server is already initialised", err)
	}

	fmt.Fprintf(out, "Initialised %s\nServer fingerprint: %s\n\n", *stateDir, pin)
	printProxyUser(out, defaultUser, password)
	fmt.Fprintf(out, "\nNext: pair a home device with\n  domicile add home%s\n", addrHint(*publicAddr))
	return nil
}

// runAdd issues a one-time join code for an exit.
func runAdd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for server state")
	addr := fs.String("addr", "", "host:port the exit should dial (default: -public-addr from init)")
	ttl := fs.Duration("ttl", defaultJoinTTL, "how long the join code stays valid")
	name, err := positionalAndFlags(fs, args, "add <exit-name>")
	if err != nil {
		return err
	}
	if err := checkName(name); err != nil {
		return err
	}
	if *ttl <= 0 {
		return errors.New("-ttl must be positive")
	}
	// Check the state first, so a wrong -state-dir does not leave a stray
	// key pair behind.
	if _, err := state.Load(statePath(*stateDir)); err != nil {
		return err
	}
	cert, err := certs.LoadOrCreate(*stateDir)
	if err != nil {
		return err
	}
	pin, err := certs.FingerprintOf(cert)
	if err != nil {
		return err
	}
	token, err := state.NewSecret()
	if err != nil {
		return err
	}

	var server string
	repairing := false
	err = state.Update(statePath(*stateDir), func(st *state.State) error {
		server = *addr
		if server == "" {
			server = st.PublicAddr
		}
		if server == "" {
			return errors.New("no address for exits to dial: pass -addr host:port, or set -public-addr with `domicile init`")
		}
		if err := checkHostPort(server); err != nil {
			return fmt.Errorf("-addr: %w", err)
		}
		e, ok := st.Exits[name]
		if !ok {
			e.Created = time.Now().UTC()
		}
		repairing = e.CredentialSHA256 != ""
		// A re-pair keeps the old credential working until the new join
		// completes, so a typo'd code does not take a live exit offline.
		e.Join = &state.JoinToken{SHA256: secret.Digest(token), Expires: time.Now().UTC().Add(*ttl)}
		st.Exits[name] = e
		return nil
	})
	if err != nil {
		return err
	}

	code, err := encodeJoinCode(joinCode{Server: server, Pin: pin.String(), Name: name, Token: token})
	if err != nil {
		return err
	}
	if repairing {
		fmt.Fprintf(out, "%q is already paired; its current credential stays valid until the new code is used.\nIf the device may be compromised, run `domicile remove %s` first.\n", name, name)
	}
	fmt.Fprintf(out, "On the home device, run (valid for %s, works once):\n\n  domicile agent join %s\n", ttl.Round(time.Minute), code)
	return nil
}

// runRemove revokes an exit. A running server drops its session within about
// a second.
func runRemove(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for server state")
	name, err := positionalAndFlags(fs, args, "remove <exit-name>")
	if err != nil {
		return err
	}
	var inUse []string
	err = state.Update(statePath(*stateDir), func(st *state.State) error {
		if _, ok := st.Exits[name]; !ok {
			return fmt.Errorf("no exit named %q", name)
		}
		delete(st.Exits, name)
		return nil
	})
	if err != nil {
		return err
	}
	// Rules naming the exit now fail closed (or fall back); say so.
	if c, err := rules.Load(filepath.Join(*stateDir, configFile)); err == nil {
		for _, r := range c.Rules {
			if r.Via == name {
				inUse = append(inUse, r.Match)
			}
		}
	}
	fmt.Fprintf(out, "Removed exit %q; a running server disconnects it within a second.\n", name)
	if len(inUse) > 0 {
		fmt.Fprintf(out, "Rules still route through it: %s. Remove them with `domicile rule remove`; the server will not start while they remain.\n", strings.Join(inUse, ", "))
	}
	return nil
}

// runUser manages proxy users. Passwords are always generated, never chosen.
func runUser(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: domicile user add|remove|list")
	}
	fs := flag.NewFlagSet("user "+args[0], flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for server state")
	path := func() string { return statePath(*stateDir) }

	switch args[0] {
	case "add":
		name, err := positionalAndFlags(fs, args[1:], "user add <name>")
		if err != nil {
			return err
		}
		if err := checkName(name); err != nil {
			return err
		}
		if strings.Contains(name, ":") {
			return errors.New("user names must not contain ':' (HTTP proxy auth splits on it)")
		}
		if reservedUsers[name] {
			return fmt.Errorf("%q is reserved for `domicile connect`/`run`; pick another name", name)
		}
		password, err := state.NewSecret()
		if err != nil {
			return err
		}
		err = state.Update(path(), func(st *state.State) error {
			if _, ok := st.Users[name]; ok {
				return fmt.Errorf("user %q exists; remove it first to issue a new password", name)
			}
			st.Users[name] = state.User{PasswordSHA256: secret.Digest(password), Created: time.Now().UTC()}
			return nil
		})
		if err != nil {
			return err
		}
		printProxyUser(out, name, password)
		return nil
	case "remove":
		name, err := positionalAndFlags(fs, args[1:], "user remove <name>")
		if err != nil {
			return err
		}
		err = state.Update(path(), func(st *state.State) error {
			if _, ok := st.Users[name]; !ok {
				return fmt.Errorf("no user named %q", name)
			}
			if len(st.Users) == 1 {
				return errors.New("cannot remove the last proxy user; add another first")
			}
			delete(st.Users, name)
			return nil
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Removed proxy user %q; new connections with it are refused.\n", name)
		return nil
	case "list":
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		st, err := state.Load(path())
		if err != nil {
			return err
		}
		names := make([]string, 0, len(st.Users))
		for n := range st.Users {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			fmt.Fprintln(out, n)
		}
		return nil
	default:
		return fmt.Errorf("unknown user command %q; use add, remove or list", args[0])
	}
}

func printProxyUser(out io.Writer, name, password string) {
	fmt.Fprintf(out, "Proxy user %q. The password is shown only now:\n", name)
	fmt.Fprintf(out, "  socks5h://%s:%s@127.0.0.1:%s\n", name, password, defaultProxyPort)
	fmt.Fprintf(out, "  http://%s:%s@127.0.0.1:%s\n", name, password, defaultProxyPort)
}

func addrHint(publicAddr string) string {
	if publicAddr != "" {
		return ""
	}
	return " -addr <vps-host>:443"
}

// joinCode is everything a new exit needs, in one pasteable string.
type joinCode struct {
	Server string `json:"s"`
	Pin    string `json:"p"`
	Name   string `json:"n"`
	Token  string `json:"t"`
}

func encodeJoinCode(c joinCode) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return joinCodePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeJoinCode(s string) (joinCode, error) {
	bad := errors.New("not a join code; copy the whole `dj1.…` string printed by `domicile add`")
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), joinCodePrefix)
	if !ok {
		return joinCode{}, bad
	}
	data, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return joinCode{}, bad
	}
	var c joinCode
	if err := json.Unmarshal(data, &c); err != nil {
		return joinCode{}, bad
	}
	if c.Server == "" || c.Pin == "" || c.Name == "" || c.Token == "" {
		return joinCode{}, bad
	}
	if _, err := certs.ParseFingerprint(c.Pin); err != nil {
		return joinCode{}, bad
	}
	return c, nil
}

var validName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func checkName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid name %q: use 1 to 64 letters, digits, '-' or '_'", name)
	}
	return nil
}

func checkHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("%q is not host:port", s)
	}
	return nil
}
