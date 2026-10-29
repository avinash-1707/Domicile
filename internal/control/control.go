// Package control is the server's local control socket: a unix socket in
// the state directory, readable only by its owner, that the CLI uses to ask
// the running server about exits and to open a connection through a named
// exit regardless of the rules. Each connection carries one JSON request
// line and one JSON reply line; a successful dial then becomes the raw
// connection to the destination.
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/avinash-1707/domicile/internal/rules"
	"github.com/avinash-1707/domicile/internal/tunnel"
	"github.com/avinash-1707/domicile/internal/wire"
)

const (
	// requestTimeout bounds reading a request and completing a dial.
	requestTimeout = 20 * time.Second
	// maxRequest caps a request line; real ones are under 200 bytes.
	maxRequest = 4 << 10
)

// ExitStatus describes one configured exit.
type ExitStatus struct {
	Name           string     `json:"name"`
	Connected      bool       `json:"connected"`
	Paired         bool       `json:"paired"`
	ConnectedSince *time.Time `json:"connected_since,omitempty"`
}

// Status is a snapshot of the running server.
type Status struct {
	Started     time.Time    `json:"started"`
	TunnelAddr  string       `json:"tunnel_addr"`
	ProxyAddr   string       `json:"proxy_addr"`
	Fingerprint string       `json:"fingerprint"`
	Exits       []ExitStatus `json:"exits"`
	RulesFile   string       `json:"rules_file"`
	Rules       []rules.Rule `json:"rules"`
	// RulesError is set when the rules file changed but could not be
	// loaded; the server keeps routing by the last good rules.
	RulesError string `json:"rules_error,omitempty"`
}

// Blocked is a host an agent reported as blocking the datacenter IP. It is a
// suggestion for a human: nothing here changes routing.
type Blocked struct {
	Host    string    `json:"host"`
	Reason  string    `json:"reason"`
	Count   int       `json:"count"`
	Last    time.Time `json:"last"`
	Suggest string    `json:"suggest"`
}

// Handler answers control requests; the server command implements it.
type Handler interface {
	Status() Status
	DialExit(ctx context.Context, exit string, dst wire.Open) (tunnel.Stream, error)
	ReportBlocked(host, reason string) error
	Blocked() []Blocked
}

type request struct {
	Op     string `json:"op"`
	Exit   string `json:"exit,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   uint16 `json:"port,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type reply struct {
	Error   string    `json:"error,omitempty"`
	Status  *Status   `json:"status,omitempty"`
	Blocked []Blocked `json:"blocked,omitempty"`
}

// ErrInUse means another server is already answering on the socket.
var ErrInUse = errors.New("control socket is in use; is another domicile server running?")

// Listen creates the socket at path with owner-only permissions, replacing a
// stale socket left by a crashed server. It never removes anything that is
// not a socket, so a mistyped path cannot delete a file.
func Listen(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket; refusing to replace it", path)
		}
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s: %w", path, ErrInUse)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Create the socket 0600 from the start: a chmod afterwards would leave
	// a window in which others could connect if the directory is not 0700.
	// This runs at startup, before other goroutines, so the process-wide
	// umask change is safe.
	old := syscall.Umask(0o177)
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// Serve answers requests on l until ctx is cancelled.
func Serve(ctx context.Context, l net.Listener, h Handler, log *slog.Logger) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("control accept: %w", err)
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			continue
		}
		wg.Go(func() { handle(ctx, uc, h, log) })
	}
}

func handle(ctx context.Context, c *net.UnixConn, h Handler, log *slog.Logger) {
	defer c.Close()
	// Shutdown must not wait for an idle client to finish its request.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(requestTimeout))
	br := bufio.NewReaderSize(c, maxRequest)
	line, err := br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			writeReply(c, reply{Error: "request too large"})
		}
		return
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		writeReply(c, reply{Error: "bad request"})
		return
	}
	switch req.Op {
	case "status":
		st := h.Status()
		writeReply(c, reply{Status: &st})
	case "report_blocked":
		if err := h.ReportBlocked(req.Host, req.Reason); err != nil {
			writeReply(c, reply{Error: err.Error()})
			return
		}
		writeReply(c, reply{})
	case "blocked":
		writeReply(c, reply{Blocked: h.Blocked()})
	case "dial":
		dctx, cancel := context.WithTimeout(ctx, requestTimeout)
		st, err := h.DialExit(dctx, req.Exit, wire.Open{Host: req.Host, Port: req.Port})
		cancel()
		if err != nil {
			writeReply(c, reply{Error: err.Error()})
			return
		}
		if err := writeReply(c, reply{}); err != nil {
			st.Close()
			return
		}
		_ = c.SetDeadline(time.Time{})
		if !stop() { // ctx already fired; Pipe would only race the close
			st.Close()
			return
		}
		if err := tunnel.Pipe(ctx, st, &bufferedUnix{UnixConn: c, r: br}, tunnel.DefaultStallTimeout); err != nil {
			log.Debug("control dial ended", "exit", req.Exit, "host", req.Host, "err", err)
		}
	default:
		writeReply(c, reply{Error: fmt.Sprintf("unknown op %q", req.Op)})
	}
}

func writeReply(c net.Conn, r reply) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = c.Write(append(data, '\n'))
	return err
}

// bufferedUnix forwards bytes the client sent right after its request.
type bufferedUnix struct {
	*net.UnixConn
	r *bufio.Reader
}

func (c *bufferedUnix) Read(p []byte) (int, error) { return c.r.Read(p) }

// Client talks to a running server's control socket.
type Client struct {
	Path string
}

// Status asks the running server for a snapshot.
func (cl Client) Status(ctx context.Context) (Status, error) {
	c, br, err := cl.request(ctx, request{Op: "status"})
	if err != nil {
		return Status{}, err
	}
	defer c.Close()
	var r reply
	if err := readReply(br, &r); err != nil {
		return Status{}, err
	}
	if r.Error != "" {
		return Status{}, errors.New(r.Error)
	}
	if r.Status == nil {
		return Status{}, errors.New("server sent no status")
	}
	return *r.Status, nil
}

// ReportBlocked records that host blocked the datacenter IP.
func (cl Client) ReportBlocked(ctx context.Context, host, reason string) error {
	_, err := cl.simple(ctx, request{Op: "report_blocked", Host: host, Reason: reason})
	return err
}

// Blocked lists reported hosts with suggested rules.
func (cl Client) Blocked(ctx context.Context) ([]Blocked, error) {
	r, err := cl.simple(ctx, request{Op: "blocked"})
	return r.Blocked, err
}

func (cl Client) simple(ctx context.Context, req request) (reply, error) {
	c, br, err := cl.request(ctx, req)
	if err != nil {
		return reply{}, err
	}
	defer c.Close()
	var r reply
	if err := readReply(br, &r); err != nil {
		return reply{}, err
	}
	if r.Error != "" {
		return reply{}, errors.New(r.Error)
	}
	return r, nil
}

// DialExit opens a connection to host:port through the named exit.
func (cl Client) DialExit(ctx context.Context, exit, host string, port uint16) (net.Conn, error) {
	c, br, err := cl.request(ctx, request{Op: "dial", Exit: exit, Host: host, Port: port})
	if err != nil {
		return nil, err
	}
	var r reply
	if err := readReply(br, &r); err != nil {
		c.Close()
		return nil, err
	}
	if r.Error != "" {
		c.Close()
		return nil, fmt.Errorf("through %s: %s", exit, r.Error)
	}
	_ = c.SetDeadline(time.Time{})
	return &bufferedUnix{UnixConn: c, r: br}, nil
}

func (cl Client) request(ctx context.Context, req request) (*net.UnixConn, *bufio.Reader, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", cl.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot reach the server at %s (is `domicile server` running?): %w", cl.Path, err)
	}
	uc := c.(*net.UnixConn)
	if dl, ok := ctx.Deadline(); ok {
		_ = uc.SetDeadline(dl)
	}
	data, err := json.Marshal(req)
	if err != nil {
		uc.Close()
		return nil, nil, err
	}
	if _, err := uc.Write(append(data, '\n')); err != nil {
		uc.Close()
		return nil, nil, err
	}
	return uc, bufio.NewReader(uc), nil
}

func readReply(br *bufio.Reader, r *reply) error {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read control reply: %w", err)
	}
	return json.Unmarshal(line, r)
}
