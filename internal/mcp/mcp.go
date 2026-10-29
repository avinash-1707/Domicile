// Package mcp serves domicile's tools to an AI agent over the Model Context
// Protocol, as newline-delimited JSON-RPC 2.0 on stdin/stdout. Every tool is
// read-only with respect to routing: an agent can see status, run checks and
// report a blocked site, but only a human adds rules (security rule 6).
//
// Tool names, descriptions and input schemas live in tools/*.json.
package mcp

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"sync"
)

//go:embed tools/*.json
var toolFiles embed.FS

// Tool is one tool definition as listed to the client.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Tools returns the embedded tool definitions, sorted by name.
func Tools() ([]Tool, error) {
	entries, err := toolFiles.ReadDir("tools")
	if err != nil {
		return nil, err
	}
	var out []Tool
	for _, e := range entries {
		data, err := toolFiles.ReadFile(path.Join("tools", e.Name()))
		if err != nil {
			return nil, err
		}
		var t Tool
		if err := json.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("tool %s: %w", e.Name(), err)
		}
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b Tool) int {
		if a.Name < b.Name {
			return -1
		}
		return 1
	})
	return out, nil
}

// Handler runs a tool call and returns a JSON-serialisable result.
type Handler func(ctx context.Context, args json.RawMessage) (any, error)

// Server answers MCP requests.
type Server struct {
	Name     string
	Version  string
	Handlers map[string]Handler
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// supportedVersions lists MCP protocol revisions this server speaks, newest
// first. Tools-only servers are the same across them.
var supportedVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

const (
	codeParse          = -32700
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	// maxMessage bounds one request line.
	maxMessage = 1 << 20
)

// Serve reads requests from r and writes responses to w until r ends or
// ctx is cancelled. Requests are answered concurrently, since a check can
// take seconds.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	tools, err := Tools()
	if err != nil {
		return err
	}
	listed := make(map[string]bool, len(tools))
	for _, t := range tools {
		if s.Handlers[t.Name] == nil {
			return fmt.Errorf("tool %s has no handler", t.Name)
		}
		listed[t.Name] = true
	}
	// The reverse too: a handler without a reviewed definition must not be
	// callable (security rule 6 rests on the listed set).
	for name := range s.Handlers {
		if !listed[name] {
			return fmt.Errorf("handler %s has no tool definition", name)
		}
	}

	var mu sync.Mutex
	enc := json.NewEncoder(w)
	send := func(resp response) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(resp)
	}
	var wg sync.WaitGroup
	defer wg.Wait()

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxMessage)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{codeParse, "parse error"}})
			continue
		}
		if len(req.ID) == 0 {
			continue // a notification, such as notifications/initialized
		}
		wg.Go(func() {
			result, rerr := s.dispatch(ctx, req, tools)
			send(response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr})
		})
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (s *Server) dispatch(ctx context.Context, req request, tools []Tool) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		// Answer with the client's version only if it is one this server
		// implements; otherwise offer the latest it does.
		version := supportedVersions[0]
		if slices.Contains(supportedVersions, p.ProtocolVersion) {
			version = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": s.Name, "version": s.Version},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{codeInvalidParams, "invalid params"}
		}
		h := s.Handlers[p.Name]
		if h == nil {
			return nil, &rpcError{codeInvalidParams, "unknown tool " + p.Name}
		}
		if len(p.Arguments) == 0 {
			p.Arguments = json.RawMessage("{}")
		}
		out, err := h(ctx, p.Arguments)
		if err != nil {
			// Tool failures are results the model can read, not protocol errors.
			return toolResult(err.Error(), true), nil
		}
		text, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return toolResult(err.Error(), true), nil
		}
		return toolResult(string(text), false), nil
	default:
		return nil, &rpcError{codeMethodNotFound, "method not found: " + req.Method}
	}
}

func toolResult(text string, isError bool) map[string]any {
	r := map[string]any{"content": []map[string]string{{"type": "text", "text": text}}}
	if isError {
		r["isError"] = true
	}
	return r
}
