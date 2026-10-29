package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

func handlers() map[string]Handler {
	ok := func(v any) Handler {
		return func(context.Context, json.RawMessage) (any, error) { return v, nil }
	}
	return map[string]Handler{
		"exit_status":   ok(map[string]any{"exits": []string{"home"}}),
		"exit_verify":   ok([]string{"report"}),
		"blocked_hosts": ok([]string{}),
		"report_blocked": func(_ context.Context, args json.RawMessage) (any, error) {
			var a struct{ Host string }
			json.Unmarshal(args, &a)
			if a.Host == "" {
				return nil, errors.New("host is required")
			}
			return map[string]string{"suggest": "domicile rule add " + a.Host + " -via home"}, nil
		},
	}
}

// session runs the server over pipes and returns a function that sends one
// request and reads one response.
func session(t *testing.T) func(string) map[string]any {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &Server{Name: "domicile", Version: "test", Handlers: handlers()}
	go func() {
		s.Serve(context.Background(), inR, outW)
		outW.Close()
	}()
	t.Cleanup(func() { inW.Close() })
	rd := bufio.NewReader(outR)
	return func(line string) map[string]any {
		t.Helper()
		if _, err := io.WriteString(inW, line+"\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := rd.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(resp, &m); err != nil {
			t.Fatalf("bad response %q: %v", resp, err)
		}
		return m
	}
}

func TestToolsAreReadOnlySet(t *testing.T) {
	// Security rule 6: the agent-facing surface is exactly these tools,
	// none of which can change routing.
	tools, err := Tools()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools {
		names = append(names, tl.Name)
		var schema map[string]any
		if err := json.Unmarshal(tl.InputSchema, &schema); err != nil || schema["type"] != "object" {
			t.Errorf("%s: input schema is not a JSON object schema", tl.Name)
		}
		if tl.Description == "" {
			t.Errorf("%s has no description", tl.Name)
		}
	}
	want := []string{"blocked_hosts", "exit_status", "exit_verify", "report_blocked"}
	if !slices.Equal(names, want) {
		t.Fatalf("tools = %v, want exactly %v", names, want)
	}
}

func TestProtocol(t *testing.T) {
	call := session(t)

	init := call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	res := init["result"].(map[string]any)
	if res["protocolVersion"] != "2025-06-18" || res["capabilities"].(map[string]any)["tools"] == nil {
		t.Fatalf("initialize = %v", init)
	}

	// A notification gets no response; the next request's answer is next.
	list := call(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if len(list["result"].(map[string]any)["tools"].([]any)) != 4 {
		t.Fatalf("tools/list = %v", list)
	}

	got := call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"report_blocked","arguments":{"host":"reddit.com","reason":"403"}}}`)
	text := got["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "domicile rule add reddit.com") {
		t.Fatalf("tools/call text = %q", text)
	}

	failed := call(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"report_blocked","arguments":{}}}`)
	if failed["result"].(map[string]any)["isError"] != true {
		t.Fatalf("a failing tool must report isError: %v", failed)
	}

	unknown := call(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"rule_add","arguments":{}}}`)
	if unknown["error"] == nil {
		t.Fatalf("calling a tool that does not exist succeeded: %v", unknown)
	}

	if m := call(`{"jsonrpc":"2.0","id":6,"method":"resources/list"}`); m["error"] == nil {
		t.Fatalf("unsupported method answered: %v", m)
	}
	if m := call(`not json`); m["error"] == nil {
		t.Fatalf("parse error not reported: %v", m)
	}
}

func TestUnlistedHandlerRefused(t *testing.T) {
	h := handlers()
	h["rule_add"] = func(context.Context, json.RawMessage) (any, error) { return nil, nil }
	s := &Server{Handlers: h}
	if err := s.Serve(context.Background(), strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("served a handler with no tool definition")
	}
}

func TestUnknownProtocolVersionGetsSupportedOne(t *testing.T) {
	call := session(t)
	m := call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}`)
	if got := m["result"].(map[string]any)["protocolVersion"]; got != supportedVersions[0] {
		t.Fatalf("answered %v to an unknown version", got)
	}
}

func TestUnknownToolIsInvalidParams(t *testing.T) {
	call := session(t)
	m := call(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}}`)
	if code := m["error"].(map[string]any)["code"].(float64); code != codeInvalidParams {
		t.Fatalf("code %v, want %d", code, codeInvalidParams)
	}
}

func TestEveryToolNeedsAHandler(t *testing.T) {
	h := handlers()
	delete(h, "exit_verify")
	s := &Server{Handlers: h}
	if err := s.Serve(context.Background(), strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("served with a tool missing its handler")
	}
}
