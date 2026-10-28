package main

import (
	"maps"
	"net"
	"strings"
	"testing"
)

func TestParseCredentials(t *testing.T) {
	tok := strings.Repeat("a", minSecretLen)
	tests := []struct {
		name    string
		in      string
		want    map[string]string
		wantErr string
	}{
		{"one", "home=" + tok, map[string]string{"home": tok}, ""},
		{"several with spaces", " home=" + tok + " , office=" + tok + "=x ", map[string]string{"home": tok, "office": tok + "=x"}, ""},
		{"empty", "  ", nil, "not set"},
		{"missing token", "home=", nil, "name=secret"},
		{"missing name", "=" + tok, nil, "name=secret"},
		{"no separator", "home", nil, "name=secret"},
		{"token too short", "home=" + tok[1:], nil, "openssl rand"},
		{"token too long", "home=" + strings.Repeat("a", 256), nil, "openssl rand"},
		{"name too long", strings.Repeat("n", 256) + "=" + tok, nil, "name longer"},
		{"duplicate", "home=" + tok + ",home=" + tok, nil, "twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCredentials(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCredentialsDoesNotEchoSecrets(t *testing.T) {
	_, err := parseCredentials("home=supersecret,broken")
	if err == nil || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("error %v must not contain a token", err)
	}
	_, err = parseCredentials("home=supersecret")
	if err == nil || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("error %v must not contain a token", err)
	}
}

func TestRouteExit(t *testing.T) {
	one := map[string]string{"home": "x"}
	two := map[string]string{"home": "x", "office": "y"}
	if got, err := routeExit("", one); err != nil || got != "home" {
		t.Fatalf("single exit = %q, %v", got, err)
	}
	if _, err := routeExit("", two); err == nil {
		t.Fatal("picked an exit arbitrarily among several")
	}
	if got, err := routeExit("office", two); err != nil || got != "office" {
		t.Fatalf("-via office = %q, %v", got, err)
	}
	if _, err := routeExit("garage", two); err == nil {
		t.Fatal("accepted -via for an unknown exit")
	}
}

func TestDefaultProxyAddrIsLoopback(t *testing.T) {
	host, _, err := net.SplitHostPort(defaultProxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Fatalf("default proxy address %q is not loopback", defaultProxyAddr)
	}
}
