package main

import (
	"maps"
	"strings"
	"testing"
)

func TestParseExits(t *testing.T) {
	tok := strings.Repeat("a", minTokenLen)
	tests := []struct {
		name    string
		in      string
		want    map[string]string
		wantErr string
	}{
		{"one", "home=" + tok, map[string]string{"home": tok}, ""},
		{"several with spaces", " home=" + tok + " , office=" + tok + "=x ", map[string]string{"home": tok, "office": tok + "=x"}, ""},
		{"empty", "  ", nil, "no exits"},
		{"missing token", "home=", nil, "name=token"},
		{"missing name", "=" + tok, nil, "name=token"},
		{"no separator", "home", nil, "name=token"},
		{"token too short", "home=" + tok[1:], nil, "openssl rand"},
		{"token too long", "home=" + strings.Repeat("a", 256), nil, "openssl rand"},
		{"name too long", strings.Repeat("n", 256) + "=" + tok, nil, "name longer"},
		{"duplicate", "home=" + tok + ",home=" + tok, nil, "twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExits(tt.in)
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

func TestParseExitsDoesNotEchoTokens(t *testing.T) {
	_, err := parseExits("home=supersecret,broken")
	if err == nil || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("error %v must not contain a token", err)
	}
	_, err = parseExits("home=supersecret")
	if err == nil || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("error %v must not contain a token", err)
	}
}
