package main

import (
	"net"
	"testing"
)

func TestDefaultProxyAddrIsLoopback(t *testing.T) {
	host, _, err := net.SplitHostPort(defaultProxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Fatalf("default proxy address %q is not loopback", defaultProxyAddr)
	}
}
