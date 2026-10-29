package main

import (
	"runtime/debug"
	"testing"
)

func TestModuleVersion(t *testing.T) {
	for _, c := range []struct {
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}}, true, "v0.1.0"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, "dev"},
		{&debug.BuildInfo{}, true, "dev"},
		{nil, false, "dev"},
	} {
		if got := moduleVersion(c.bi, c.ok); got != c.want {
			t.Errorf("moduleVersion(%+v, %v) = %q, want %q", c.bi, c.ok, got, c.want)
		}
	}
}
