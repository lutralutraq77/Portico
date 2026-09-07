package main

import (
	"bytes"
	"testing"
)

func TestCommandSurface(t *testing.T) {
	for _, test := range []struct {
		args []string
		want int
	}{{[]string{"version"}, 0}, {nil, 2}, {[]string{"renew"}, 2}, {[]string{"serve"}, 2}, {[]string{"serve", "--config", "relative.json"}, 1}, {[]string{"serve", "--config", "somewhere", "--unsafe"}, 2}, {[]string{"result", "--config", "relative.json", "--attempt", "bad"}, 1}} {
		var out bytes.Buffer
		if got := run(test.args, &out); got != test.want {
			t.Fatalf("%v returned %d, want %d", test.args, got, test.want)
		}
	}
}
