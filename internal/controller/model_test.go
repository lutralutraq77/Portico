package controller

import (
	"strconv"
	"testing"
)

func fmtInt(v int) string { return strconv.Itoa(v) }
func TestDestinationValidation(t *testing.T) {
	for _, v := range []string{"http://10.0.0.1", "10.0.0.0/24", "127.0.0.1", "::1", "fe80::1%eth0", "169.254.169.254", "0.0.0.0", "::", "224.0.0.1", "255.255.255.255", "010.0.0.1", "example.test", "10.0.0.1:22"} {
		if _, e := literal(v); e == nil {
			t.Errorf("accepted %q", v)
		}
	}
	for input, want := range map[string]string{"10.0.0.1": "10.0.0.1", "::ffff:192.168.1.2": "192.168.1.2", "fd00::1": "fd00::1"} {
		got, e := literal(input)
		if e != nil || got != want {
			t.Fatalf("%q -> %q, %v", input, got, e)
		}
	}
}
func FuzzDestination(f *testing.F) {
	for _, s := range []string{"10.0.0.1", "::ffff:127.0.0.1", "example.test", "192.168.1.1/24", "fe80::1%eth0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		canonical, e := literal(s)
		if e != nil {
			return
		}
		again, e := literal(canonical)
		if e != nil || again != canonical {
			t.Fatal("canonicalization is not stable")
		}
	})
}
