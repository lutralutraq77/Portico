// This test-only utility writes a small newc initramfs with fixed destinations.
// It does not read or extract arbitrary archives.
package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

type entry struct {
	name               string
	mode, major, minor uint32
	data               []byte
}

func main() {
	if len(os.Args) != 10 {
		panic("usage: archive output init cli-test controller-test pki-test adminauth-test adapter-test issuer-test app")
	}
	f, e := os.Create(os.Args[1])
	check(e)
	z := gzip.NewWriter(f)
	entries := []entry{{name: "dev", mode: 0040755}, {name: "proc", mode: 0040755}, {name: "sys", mode: 0040755}, {name: "tmp", mode: 0041777}, {name: "tests", mode: 0040755}, {name: "dev/console", mode: 0020600, major: 5, minor: 1}, {name: "dev/null", mode: 0020666, major: 1, minor: 3}, {name: "dev/urandom", mode: 0020444, major: 1, minor: 9}}
	entries = append(entries, entry{name: "etc", mode: 0040755}, entry{name: "etc/hosts", mode: 0100644, data: []byte("127.0.0.1 localhost\n::1 localhost\n")})
	for i, name := range []string{"init", "tests/cli", "tests/controller", "tests/pki", "tests/adminauth", "tests/adapter", "tests/issuer", "portico"} {
		data, e := os.ReadFile(os.Args[i+2])
		check(e)
		entries = append(entries, entry{name: name, mode: 0100755, data: data})
	}
	entries = append(entries, entry{name: "TRAILER!!!"})
	for i, v := range entries {
		header := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", i+1, v.mode, 0, 0, 1, 0, len(v.data), 0, 0, v.major, v.minor, len(v.name)+1, 0)
		write(z, []byte(header))
		write(z, append([]byte(v.name), 0))
		pad(z, 110+len(v.name)+1)
		write(z, v.data)
		pad(z, len(v.data))
	}
	check(z.Close())
	check(f.Close())
}
func pad(w io.Writer, n int)      { write(w, make([]byte, (4-n%4)%4)) }
func write(w io.Writer, b []byte) { _, e := w.Write(b); check(e) }
func check(e error) {
	if e != nil {
		panic(e)
	}
}
