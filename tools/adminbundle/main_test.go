package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type zipMember struct {
	name string
	mode os.FileMode
	data string
}

func seed(t *testing.T, extra ...zipMember) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	for _, item := range append([]zipMember{{"electron", 0755, "runtime"}, {"chrome-sandbox", 0755, "sandbox"}, {"chrome_crashpad_handler", 0755, "crash helper"}, {"LICENSE", 0644, "license"}, {"LICENSES.chromium.html", 0644, "notices"}, {"version", 0644, "44.3.0"}, {"locales/en-GB.pak", 0644, "locale"}}, extra...) {
		header := &zip.FileHeader{Name: item.name, Method: zip.Store}
		header.SetMode(item.mode)
		file, err := w.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, item.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "runtime.zip")
	if err := os.WriteFile(archive, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"main.cjs", "channel.cjs", "shell.cjs"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("isolated "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	hash := sha256.Sum256(data.Bytes())
	return dir, archive, hex.EncodeToString(hash[:])
}

func TestBundleHasOnlyFixedRootOwnedMembersAndIsDeterministic(t *testing.T) {
	dir, archive, digest := seed(t)
	first, second := filepath.Join(dir, "first.tar.gz"), filepath.Join(dir, "second.tar.gz")
	for _, output := range []string{first, second} {
		if err := build(output, archive, digest, dir, 1234567890); err != nil {
			t.Fatal(err)
		}
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("archive depends on host or output path")
	}
	z, err := gzip.NewReader(bytes.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	r := tar.NewReader(z)
	seen := map[string]bool{}
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(h.Name, prefix) || h.Uid != 0 || h.Gid != 0 || h.ModTime.Unix() != 1234567890 || seen[h.Name] {
			t.Fatal("unbound archive member")
		}
		seen[h.Name] = true
		if h.Name == prefix+"electron/chrome-sandbox" {
			if h.Mode != 04755 {
				t.Fatal("sandbox helper mode missing")
			}
		} else if h.Mode&07000 != 0 {
			t.Fatal("unexpected privileged mode")
		}
		if h.Name == prefix+"app/main.cjs" {
			value, err := io.ReadAll(r)
			if err != nil || string(value) != "isolated main.cjs" {
				t.Fatal("entrypoint substituted")
			}
		}
	}
	if !seen[prefix+"app/main.cjs"] || !seen[prefix+"electron/LICENSES.chromium.html"] {
		t.Fatal("missing application or upstream notices")
	}
	if err := build(first, archive, digest, dir, 1234567890); err == nil {
		t.Fatal("existing archive overwritten")
	}
	after, err := os.ReadFile(first)
	if err != nil || !bytes.Equal(a, after) {
		t.Fatal("existing archive changed")
	}
}

func TestBundleRejectsAmbiguousOrSpecialRuntimeEntries(t *testing.T) {
	for _, item := range []zipMember{{"../escape", 0644, "x"}, {"/absolute", 0644, "x"}, {"folder\\escape", 0644, "x"}, {"x:y", 0644, "x"}, {"electron", 0644, "duplicate"}, {"locales", 0644, "parent file"}, {"alias", os.ModeSymlink | 0777, "electron"}, {"pipe", os.ModeNamedPipe | 0600, ""}, {"a/b/c/d/e", 0644, "depth"}} {
		t.Run(item.name, func(t *testing.T) {
			dir, archive, digest := seed(t, item)
			if err := build(filepath.Join(dir, "output.tar.gz"), archive, digest, dir, 1234567890); err == nil {
				t.Fatal("unsafe runtime accepted")
			}
		})
	}
}

func TestBundleRejectsDigestSizeCRCAndMissingApplication(t *testing.T) {
	for _, name := range []string{"digest", "missing_app", "size", "crc", "entry_limit", "missing_runtime"} {
		t.Run(name, func(t *testing.T) {
			dir, archive, digest := seed(t)
			switch name {
			case "digest":
				digest = strings.Repeat("0", 64)
			case "missing_app":
				if err := os.Remove(filepath.Join(dir, "main.cjs")); err != nil {
					t.Fatal(err)
				}
			case "size", "entry_limit", "missing_runtime":
				reader, err := zip.OpenReader(archive)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				if name == "size" {
					reader.File[0].UncompressedSize64 = 513 * 1024 * 1024
				} else if name == "entry_limit" {
					for len(reader.File) < 257 {
						reader.File = append(reader.File, reader.File[0])
					}
				} else {
					reader.File = reader.File[1:]
				}
				if _, err := runtimeMembers(&reader.Reader); err == nil {
					t.Fatal("runtime bound ignored")
				}
				return
			case "crc":
				data, err := os.ReadFile(archive)
				if err != nil {
					t.Fatal(err)
				}
				index := bytes.Index(data, []byte("runtime"))
				if index < 0 {
					t.Fatal("fixture body missing")
				}
				data[index] = 'X'
				if err := os.WriteFile(archive, data, 0600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(data)
				digest = hex.EncodeToString(sum[:])
			}
			if err := build(filepath.Join(dir, "output.tar.gz"), archive, digest, dir, 1234567890); err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
}
