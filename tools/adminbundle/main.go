// adminbundle prepares the fixed Linux administrator installation tree. It never
// installs files or extracts upstream paths onto the host filesystem.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var errRejected = errors.New("administrator bundle input rejected")

const prefix = "usr/lib/portico-admin/"

func main() {
	if len(os.Args) != 6 {
		panic("usage: adminbundle output pinned-electron-zip sha256 app-directory source-epoch")
	}
	epoch, err := strconv.ParseInt(os.Args[5], 10, 64)
	if err != nil || epoch < 1 {
		panic(errRejected)
	}
	if err := build(os.Args[1], os.Args[2], os.Args[3], os.Args[4], epoch); err != nil {
		panic(err)
	}
}

type member struct {
	name string
	mode int64
	size int64
	open func() (io.ReadCloser, error)
}

func runtimeMembers(archive *zip.Reader) ([]member, error) {
	if len(archive.File) == 0 || len(archive.File) > 256 {
		return nil, errRejected
	}
	seen := make(map[string]bool)
	files := make(map[string]bool)
	var members []member
	var total uint64
	for _, file := range archive.File {
		name := strings.TrimSuffix(file.Name, "/")
		if name == "" || len(name) > 240 || strings.ContainsAny(name, "\\:\x00\r\n") || path.IsAbs(name) || path.Clean(name) != name || name == "." || strings.HasPrefix(name, "../") || seen[name] || len(strings.Split(name, "/")) > 4 {
			return nil, errRejected
		}
		seen[name] = true
		if file.FileInfo().IsDir() {
			if file.UncompressedSize64 != 0 {
				return nil, errRejected
			}
			continue
		}
		if !file.Mode().IsRegular() || file.Mode()&os.ModeType != 0 || file.UncompressedSize64 > 512*1024*1024 {
			return nil, errRejected
		}
		total += file.UncompressedSize64
		if total > 768*1024*1024 {
			return nil, errRejected
		}
		files[name] = true
		mode := int64(0644)
		if name == "electron" || name == "chrome_crashpad_handler" {
			mode = 0755
		}
		if name == "chrome-sandbox" {
			mode = 04755
		}
		members = append(members, member{prefix + "electron/" + name, mode, int64(file.UncompressedSize64), file.Open})
	}
	for name := range seen {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if files[parent] {
				return nil, errRejected
			}
		}
	}
	for _, required := range []string{"electron", "chrome-sandbox", "chrome_crashpad_handler", "LICENSE", "LICENSES.chromium.html", "version"} {
		if !files[required] {
			return nil, errRejected
		}
	}
	return members, nil
}

func build(output, archivePath, expected, app string, epoch int64) (result error) {
	if len(expected) != 64 || strings.ToLower(expected) != expected {
		return errRejected
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return errRejected
	}
	input, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer input.Close()
	hash := sha256.New()
	_, copyErr := io.Copy(hash, io.LimitReader(input, 256*1024*1024+1))
	info, statErr := input.Stat()
	if copyErr != nil || statErr != nil || !info.Mode().IsRegular() || info.Size() > 256*1024*1024 || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errRejected
	}
	archive, err := zip.NewReader(input, info.Size())
	if err != nil {
		return err
	}
	members, err := runtimeMembers(archive)
	if err != nil {
		return err
	}
	for _, name := range []string{"main.cjs", "channel.cjs", "shell.cjs"} {
		data, err := os.ReadFile(filepath.Join(app, name))
		if err != nil || len(data) == 0 || len(data) > 64*1024 {
			return errRejected
		}
		members = append(members, member{prefix + "app/" + name, 0644, int64(len(data)), func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(data))), nil }})
	}
	directories := map[string]bool{strings.TrimSuffix(prefix, "/"): true}
	for _, file := range members {
		for parent := path.Dir(file.name); strings.HasPrefix(parent+"/", prefix); parent = path.Dir(parent) {
			directories[parent] = true
		}
	}
	for name := range directories {
		members = append(members, member{name + "/", 0755, 0, nil})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
	if len(members) > 512 {
		return errRejected
	}
	file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); result == nil {
			result = err
		}
	}()
	z := gzip.NewWriter(file)
	w := tar.NewWriter(z)
	for _, item := range members {
		kind := byte(tar.TypeReg)
		if item.open == nil {
			kind = tar.TypeDir
		}
		header := &tar.Header{Name: item.name, Mode: item.mode, Size: item.size, Typeflag: kind, Uid: 0, Gid: 0, ModTime: time.Unix(epoch, 0).UTC(), Format: tar.FormatUSTAR}
		if err := w.WriteHeader(header); err != nil {
			return err
		}
		if item.open != nil {
			reader, err := item.open()
			if err != nil {
				return err
			}
			n, copyErr := io.Copy(w, io.LimitReader(reader, item.size+1))
			closeErr := reader.Close()
			if copyErr != nil || closeErr != nil || n != item.size {
				return errRejected
			}
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	fmt.Println("PORTICO_ADMIN_BUNDLE_PREPARED")
	return nil
}
