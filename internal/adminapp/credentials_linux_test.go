//go:build linux

package adminapp

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/testfixture"
)

func TestLinuxCredentialStateSurvivesReplacementAndRejectsConcurrentWriter(t *testing.T) {
	_, state := installedFixture(t)
	disk, err := openCredentialDisk(state)
	testfixture.Must(t, err)
	t.Cleanup(disk.Close)
	if other, err := openCredentialDisk(state); err == nil || other != nil {
		t.Fatal("second process acquired the credential directory")
	}
	initial, pending, active := []byte("initial public identity"), []byte("retained public candidate"), []byte("activated public identity")
	read, err := disk.Read()
	testfixture.Must(t, err)
	if read != nil {
		t.Fatal("new directory contains credential state")
	}
	testfixture.Must(t, disk.Commit(nil, initial))
	testfixture.Must(t, disk.Commit(initial, pending))
	disk.Close()
	reopened, err := openCredentialDisk(state)
	testfixture.Must(t, err)
	t.Cleanup(reopened.Close)
	read, err = reopened.Read()
	testfixture.Must(t, err)
	if !bytes.Equal(read, pending) {
		t.Fatal("candidate was lost across reopening")
	}
	testfixture.Must(t, reopened.Commit(pending, active))
	read, err = reopened.Read()
	testfixture.Must(t, err)
	if !bytes.Equal(read, active) {
		t.Fatal("committed current identity changed")
	}
	info, err := os.Stat(filepath.Join(state, "credentials", credentialFile))
	testfixture.Must(t, err)
	if info.Mode().Perm() != 0600 {
		t.Fatal("credential file permissions changed")
	}
}

func TestLinuxCredentialCommitFailureRequiresReopenAndPreservesPublishedState(t *testing.T) {
	for _, stage := range []string{"file-sync", "publish", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			_, state := installedFixture(t)
			disk, err := openCredentialDisk(state)
			testfixture.Must(t, err)
			t.Cleanup(disk.Close)
			old, next := []byte("old public certificate"), []byte("new public certificate")
			testfixture.Must(t, disk.Commit(nil, old))
			disk.barrier = func(name string) error {
				if name == stage {
					return errors.New("injected durability failure")
				}
				return nil
			}
			if disk.Commit(old, next) == nil {
				t.Fatal("durability failure reported success")
			}
			if _, err := disk.Read(); err == nil || disk.Commit(old, []byte("retry")) == nil {
				t.Fatal("uncertain handle allowed dependent state use or retry")
			}
			disk.Close()
			reopened, err := openCredentialDisk(state)
			testfixture.Must(t, err)
			t.Cleanup(reopened.Close)
			stored, err := reopened.Read()
			testfixture.Must(t, err)
			want := old
			if stage == "directory-sync" {
				want = next
			}
			if !bytes.Equal(stored, want) {
				t.Fatal("failed commit lost or mixed an identity record")
			}
			entries, err := os.ReadDir(filepath.Join(state, "credentials"))
			testfixture.Must(t, err)
			if len(entries) != 1 || entries[0].Name() != credentialFile {
				t.Fatal("failed commit retained an uncommitted temporary file")
			}
		})
	}
}

func TestLinuxCredentialStorageRejectsHostileEntriesAndUnexpectedReplacement(t *testing.T) {
	for _, scenario := range []string{"symlink", "hardlink", "fifo", "public-file", "directory", "oversized", "changed", "public-parent", "symlink-parent"} {
		t.Run(scenario, func(t *testing.T) {
			_, state := installedFixture(t)
			disk, err := openCredentialDisk(state)
			testfixture.Must(t, err)
			testfixture.Must(t, disk.Commit(nil, []byte("original")))
			disk.Close()
			parent := filepath.Join(state, "credentials")
			path := filepath.Join(parent, credentialFile)
			switch scenario {
			case "symlink", "hardlink":
				other := filepath.Join(parent, "retained")
				testfixture.Must(t, os.Rename(path, other))
				if scenario == "symlink" {
					err = os.Symlink(other, path)
				} else {
					err = os.Link(other, path)
				}
			case "fifo", "directory":
				testfixture.Must(t, os.Remove(path))
				if scenario == "fifo" {
					err = unix.Mkfifo(path, 0600)
				} else {
					err = os.Mkdir(path, 0700)
				}
			case "public-file":
				err = os.Chmod(path, 0640)
			case "oversized":
				err = os.WriteFile(path, bytes.Repeat([]byte("a"), maxCredentialState+1), 0600)
			case "changed":
				err = os.WriteFile(path, []byte("unexpected public identity"), 0600)
			case "public-parent":
				err = os.Chmod(parent, 0750)
			case "symlink-parent":
				testfixture.Must(t, os.Rename(parent, parent+"-retained"))
				err = os.Symlink(parent+"-retained", parent)
			}
			testfixture.Must(t, err)
			disk, err = openCredentialDisk(state)
			if scenario == "public-parent" || scenario == "symlink-parent" {
				if err == nil || disk != nil {
					t.Fatal("unsafe credential directory accepted or repaired")
				}
				return
			}
			testfixture.Must(t, err)
			t.Cleanup(disk.Close)
			if disk.Commit([]byte("original"), []byte("replacement")) == nil {
				t.Fatal("unsafe or unexpected entry was overwritten")
			}
		})
	}
}

func TestLinuxCredentialConcurrentUpdatesRetainOneCompleteRecord(t *testing.T) {
	_, state := installedFixture(t)
	disk, err := openCredentialDisk(state)
	testfixture.Must(t, err)
	t.Cleanup(disk.Close)
	old := []byte("original")
	testfixture.Must(t, disk.Commit(nil, old))
	var workers sync.WaitGroup
	results := make([]error, 2)
	values := [][]byte{[]byte("first candidate"), []byte("second candidate")}
	for i := range results {
		workers.Go(func() { results[i] = disk.Commit(old, values[i]) })
	}
	workers.Wait()
	disk.Close()
	reopened, err := openCredentialDisk(state)
	testfixture.Must(t, err)
	t.Cleanup(reopened.Close)
	stored, err := reopened.Read()
	testfixture.Must(t, err)
	winner := -1
	for i, result := range results {
		if result == nil {
			if winner != -1 {
				t.Fatal("both updates overwrote the same prior version")
			}
			winner = i
		}
	}
	if winner == -1 || !bytes.Equal(stored, values[winner]) {
		t.Fatal("stored identity is not the single committed update")
	}
}

func TestLinuxCredentialDirectoryChangesAndClosedHandleDenyWrites(t *testing.T) {
	_, state := installedFixture(t)
	disk, err := openCredentialDisk(state)
	testfixture.Must(t, err)
	testfixture.Must(t, disk.Commit(nil, []byte("original")))
	testfixture.Must(t, os.Chmod(filepath.Join(state, "credentials"), 0770))
	if disk.Commit([]byte("original"), []byte("replacement")) == nil {
		t.Fatal("directory lost its private boundary without closing storage")
	}
	disk.Close()
	if _, err := disk.Read(); err == nil || disk.Commit([]byte("original"), []byte("replacement")) == nil {
		t.Fatal("closed credential handle retained filesystem access")
	}
	stored, err := os.ReadFile(filepath.Join(state, "credentials", credentialFile))
	testfixture.Must(t, err)
	if string(stored) != "original" {
		t.Fatal("directory or handle failure changed the original record")
	}
}
