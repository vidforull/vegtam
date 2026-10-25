//go:build unix

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestNamedPipe checks that a named pipe in place of the policy or of the
// trust store is refused, rather than opened: the open would wait for a
// writer for ever.
func TestNamedPipe(t *testing.T) {
	dir := configDir(t)
	for _, name := range []string{PolicyFile, "trust.json"} {
		path := filepath.Join(dir, name)
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadFile(filepath.Join(dir, PolicyFile)); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("the policy: %v", err)
	}
	if _, err := NewStore(filepath.Join(dir, "trust.json")).List(); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("the trust store: %v", err)
	}
}

// TestNamedPipeSwapped checks a named pipe put in place of the policy or
// of the trust store after the check of its name: opened as they open
// their files, it does not wait for a writer, and is refused once open.
func TestNamedPipeSwapped(t *testing.T) {
	dir := configDir(t)
	path := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, read := range map[string]func(*os.File) error{
		"the policy":      func(f *os.File) error { _, _, err := readPolicy(f, path, fmt.Errorf); return err },
		"the trust store": func(f *os.File) error { _, err := NewStore(path).read(f, fmt.Errorf); return err },
	} {
		f, err := openFile(root, "pipe")
		if err != nil {
			t.Fatal(err)
		}
		if err := read(f); err == nil || err.Error() != "not a regular file" {
			t.Errorf("%s: %v", name, err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
