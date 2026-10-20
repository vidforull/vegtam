//go:build unix

package policy

import (
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
