//go:build unix

package env

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/httpfile"
)

// TestPrepareBodyFileFIFO checks that a body file that is a named pipe,
// or a link to one, is an error at once: opening it would wait for
// whoever writes it, and a preview would hang.
func TestPrepareBodyFileFIFO(t *testing.T) {
	path := tree(t, "")
	dir := filepath.Dir(path)
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("fifo", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"fifo", "link"} {
		if err := os.WriteFile(path, []byte("POST https://example.com\n\n< "+file), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := httpfile.ParseFile(path)
		if err != nil {
			t.Fatal(err)
		}
		v, err := NewLoader(Options{DryRun: true}).For(path)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, perr := v.Prepare(t.Context(), f.Requests[0])
			done <- perr
		}()
		select {
		case err := <-done:
			if !isKind(err, core.KindRequest) || !strings.HasSuffix(err.Error(), file+" is a named pipe: a body file must be a regular file") {
				t.Errorf("< %s: %v", file, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("< %s: waiting for the pipe", file)
		}
	}
}
