//go:build unix

package tui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestPreviewFIFO checks that the preview of a request whose body file
// is a named pipe says so at once, rather than wait for a writer.
func TestPreviewFIFO(t *testing.T) {
	fx := newFixture(t)
	if err := syscall.Mkfifo(filepath.Join(fx.dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := "# @name piped\nPOST {{host}}/echo\n\n< ./fifo\n"
	if err := os.WriteFile(filepath.Join(fx.dir, "piped.http"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newModel(t, fx.dir, "test", 100, 30)
	i := slices.IndexFunc(m.rows, func(r row) bool { return r.index >= 0 && r.file.Requests[r.index].Name == "piped" })
	if i < 0 {
		t.Fatal("no request piped")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.choose(i)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the preview waits for the pipe")
	}
	if text := m.requestText(); !strings.Contains(text, "fifo is a named pipe: a body file must be a regular file") {
		t.Errorf("preview:\n%s", text)
	}
}
