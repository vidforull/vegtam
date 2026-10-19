package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, r, w)
	if isTerminal(w) {
		t.Error("isTerminal(pipe) = true, want false")
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, f)
	if isTerminal(f) {
		t.Error("isTerminal(regular file) = true, want false")
	}
}

// closeAtEnd closes files when the test ends.
func closeAtEnd(t *testing.T, files ...*os.File) {
	t.Helper()
	t.Cleanup(func() {
		for _, f := range files {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		}
	})
}
