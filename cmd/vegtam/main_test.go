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
	defer r.Close()
	defer w.Close()
	if isTerminal(w) {
		t.Error("isTerminal(pipe) = true, want false")
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("isTerminal(regular file) = true, want false")
	}
}
