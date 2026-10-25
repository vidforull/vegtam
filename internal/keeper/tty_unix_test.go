//go:build linux || darwin

package keeper

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// The terminal's tests run where a file is polled (see waitReadable):
// elsewhere, stop cannot end the reading of a file with nothing to read.

func TestTTY(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer discard(w)
	defer discard(r)
	var out strings.Builder
	term, stop := NewTTY(r, &out)
	defer stop()
	tt, ok := term.(*tty)
	if !ok {
		t.Fatalf("a %T", term)
	}
	typeLine := func(s string) {
		t.Helper()
		if _, err := w.WriteString(s + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	// A line typed before the question is no answer to it.
	typeLine("abcd")
	waitFor(t, func() bool { return len(tt.lines) == 1 })
	if err := term.Write("question\n"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if line, err := term.ReadLine(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadLine: %q, %v; want no line", line, err)
	}
	typeLine("efgh\r")
	if line, err := term.ReadLine(t.Context()); err != nil || line != "efgh" {
		t.Fatalf("ReadLine: %q, %v", line, err)
	}
	// A long line is cut.
	typeLine(strings.Repeat("x", 3*maxAnswer))
	if line, err := term.ReadLine(t.Context()); err != nil || line != strings.Repeat("x", maxAnswer) {
		t.Fatalf("ReadLine: %d bytes, %v", len(line), err)
	}
	if out.String() != "question\n" {
		t.Errorf("output %q", out.String())
	}
	discard(w)
	if _, err := term.ReadLine(t.Context()); !errors.Is(err, io.EOF) {
		t.Errorf("ReadLine at the end: %v", err)
	}
}

func TestTTYLateLine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer discard(w)
	defer discard(r)
	term, stop := NewTTY(r, io.Discard)
	defer stop()
	tt, ok := term.(*tty)
	if !ok {
		t.Fatalf("a %T", term)
	}
	a := &Asker{Term: term, Timeout: 20 * time.Millisecond}
	p, bs := prepared()
	if err := a.Ask(t.Context(), peer, p, bs, nil); err == nil || err.Error() != "no answer in 0.02s" {
		t.Fatalf("error %v", err)
	}
	// Typed too late for that question: no answer to the next either.
	if _, err := w.WriteString("zzzz\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(tt.lines) == 1 })
	if err := a.Ask(t.Context(), peer, p, bs, nil); err == nil || err.Error() != "no answer in 0.02s" {
		t.Fatalf("error %v", err)
	}
}

func TestTTYStop(t *testing.T) {
	// A file with nothing to read: stop ends the reading all the same, and
	// leaves the file open.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer discard(w)
	defer discard(r)
	term, stop := NewTTY(r, io.Discard)
	stop()
	stop()
	if _, err := term.ReadLine(t.Context()); !errors.Is(err, errStopped) {
		t.Errorf("ReadLine after stop: %v", err)
	}
	if _, err := w.WriteString("x\n"); err != nil {
		t.Errorf("the file was closed: %v", err)
	}
	// Any other reader is closed.
	pr, pw := io.Pipe()
	defer discard(pw)
	_, stop = NewTTY(pr, io.Discard)
	stop()
	if _, err := pw.Write([]byte("x\n")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("the reader is not closed: %v", err)
	}
}
