//go:build unix

package history

import (
	"syscall"
	"testing"
	"time"
)

// TestNotRegular checks that a history file that is a FIFO is an error
// at once: opening it would wait for the other end.
func TestNotRegular(t *testing.T) {
	l := newLog(t)
	if err := syscall.Mkfifo(l.Path(), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() { done <- l.Add(entry(1)) }()
	go func() {
		_, err := l.Last(1)
		done <- err
	}()
	for range 2 {
		select {
		case err := <-done:
			if err == nil {
				t.Error("no error for a FIFO")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("waiting on a FIFO")
		}
	}
}
