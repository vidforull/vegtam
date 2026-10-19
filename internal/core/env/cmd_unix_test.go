//go:build unix && !aix && !solaris

package env

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// leadsGroup reports whether the process leads its process group, as the
// first process of a session of its own does.
func leadsGroup() bool { return syscall.Getpgrp() == os.Getpid() }

// TestCommandKilledWithChildren checks that a command that runs out of
// time is killed with the processes it started: in a session of its own,
// they would not get the terminal's Ctrl-C either.
func TestCommandKilledWithChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	cmds := map[string]any{"F": map[string]any{"argv": helper("family", pidFile), "timeout": "2s"}}
	path, store := cmdTree(t, cmds, true, "GET https://example.com/{{$cmd F}}")
	if _, err := prepare(t, NewLoader(Options{Trust: store}), path); err == nil || !strings.Contains(err.Error(), "did not finish within 2s") {
		t.Fatalf("error = %v", err)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(b))
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); syscall.Kill(pid, 0) == nil; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the child %d of the command outlived it", pid)
		}
	}
}
