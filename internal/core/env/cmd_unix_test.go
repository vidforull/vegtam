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

// TestCommandProgramPinned checks that a command whose program PATH finds
// runs the program found when its command was first checked, and that the
// keeper's person is shown its path: one put earlier in PATH after that,
// while the question waits, does not run in its place.
func TestCommandProgramPinned(t *testing.T) {
	dirs := [2]string{t.TempDir(), t.TempDir()}
	for i, dir := range dirs {
		script := "#!/bin/sh\necho program" + strconv.Itoa(i) + "\n"
		if err := os.WriteFile(filepath.Join(dir, "vegtam-pinned"), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dirs[0]+string(os.PathListSeparator)+os.Getenv("PATH"))
	path, store := cmdTree(t, map[string]any{"P": map[string]any{"argv": []string{"vegtam-pinned"}}}, true, "GET https://example.com/?p={{$cmd P}}")
	l := NewLoader(Options{Trust: store, Held: true})
	v, err := l.For(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := prepare(t, l, path)
	if err != nil {
		t.Fatal(err)
	}
	cmds, err := v.Commands(t.Context(), p, false)
	if want := filepath.Join(dirs[0], "vegtam-pinned"); err != nil || len(cmds) != 1 || cmds[0].Path != want {
		t.Fatalf("checked: %+v, %v; want the path %s", cmds, err, want)
	}
	t.Setenv("PATH", dirs[1]+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err = v.Commands(t.Context(), p, true); err != nil {
		t.Fatal(err)
	}
	if got, err := v.commandValue("P"); err != nil || got != "program0" {
		t.Errorf("ran %q, %v; want what program0 prints", got, err)
	}
}
