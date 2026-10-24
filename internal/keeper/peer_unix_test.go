//go:build linux || darwin

package keeper

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPeerOf(t *testing.T) {
	path := socketPath(t)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer discard(ln)
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer discard(c)
	s, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer discard(s)
	// Each end sees the test's process at the other.
	for _, conn := range []*net.UnixConn{s, c} {
		p, err := peerOf(conn)
		if err != nil {
			t.Fatal(err)
		}
		if p.UID != os.Geteuid() || p.PID != os.Getpid() {
			t.Errorf("peer %s, want uid %d and pid %d", p, os.Geteuid(), os.Getpid())
		}
		// The name of the test's binary, as the kernel cuts it.
		if exe := filepath.Base(os.Args[0]); p.Name == "" || !strings.HasPrefix(exe, p.Name) {
			t.Errorf("peer name %q, want the start of %q", p.Name, exe)
		}
	}
}

func TestProcessName(t *testing.T) {
	for in, want := range map[string]string{
		"agent":                  "agent",
		"node\n":                 "node?",
		"x) uid 0 (y":            "x] uid 0 [y",
		"\x1b[31mred":            "?[31mred",
		"a\u202eb\xff":           "a?b?",
		strings.Repeat("n", 100): strings.Repeat("n", maxName),
		"  ":                     "",
	} {
		if got := processName([]byte(in)); got != want {
			t.Errorf("processName(%q) = %q, want %q", in, got, want)
		}
	}
}
