package keeper

import (
	"bytes"
	"os"
	"testing"
)

func TestMultiplexer(t *testing.T) {
	for _, tc := range []struct {
		tmux, sty, program string
		want               string
	}{
		{"/tmp/tmux-501/default,4242,0", "", "", "tmux"},
		{"", "4242.pts-0.host", "", "screen"},
		{"", "", "tmux", "tmux"},
	} {
		t.Setenv("TMUX", tc.tmux)
		t.Setenv("STY", tc.sty)
		t.Setenv("TERM_PROGRAM", tc.program)
		if name, ok := Multiplexer(); !ok || name != tc.want {
			t.Errorf("%+v: %q, %v; want %q", tc, name, ok, tc.want)
		}
	}
	// None in the environment: the parent process says.
	t.Setenv("TMUX", "")
	t.Setenv("STY", "")
	t.Setenv("TERM_PROGRAM", "iTerm.app")
	want := multiplexer(procName(os.Getppid()))
	if name, ok := Multiplexer(); name != want || ok != (want != "") {
		t.Errorf("%q, %v; want %q", name, ok, want)
	}
}

func TestMultiplexerName(t *testing.T) {
	for name, want := range map[string]string{
		"tmux: server": "tmux",
		"tmux":         "tmux",
		"screen":       "screen",
		"SCREEN":       "screen",
		"script":       "script",
		"bash":         "",
		"go":           "",
		"":             "",
	} {
		if got := multiplexer(name); got != want {
			t.Errorf("multiplexer(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestUnlock(t *testing.T) {
	b := []byte("s3cr3t-value")
	if err := Lock(b); err != nil {
		t.Logf("Lock: %v", err) // best effort: see TestLock
	}
	if err := Unlock(b); err != nil {
		t.Logf("Unlock: %v", err)
	}
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Errorf("Unlock left %q", b)
	}
	Wipe(nil)
}
