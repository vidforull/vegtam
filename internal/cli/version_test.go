package cli

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// runVersion runs vegtam version with the version, commit and date of a
// build.
func runVersion(t *testing.T, tty bool, version, commit, date string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	cfg := Config{Stdout: &out, Stderr: &errOut, TTY: tty, Version: version, Commit: commit, Date: date}
	code = Run(t.Context(), []string{"version"}, cfg)
	return code, out.String(), errOut.String()
}

// TestVersionStamped checks what a build that recorded its commit and
// date prints, and that a value it did not record is left out, in text
// and in JSON. TestVersion checks a build that recorded neither.
func TestVersionStamped(t *testing.T) {
	const (
		rev  = "6c213c9b45cd9fe0d834d0bc8b65db6881b10f4e"
		when = "2026-10-20T10:22:32Z"
	)
	goos := runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH
	tail := `"go":"` + runtime.Version() + `","os":"` + runtime.GOOS + `","arch":"` + runtime.GOARCH + `"}` + "\n"
	tests := []struct {
		name                  string
		version, commit, date string
		text, json            string
	}{
		{
			"commit and date", "0.1.0", rev, when,
			"vegtam 0.1.0 (commit 6c213c9b45cd, " + when + ", " + goos + ")\n",
			`{"name":"vegtam","version":"0.1.0","commit":"` + rev + `","date":"` + when + `",` + tail,
		},
		{
			"files with changes", "v0.0.0-20261020102232-6c213c9b45cd+dirty", rev + "+dirty", when,
			"vegtam v0.0.0-20261020102232-6c213c9b45cd+dirty (commit 6c213c9b45cd+dirty, " + when + ", " + goos + ")\n",
			`{"name":"vegtam","version":"v0.0.0-20261020102232-6c213c9b45cd+dirty","commit":"` + rev + `+dirty","date":"` + when + `",` + tail,
		},
		{
			"commit alone", "dev", rev, "",
			"vegtam dev (commit 6c213c9b45cd, " + goos + ")\n",
			`{"name":"vegtam","version":"dev","commit":"` + rev + `",` + tail,
		},
		{
			"date alone", "v0.1.0", "", when,
			"vegtam v0.1.0 (" + when + ", " + goos + ")\n",
			`{"name":"vegtam","version":"v0.1.0","date":"` + when + `",` + tail,
		},
		{
			"neither", "dev", "", "",
			"vegtam dev (" + goos + ")\n",
			`{"name":"vegtam","version":"dev",` + tail,
		},
		{
			"a short commit", "0.1.0", "6c213c9", "",
			"vegtam 0.1.0 (commit 6c213c9, " + goos + ")\n",
			`{"name":"vegtam","version":"0.1.0","commit":"6c213c9",` + tail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, run := range []struct {
				tty  bool
				want string
			}{
				{true, tt.text},
				{false, tt.json},
			} {
				code, stdout, stderr := runVersion(t, run.tty, tt.version, tt.commit, tt.date)
				if code != exitOK || stdout != run.want || stderr != "" {
					t.Errorf("version (tty %v) = %d, %q, %q; want %d, %q, empty stderr", run.tty, code, stdout, stderr, exitOK, run.want)
				}
			}
		})
	}
}

// TestVersionIsTerminalText checks that what a build set, which -X can
// make any string, reaches a terminal as text, not as escape sequences.
func TestVersionIsTerminalText(t *testing.T) {
	code, stdout, _ := runVersion(t, true, "0.1.0\x1b]0;title\x07", "6c213c9\x1b[2J", "")
	if code != exitOK || strings.ContainsAny(stdout, "\x1b\x07") || !strings.Contains(stdout, `\x1b`) {
		t.Errorf("version = %d, %q; want the escapes shown as text", code, stdout)
	}
}

func TestShortCommit(t *testing.T) {
	for in, want := range map[string]string{
		"":             "",
		"6c213c9":      "6c213c9",
		"6c213c9b45cd": "6c213c9b45cd",
		"6c213c9b45cd9fe0d834d0bc8b65db6881b10f4e":       "6c213c9b45cd",
		"6c213c9b45cd9fe0d834d0bc8b65db6881b10f4e+dirty": "6c213c9b45cd+dirty",
		"6c213c9+dirty": "6c213c9+dirty",
	} {
		if got := shortCommit(in); got != want {
			t.Errorf("shortCommit(%q) = %q, want %q", in, got, want)
		}
	}
}
