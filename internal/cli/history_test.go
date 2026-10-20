package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core/history"
)

// TestMain keeps the tests out of the history of whoever runs them: a
// test of the history turns it on, in a directory of its own.
func TestMain(m *testing.M) {
	if err := os.Setenv("VEGTAM_NO_HISTORY", "1"); err != nil {
		panic(err)
	}
	m.Run()
}

// historyOn turns the history on for the test, in a directory of its own,
// and returns the files it keeps.
func historyOn(t *testing.T) (file string) {
	t.Helper()
	t.Setenv("VEGTAM_NO_HISTORY", "")
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	return filepath.Join(data, "vegtam", history.FileName)
}

// TestHistoryNoSecrets runs every kind of outcome, with secrets in the
// URL, the headers and the body, and values captured as secrets, and
// checks that the history file holds none of them in any form, while it
// holds each run.
func TestHistoryNoSecrets(t *testing.T) {
	file := historyOn(t)
	fx := newFixture(t)
	quiet := "# @name quiet\n# @no-log\nGET {{host}}/echo?quiet=1&key={{token}}\n"
	if err := os.WriteFile(fx.path("quiet.http"), []byte(quiet), 0o600); err != nil {
		t.Fatal(err)
	}
	api := fx.path("api.http")
	runs := [][]string{
		{"run", api + "#echo"},
		{"run", api + "#fail", "--fail"},
		{"run", api + "#refused"},
		{"run", api + "#slow", "--max-time", "100ms"},
		{"run", api + "#binary", "--json"},
		{"run", api + "#big", "--max-body", "106"},
		{"run", api + "#hidden"},
		{"run", api + "#hops"},
		{"run", fx.path("quiet.http") + "#quiet"},
		{"run", fx.dir, "--max-time", "100ms", "--max-body", "106"},
	}
	for _, args := range runs {
		if _, _, stderr := runCLI(t, true, append(args, "-e", "test", "--confirm")...); strings.Contains(stderr, "history") {
			t.Fatalf("%q: %s", args, stderr)
		}
	}
	flow, _ := newFlowFixture(t)
	t.Chdir(flow)
	if code, _, stderr := runCLI(t, true, "run", "login.http", "-e", "test", "--confirm"); code != exitOK {
		t.Fatalf("the flow: exit code %d\n%s", code, stderr)
	}

	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if found := append(fx.leaks(text), flowLeaks(text)...); len(found) > 0 {
		t.Errorf("secret forms %q in the history:\n%s", found, text)
	}
	if strings.Contains(text, "quiet") {
		t.Errorf("a request with @no-log is in the history:\n%s", text)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	// 8 requests one by one, 9 in the directory (8 in api.http, 1 in more/)
	// and 3 in the flow.
	if want := 8 + 9 + 3; len(lines) != want {
		t.Errorf("%d entries, want %d:\n%s", len(lines), want, text)
	}
	var first history.Entry
	if err = json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	want := history.Entry{
		Time: first.Time, Ref: api + "#echo", Env: "test", Method: "POST", URL: "{{host}}/echo?key={{token}}&env={{$env VEGTAM_TEST_KEY}}",
		Status: 200, DurationMS: first.DurationMS, Result: "ok",
	}
	if first != want {
		t.Errorf("first entry:\n%+v\nwant\n%+v", first, want)
	}
	for _, kind := range []string{`"result":"status"`, `"result":"network"`, `"result":"timeout"`, `"truncated":true`, "?key={{token}}&env="} {
		if !strings.Contains(text, kind) {
			t.Errorf("no entry with %s:\n%s", kind, text)
		}
	}
}

// TestRunNoHistory checks the ways to keep runs out of the history: the
// flag, the variable and a dry run.
func TestRunNoHistory(t *testing.T) {
	file := historyOn(t)
	fx := newFixture(t)
	echo := fx.path("api.http") + "#echo"
	runCLI(t, true, "run", echo, "-e", "test", "--no-history", "--confirm")
	runCLI(t, true, "run", echo, "-e", "test", "--dry-run")
	t.Setenv("VEGTAM_NO_HISTORY", "1")
	runCLI(t, true, "run", echo, "-e", "test", "--confirm")
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("history file: %v", err)
	}

	// A history that cannot be kept is a warning, not an error.
	t.Setenv("VEGTAM_NO_HISTORY", "")
	if err := os.WriteFile(filepath.Dir(file), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, true, "run", fx.path("api.http"), "-e", "test", "--max-time", "100ms", "--confirm")
	if code != exitNetwork || strings.Count(stderr, "vegtam: history: ") != 1 || !strings.Contains(stderr, "VEGTAM_NO_HISTORY=1 turns it off") {
		t.Errorf("exit code %d\n%s", code, stderr)
	}
}
