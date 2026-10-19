package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core/output"
)

// cmdSecret is what the command of the trust tests prints.
const cmdSecret = "Cmd-s3cr/et+v"

// TestHelperProcess is not a test: the {{$cmd NAME}} tests run the test
// binary as their command. It prints cmdSecret, or with "leak" fails with
// cmdSecret on stderr.
func TestHelperProcess(_ *testing.T) {
	if os.Getenv("VEGTAM_TEST_HELPER") != "1" {
		return
	}
	if os.Args[len(os.Args)-1] == "leak" {
		fmt.Fprintln(os.Stderr, "cannot read", cmdSecret)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, cmdSecret)
	os.Exit(0)
}

func TestTrust(t *testing.T) {
	fx := newFixture(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VEGTAM_TEST_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0") // a helper built with -race would wait a second
	helper := []string{os.Args[0], "-test.run=^TestHelperProcess$"}
	cmds, _ := json.Marshal(map[string]any{
		"KEY":  map[string]any{"argv": helper},
		"LEAK": map[string]any{"argv": append(helper, "--", "leak")},
	})
	files := map[string]string{
		"cmd/http-client.cmd.json": string(cmds),
		"cmd/key.http": "# @name echo\nPOST {{host}}/echo?key={{$cmd KEY}}\nAuthorization: Bearer {{$cmd KEY}}\n\n" +
			"###\n# @name leak\nGET {{host}}/echo?key={{$cmd KEY}}&other={{$cmd LEAK}}\n",
	}
	if err := os.Mkdir(fx.path("cmd"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, src := range files {
		if err := os.WriteFile(fx.path(name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(fx.dir)
	run := func(tty bool, args ...string) (int, string, string) {
		t.Helper()
		code, stdout, stderr := runCLI(t, tty, args...)
		if !tty {
			validateJSON(t, stdout)
		}
		forms := []string{cmdSecret, url.QueryEscape(cmdSecret), strings.ReplaceAll(cmdSecret, "/", `\/`), cmdSecret[:4]}
		for _, f := range forms {
			if strings.Contains(stdout+stderr, f) {
				t.Errorf("%q: %q in the output\n%s\n%s", args, f, stdout, stderr)
			}
		}
		return code, normalize(fx, stdout), normalize(fx, stderr)
	}
	file := "DIR/cmd/http-client.cmd.json"

	// Not trusted yet: exit 6 with the command that trusts, and no command
	// runs, not even for a dry run or show.
	for _, args := range [][]string{
		{"run", "cmd/key.http#echo", "-e", "test"},
		{"run", "cmd", "-e", "test", "--dry-run"},
		{"show", "cmd/key.http#echo", "-e", "test"},
	} {
		code, stdout, stderr := run(false, args...)
		want := file + " is not trusted to run commands; read it, then trust it with: vegtam trust DIR/cmd\n"
		if code != exitPolicy || !strings.HasSuffix(stderr, want) || !strings.Contains(stdout, `"kind":"policy"`) {
			t.Errorf("%q untrusted = %d\n%s\n%s", args, code, stdout, stderr)
		}
	}

	// Trusting shows what now runs.
	code, stdout, _ := run(true, "trust", "cmd")
	want := "Trusted " + file + ". {{$cmd NAME}} now runs:\n  KEY   " + os.Args[0] + " '-test.run=^TestHelperProcess$'\n" +
		"  LEAK  " + os.Args[0] + " '-test.run=^TestHelperProcess$' -- leak\n"
	if code != exitOK || stdout != want {
		t.Errorf("trust = %d\n%s\nwant\n%s", code, stdout, want)
	}

	// The value goes on the wire and is masked in the response.
	code, stdout, _ = run(true, "run", "cmd/key.http#echo", "-e", "test")
	if code != exitOK || !strings.Contains(stdout, `"authorization": "Bearer ***"`) || !strings.Contains(stdout, `"key": "***"`) {
		t.Errorf("run trusted = %d\n%s", code, stdout)
	}
	code, stdout, _ = run(false, "run", "cmd/key.http#echo", "-e", "test", "--dry-run")
	if code != exitOK || !strings.Contains(stdout, `"url":"HOST/echo?key={{$cmd KEY}}"`) {
		t.Errorf("dry run trusted = %d\n%s", code, stdout)
	}
	// A command that fails with a value on stderr has it masked.
	code, _, stderr := run(true, "run", "cmd/key.http#leak", "-e", "test")
	if code != exitUsage || !strings.Contains(stderr, "exit status 1: cannot read ***") {
		t.Errorf("run with a failing command = %d, %s", code, stderr)
	}
	fx.mu.Lock()
	seen := strings.Join(fx.seen, "\n")
	fx.mu.Unlock()
	if !strings.Contains(seen, "key="+cmdSecret) {
		t.Errorf("the server never saw the value: %q", seen)
	}

	list := func() []*output.Trusted {
		t.Helper()
		c, out, _ := run(false, "trust", "--list")
		var doc output.Document
		decode(t, out, &doc)
		if c != exitOK || doc.Trust == nil {
			t.Errorf("trust --list = %d\n%s", c, out)
		}
		return doc.Trust
	}
	if l := list(); len(l) != 1 || l[0].Status != "trusted" || len(l[0].SHA256) != 64 {
		t.Errorf("list: %+v", l)
	}

	// A change takes the trust away until the file is trusted again.
	if err := os.WriteFile(fx.path("cmd/http-client.cmd.json"), []byte(`{"KEY": {"argv": ["sh", "-c", "env"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if l := list(); len(l) != 1 || l[0].Status != "changed" {
		t.Errorf("list after a change: %+v", l)
	}
	code, _, stderr = run(true, "run", "cmd/key.http#echo", "-e", "test")
	if code != exitPolicy || !strings.Contains(stderr, file+" has changed since it was trusted") {
		t.Errorf("run changed = %d, %s", code, stderr)
	}

	// Revoking, twice.
	code, stdout, _ = run(true, "trust", "--revoke", "cmd")
	if code != exitOK || stdout != "Revoked the trust in "+file+": its commands no longer run.\n" {
		t.Errorf("revoke = %d, %q", code, stdout)
	}
	code, stdout, _ = run(false, "trust", "--revoke", "cmd/http-client.cmd.json")
	if code != exitOK || stdout != `{"schema_version":1,"trust":[{"file":"`+file+`","status":"untrusted"}]}`+"\n" {
		t.Errorf("revoke again = %d, %q", code, stdout)
	}
	if l := list(); len(l) != 0 {
		t.Errorf("list after revoking: %+v", l)
	}
	if c, out, _ := run(true, "trust", "--list"); c != exitOK || out != "No command file is trusted.\n" {
		t.Errorf("empty list = %d, %q", c, out)
	}

	for _, args := range [][]string{
		{"trust"},
		{"trust", "--list", "cmd"},
		{"trust", "--list", "--revoke", "cmd"},
		{"trust", "none"},
		{"trust", "api.http"},
	} {
		if c, _, _ := run(false, args...); c != exitUsage {
			t.Errorf("%q = %d, want %d", args, c, exitUsage)
		}
	}

	// The trust in a directory since deleted can be revoked.
	if c, _, _ := run(false, "trust", "cmd"); c != exitOK {
		t.Fatal("trust again")
	}
	os.RemoveAll(fx.path("cmd"))
	if l := list(); len(l) != 1 || l[0].Status != "missing" {
		t.Errorf("list after deleting: %+v", l)
	}
	code, stdout, _ = run(false, "trust", "--revoke", "cmd")
	if code != exitOK || !strings.Contains(stdout, `"status":"revoked"`) || len(list()) != 0 {
		t.Errorf("revoke a deleted directory = %d, %s", code, stdout)
	}

	// Without a place for the store, nothing is trusted, and trust says
	// what to set.
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if code, _, stderr := run(true, "trust", "--list"); code != exitPolicy || !strings.Contains(stderr, "set XDG_CONFIG_HOME or HOME") {
		t.Errorf("trust without HOME = %d, %s", code, stderr)
	}
}
