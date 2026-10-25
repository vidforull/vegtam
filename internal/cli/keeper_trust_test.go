package cli

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// TestKeeperTrust is the gate of a command that a program would have the
// keeper run: it writes a command file of its own, and a request that
// sends what the command prints where the policy binds it. The program
// cannot trust the file; trusted once the keeper has started, the keeper
// still runs none of it, and says so in its terminal; trusted before, it
// asks of the request, whatever keeper_asks says, and shows the command
// whole before it runs it.
func TestKeeperTrust(t *testing.T) {
	w := newAgentWorld(t, `{"network": {"allow": ["127.0.0.1"]}, "secrets": {"unattended": "keeper", "keeper_asks": "unbound"}}`)
	k := w.k
	pol := `{"network": {"allow": ["127.0.0.1"]}, "secrets": {"unattended": "keeper", "keeper_asks": "unbound", "cmd": {"EVIL": ["` + w.a.URL + `"]}}}`
	if err := os.WriteFile(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "vegtam", policy.PolicyFile), []byte(pol), 0o600); err != nil {
		t.Fatal(err)
	}
	touched := filepath.Join(t.TempDir(), "touched")
	t.Setenv("VEGTAM_TEST_HELPER", "1")
	t.Setenv("VEGTAM_TEST_TOUCH", touched)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	for name, src := range map[string]string{
		"http-client.cmd.json": `{"EVIL": {"argv": ["` + os.Args[0] + `", "-test.run=^TestHelperProcess$", "--", "touch"]}}`,
		"cmd.http":             "GET {{a}}/cmd?k={{$cmd EVIL}}\n",
	} {
		if err := os.WriteFile(filepath.Join(w.dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file, err := policy.Canonical(filepath.Join(w.dir, "http-client.cmd.json"))
	if err != nil {
		t.Fatal(err)
	}
	agent := func() (code int, doc output.Document, stderr string) {
		t.Helper()
		code, stdout, stderr := runAgent(t, "run", filepath.Join(w.dir, "cmd.http"), "-e", "test")
		validateJSON(t, stdout)
		decode(t, stdout, &doc)
		if strings.Contains(stdout+stderr, cmdSecret) {
			t.Errorf("the agent sees what the command printed:\n%s\n%s", stdout, stderr)
		}
		return code, doc, stderr
	}
	ran := func() bool {
		t.Helper()
		_, err := os.Stat(touched)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		return err == nil
	}

	// The program cannot trust it.
	if code, _, stderr := runAgent(t, "trust", w.dir); code != exitPolicy || !strings.Contains(stderr, "is for a person at a terminal") {
		t.Errorf("the agent's trust = %d, %s", code, stderr)
	}
	if code, stdout, _ := runAgent(t, "trust", "--list"); code != exitOK || strings.Contains(stdout, file) {
		t.Errorf("trusted by the agent: %d, %s", code, stdout)
	}

	// Trusted after the keeper started, as a program with a terminal of
	// its own could, or with trust.json written: the keeper runs nothing.
	from := len(k.screen.String())
	if code, _, stderr := runAt(t, "trust", w.dir); code != exitOK {
		t.Fatalf("trust = %d, %s", code, stderr)
	}
	code, doc, stderr := agent()
	since := file + " was trusted after the keeper started, which reads the trust store once: start the keeper again"
	if e := doc.Results[0].Error; code != exitPolicy || e == nil || e.Kind != core.KindPolicy || !strings.Contains(e.Message, since) {
		t.Errorf("trusted after the keeper started = %d, %+v\n%s", code, e, stderr)
	}
	if ran() {
		t.Error("the keeper ran a command trusted after it started")
	}
	changed := regexp.MustCompile(`the trust store changed: ` + regexp.QuoteMeta(file) + ` trusted\. A trust taken back applies now; one given, once the keeper starts again\.`)
	if k.screen.await(from, changed) == nil {
		t.Errorf("the keeper did not say the trust store changed:\n%s", k.screen.String()[from:])
	}
	if strings.Contains(k.screen.String()[from:], "a request asked by") {
		t.Errorf("the keeper asked of a command it does not run:\n%s", k.screen.String()[from:])
	}

	// Trusted before it started: it says so when it starts, and asks,
	// though the secret is bound and keeper_asks is "unbound", and shows
	// the command.
	k.shut(t)
	k = startKeeper(t, "pw")
	if want := "the commands it may run, once you type a code, are those of 1 command file trusted now: " + file + ".\n"; !strings.Contains(k.screen.String(), want) {
		t.Errorf("the keeper does not say which files it trusts:\n%s", k.screen.String())
	}
	from = len(k.screen.String())
	asked := make(chan string, 1)
	go func() { asked <- k.answer(from, "") }()
	code, doc, stderr = agent()
	q := <-asked
	if r := doc.Results[0]; code != exitOK || r.Error != nil || r.Response == nil || r.Response.Status != 200 {
		t.Errorf("trusted before the keeper started = %d, %+v\n%s", code, r.Error, stderr)
	}
	for _, want := range []string{
		"  secret {{$cmd EVIL}}, in the URL, goes to " + w.a.URL + ": bound to it\n",
		"  command EVIL: " + core.ShellQuote(os.Args[0]) + " '-test.run=^TestHelperProcess$' -- touch\n",
		"  from " + file + ": it runs here, as you, once you type the code\n",
	} {
		if !strings.Contains(q, want) {
			t.Errorf("the question does not say %q:\n%s", want, q)
		}
	}
	if !ran() {
		t.Error("the command did not run once its person said yes")
	}

	// A trust taken back applies at once, in the run as in the keeper (see
	// TestKeeperAsksForCommands): no question, nothing runs.
	if err := os.Remove(touched); err != nil {
		t.Fatal(err)
	}
	if c, stdout, errs := runAt(t, "trust", "--revoke", w.dir); c != exitOK || !strings.HasPrefix(stdout, "Revoked the trust in ") {
		t.Fatalf("revoke = %d, %s%s", c, stdout, errs)
	}
	from = len(k.screen.String())
	code, doc, stderr = agent()
	if e := doc.Results[0].Error; code != exitPolicy || e == nil || !strings.Contains(e.Message, file+" is not trusted to run commands") {
		t.Errorf("revoked while the keeper runs = %d, %+v\n%s", code, e, stderr)
	}
	if ran() || strings.Contains(k.screen.String()[from:], "a request asked by") {
		t.Errorf("the keeper asked of, or ran, a command no longer trusted:\n%s", k.screen.String()[from:])
	}

	// A store that others can write trusts nothing: the keeper says so,
	// and runs nothing.
	k.shut(t)
	if c, _, errs := runAt(t, "trust", w.dir); c != exitOK {
		t.Fatalf("trust = %d, %s", c, errs)
	}
	store := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "vegtam", "trust.json")
	if err := os.Chmod(store, 0o620); err != nil {
		t.Fatal(err)
	}
	k = startKeeper(t, "pw")
	if want := "others can write it, so it trusts nothing; make it private: chmod 600 " + store + "; the keeper runs no {{$cmd NAME}}\n"; !strings.Contains(k.screen.String(), want) {
		t.Errorf("the keeper does not warn of the store:\n%s", k.screen.String())
	}
	if code, doc, _ = agent(); code != exitPolicy || ran() {
		t.Errorf("with a store others can write = %d, %+v", code, doc.Results[0].Error)
	}
}
