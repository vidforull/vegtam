package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
)

// TestDescribe checks the document of vegtam describe: what it says of
// the commands, the exit codes, the errors, the mode and the policy, and
// that it agrees with the rest of vegtam.
func TestDescribe(t *testing.T) {
	newFixture(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("VEGTAM_NO_HISTORY", "")
	code, stdout, stderr := runCLI(t, false, "describe")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	d := doc.Describe
	if code != exitOK || stderr != "" || d == nil || d.Name != "vegtam" || d.Version != "v1.2.3" || d.Schema != "vegtam schema" {
		t.Fatalf("describe = %d\n%s\n%s", code, stdout, stderr)
	}
	// The fixture's policy sends the secrets of such a run through the keeper.
	if d.Mode != (output.DescribeMode{Unattended: true, Why: "stdin or stdout is not a terminal", Secrets: output.RunSecretsKeeper}) {
		t.Errorf("mode %+v", d.Mode)
	}
	var names []string
	for _, c := range d.Commands {
		names = append(names, c.Name)
	}
	want := []string{"describe", "doctor", "import", "import postman", "list", "policy", "run", "schema", "show", "trust", "tui", "version"}
	if !slices.Equal(names, want) {
		t.Errorf("commands %q, want %q", names, want)
	}
	run := d.Commands[slices.Index(names, "run")]
	flag := func(name string) (output.DescribeFlag, bool) {
		i := slices.IndexFunc(run.Flags, func(f output.DescribeFlag) bool { return f.Name == name })
		if i < 0 {
			return output.DescribeFlag{}, false
		}
		return run.Flags[i], true
	}
	if f, ok := flag("--confirm"); !ok || f.Value != "optional" || f.Default != "" {
		t.Errorf("--confirm: %+v", f)
	}
	if f, ok := flag("--env"); !ok || f.Shorthand != "-e" || f.Value != "required" || f.Type != "string" {
		t.Errorf("--env: %+v", f)
	}
	if f, ok := flag("--max-time"); !ok || f.Default != "2m" || f.Type != "time" {
		t.Errorf("--max-time: %+v", f)
	}
	if f, ok := flag("--dry-run"); !ok || f.Value != "none" || f.Type != "" {
		t.Errorf("--dry-run: %+v", f)
	}
	if _, ok := flag("--timeout"); ok { // hidden
		t.Error("a hidden flag is listed")
	}
	if len(d.Flags) != 1 || d.Flags[0].Name != "--json" {
		t.Errorf("flags of every command: %+v", d.Flags)
	}
	if run.Usage != "vegtam run <file>[#<name>|#<N>] | <dir>" || run.Summary != "Send requests" {
		t.Errorf("run: %+v", run)
	}

	// The exit codes are the help's, and every kind of error has the code
	// that a run of that kind exits with.
	_, help, _ := runCLI(t, false, "--help")
	for _, e := range d.ExitCodes {
		if !strings.Contains(strings.Join(strings.Fields(help), " "), " "+e.Meaning) {
			t.Errorf("the help does not give %d: %s", e.Code, e.Meaning)
		}
	}
	kinds := []core.Kind{
		core.KindAssert, core.KindUsage, core.KindParse, core.KindVariable, core.KindRequest, core.KindImport, core.KindCapture,
		core.KindNetwork, core.KindTimeout, core.KindStatus, core.KindConfirm, core.KindPolicy, core.KindCanceled,
	}
	if len(d.Errors) != len(kinds) {
		t.Errorf("%d kinds of error, want %d", len(d.Errors), len(kinds))
	}
	for i, k := range kinds {
		if i < len(d.Errors) && (d.Errors[i].Kind != string(k) || d.Errors[i].ExitCode != exitCode(k) ||
			!slices.ContainsFunc(d.ExitCodes, func(e output.DescribeExit) bool { return e.Code == exitCode(k) })) {
			t.Errorf("errors[%d] = %+v, want %s", i, d.Errors[i], k)
		}
	}
	if c := d.Errors[slices.IndexFunc(d.Errors, func(e output.DescribeError) bool { return e.Kind == "confirm" })]; c.ExitCode != 5 {
		t.Errorf("confirm: %+v", c)
	}

	// The policy as vegtam policy prints it, for this mode.
	_, policyOut, _ := runCLI(t, false, "policy")
	var p output.Document
	decode(t, policyOut, &p)
	if d.Policy == nil || d.PolicyError != nil || !d.Policy.Run.Unattended || !d.Policy.Run.ConfirmMutations ||
		!slices.Equal(d.Policy.Network.Allow, p.Policy.Network.Allow) || len(d.Never) == 0 {
		t.Errorf("policy %+v, error %+v", d.Policy, d.PolicyError)
	}
	if !d.History.On || !strings.HasSuffix(d.History.Path, filepath.Join("vegtam", "history.jsonl")) {
		t.Errorf("history %+v", d.History)
	}
	t.Setenv("VEGTAM_NO_HISTORY", "1")
	_, stdout, _ = runCLI(t, false, "describe")
	doc = output.Document{}
	decode(t, stdout, &doc)
	if h := doc.Describe.History; h.On || h.Path != "" || h.Why != "VEGTAM_NO_HISTORY is set" {
		t.Errorf("history off: %+v", h)
	}

	// A person at a terminal; and --json there.
	for _, tt := range []struct {
		args []string
		mode output.DescribeMode
	}{
		{[]string{"describe", "--json"}, output.DescribeMode{Unattended: true, Why: "--json is given", Secrets: output.RunSecretsKeeper}},
		{[]string{"describe"}, output.DescribeMode{Why: "stdin and stdout are terminals", Secrets: output.RunSecretsAll}},
	} {
		code, stdout, _ := runAt(t, tt.args...)
		if tt.args[len(tt.args)-1] != "--json" {
			if code != exitOK || !strings.Contains(stdout, "Mode: a person is at a terminal (stdin and stdout are terminals).\nSecrets: each to the origins it is bound to.\n") {
				t.Errorf("as text:\n%s", stdout)
			}
			continue
		}
		validateJSON(t, stdout)
		doc = output.Document{}
		decode(t, stdout, &doc)
		if code != exitOK || doc.Describe.Mode != tt.mode {
			t.Errorf("%q = %d, mode %+v", tt.args, code, doc.Describe.Mode)
		}
	}
}

// TestDescribeSecretOrigins checks what describe says of secrets that
// would go to an origin they are not bound to: that vegtam never sends
// them, what binds them, and the kinds of error and exit codes they give,
// in JSON and as text.
func TestDescribeSecretOrigins(t *testing.T) {
	writePolicy(t, `{}`)
	_, stdout, _ := runCLI(t, false, "describe")
	var doc output.Document
	decode(t, stdout, &doc)
	d := doc.Describe
	const item = "send a secret value to an origin it is not bound to: "
	i := slices.IndexFunc(d.Never, func(n string) bool { return strings.HasPrefix(n, item) })
	if i < 0 {
		t.Fatalf("never says nothing of secret origins: %q", d.Never)
	}
	for _, want := range []string{
		"the $allow of http-client.private.env.json binds the file's own values",
		"the operator's policy (secrets) alone binds {{$env NAME}} and {{$cmd NAME}}", "a captured value goes back only to",
		"bound to none goes nowhere", "a person at a terminal may confirm", "without a person --confirm does not lift it",
	} {
		if !strings.Contains(d.Never[i], want) {
			t.Errorf("never[%d] does not say %q: %s", i, want, d.Never[i])
		}
	}
	meaning := func(kind core.Kind) string {
		j := slices.IndexFunc(d.Errors, func(e output.DescribeError) bool { return e.Kind == string(kind) })
		if j < 0 {
			t.Fatalf("no error of kind %s", kind)
		}
		return d.Errors[j].Meaning
	}
	if m := meaning(core.KindPolicy); !strings.Contains(m, "a secret that would go to an origin it is not bound to") ||
		!strings.Contains(m, "--confirm does not lift it") {
		t.Errorf("policy: %s", m)
	}
	if m := meaning(core.KindConfirm); !strings.Contains(m, "with a person at a terminal, one that would send a secret to an origin it is not bound to") {
		t.Errorf("confirm: %s", m)
	}
	for _, e := range d.ExitCodes {
		if (e.Code == exitConfirm || e.Code == exitPolicy) && !strings.Contains(e.Meaning, "a secret") {
			t.Errorf("exit code %d says nothing of secrets: %s", e.Code, e.Meaning)
		}
	}
	_, text, _ := runAt(t, "describe")
	if words := strings.Join(strings.Fields(text), " "); !strings.Contains(words, "- "+d.Never[i]) {
		t.Errorf("as text, never does not say:\n%s\nin:\n%s", d.Never[i], text)
	}
}

// oddDir is the name of a directory with what would drive a terminal.
const oddDir = "conf\x1b]0;t\x07"

// TestDescribeNoSecrets runs describe with a policy whose proxy has
// credentials in a variable, and a proxy of the environment with a
// password: neither shows, in text or JSON. The paths of the policy and
// of the history come from the environment, so a control character in
// them shows as an escape.
func TestDescribeNoSecrets(t *testing.T) {
	const (
		authMarker = "describe-user:Pr0xy-M4rker/pw"
		envMarker  = "Env-Pr0xy-M4rker"
	)
	t.Setenv("VEGTAM_TEST_DESCRIBE_AUTH", authMarker)
	t.Setenv("HTTPS_PROXY", "http://someone:"+envMarker+"@proxy.example:3128")
	t.Setenv("NO_PROXY", "")
	odd := filepath.Join(t.TempDir(), oddDir)
	if err := os.MkdirAll(filepath.Join(odd, "vegtam"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", odd)
	t.Setenv("XDG_DATA_HOME", odd)
	t.Setenv("VEGTAM_NO_HISTORY", "")
	for _, policy := range []string{
		`{"network": {"proxy": "http://proxy.example:3128", "proxy_auth": "$env VEGTAM_TEST_DESCRIBE_AUTH"}}`,
		`{}`,
	} {
		if err := os.WriteFile(filepath.Join(odd, "vegtam", "policy.json"), []byte(policy), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []struct {
			name        string
			tty, person bool
			json        bool
			extra       []string
		}{
			{"not a terminal", false, false, true, nil},
			{"a person", true, true, false, nil},
			{"a person, --json", true, true, true, []string{"--json"}},
		} {
			code, stdout, stderr := runAs(t, mode.tty, mode.person, append([]string{"describe"}, mode.extra...)...)
			all := stdout + stderr
			if code != exitOK {
				t.Errorf("%s, %s = %d\n%s", policy, mode.name, code, all)
			}
			for _, m := range []string{authMarker, "Pr0xy-M4rker", envMarker, "M4rker"} {
				if strings.Contains(all, m) {
					t.Errorf("%s, %s: %q in the output\n%s", policy, mode.name, m, all)
				}
			}
			if mode.json {
				validateJSON(t, stdout)
				continue
			}
			if strings.Contains(all, "\x1b") || !strings.Contains(stdout, `conf\x1b]0;t\x07/vegtam/policy.json`) ||
				!strings.Contains(stdout, `conf\x1b]0;t\x07/vegtam/history.jsonl`) {
				t.Errorf("%s, %s: as text\n%s", policy, mode.name, stdout)
			}
		}
	}
	// The person's run goes through the environment's proxy: shown, its
	// password masked.
	if _, stdout, _ := runAt(t, "describe"); !strings.Contains(stdout, "Requests to https URLs go through http://***@proxy.example:3128") {
		t.Errorf("the environment's proxy:\n%s", stdout)
	}
}

// TestDescribePolicyError checks describe with a policy file that cannot
// be read: the rest of the document, the reason in place of the policy,
// and exit code 6, as every command that reads the policy gives.
func TestDescribePolicyError(t *testing.T) {
	dir := writePolicy(t, `{"network": {"alow": []}}`)
	code, stdout, stderr := runCLI(t, false, "describe")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	d := doc.Describe
	if code != exitPolicy || d == nil || d.Policy != nil || d.PolicyError == nil || d.PolicyError.Kind != core.KindPolicy ||
		!strings.Contains(d.PolicyError.Message, `unknown field "alow"`) || len(d.Commands) == 0 ||
		!strings.Contains(stderr, `vegtam: `+filepath.Join(dir, "policy.json")+`: json: unknown field "alow"`) {
		t.Errorf("describe = %d\n%s\n%s", code, stdout, stderr)
	}
	if code, stdout, _ := runAt(t, "describe"); code != exitPolicy || !strings.Contains(stdout, `Policy:
  cannot be read: json: unknown field "alow"`) {
		t.Errorf("as text = %d\n%s", code, stdout)
	}
}
