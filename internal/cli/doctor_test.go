package cli

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
)

// doctorMarker is a secret value that doctor must never print: it is in
// the private environment file, and in variables that the policy names.
const doctorMarker = "D0ct0r-M4rker/x+y"

// doctorPolicyFile binds secrets of the environment and of a command, sends a
// run without a person to the keeper, and names the variable of the
// proxy's credentials.
const doctorPolicyFile = `{
  "secrets": {"env": {"VEGTAM_DOCTOR_TOKEN": ["https://api.example.com"], "VEGTAM_DOCTOR_UNSET": []},
              "cmd": {"TOKEN": ["https://api.example.com"]}, "unattended": "keeper", "keeper_asks": "unbound"},
  "network": {"proxy": "http://proxy.example:3128", "proxy_auth": "$env VEGTAM_DOCTOR_PROXY"}
}`

// doctorEnv makes the world of a test of doctor: a policy that says doc,
// a runtime directory for the keeper's socket, no multiplexer, and a
// current directory below one with a private environment file that holds
// doctorMarker, if private. It returns vegtam's configuration directory,
// the runtime directory and the directory of the private file.
func doctorEnv(t *testing.T, doc string, private bool) (config, runtime, work string) {
	t.Helper()
	config, runtime, work = writePolicy(t, doc), t.TempDir(), t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	t.Setenv("TMUX", "")
	t.Setenv("STY", "")
	if private {
		b := []byte(`{"dev": {"token": "` + doctorMarker + `"}}`)
		if err := os.WriteFile(filepath.Join(work, "http-client.private.env.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sub := filepath.Join(work, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	return config, runtime, work
}

// runDoctor runs doctor without a person at a terminal, checks that it
// exits with 0, prints a document the schema accepts and nothing on
// stderr, and returns the document.
func runDoctor(t *testing.T) *output.Doctor {
	t.Helper()
	code, stdout, stderr := runCLI(t, false, "doctor")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if code != exitOK || stderr != "" || doc.Doctor == nil {
		t.Fatalf("doctor = %d\n%s\n%s", code, stdout, stderr)
	}
	return doc.Doctor
}

// rows returns the lines of s with their runs of spaces made one, as the
// columns of a table are.
func rows(s string) []string {
	var lines []string
	for line := range strings.Lines(s) {
		lines = append(lines, strings.Join(strings.Fields(line), " "))
	}
	return lines
}

// messages returns the messages of ws, each after its file if it has one.
func messages(ws []output.Warning) []string {
	var list []string
	for _, w := range ws {
		if w.File != "" {
			list = append(list, w.File+": "+w.Message)
		} else {
			list = append(list, w.Message)
		}
	}
	return list
}

// TestDoctor checks what doctor says, in JSON and as text, of a policy
// with the keeper, a private environment file, variables that hold
// secrets, a multiplexer and a socket where the keeper's goes: and that
// no secret value shows, whoever runs it.
func TestDoctor(t *testing.T) {
	config, runtime, work := doctorEnv(t, doctorPolicyFile, true)
	t.Setenv("VEGTAM_DOCTOR_TOKEN", doctorMarker)
	t.Setenv("VEGTAM_DOCTOR_UNSET", "")
	t.Setenv("VEGTAM_DOCTOR_PROXY", "someone:"+doctorMarker)
	t.Setenv("TMUX", "/tmp/tmux-1000/default,4242,0")
	if err := os.Mkdir(filepath.Join(runtime, "vegtam"), 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(runtime, "vegtam", "keeper.sock")
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})

	d := runDoctor(t)
	if d.Mode != (output.DescribeMode{Unattended: true, Why: "stdin or stdout is not a terminal", Secrets: output.RunSecretsKeeper}) {
		t.Errorf("mode %+v", d.Mode)
	}
	p := d.Policy
	if p.Path != filepath.Join(config, "policy.json") || !p.Found || p.Error != nil || p.SecretsMode == nil ||
		*p.SecretsMode != (output.PolicySecretsMode{Unattended: "keeper", KeeperAsks: "unbound"}) ||
		!slices.Equal(p.Env, []string{"VEGTAM_DOCTOR_TOKEN", "VEGTAM_DOCTOR_UNSET"}) || !slices.Equal(p.Cmd, []string{"TOKEN"}) {
		t.Errorf("policy %+v", p)
	}
	private := filepath.Join(work, "http-client.private.env.json")
	uid := os.Getuid()
	mine := func(what string, got output.DoctorPath, path, typ, mode string) {
		t.Helper()
		if got.Path != path || !got.Exists || got.Type != typ || (mode != "" && got.Mode != mode) || !got.Owned ||
			got.UID == nil || *got.UID != uid || got.Why != "" {
			t.Errorf("%s: %+v, want %s, a %s %s of uid %d", what, got, path, typ, mode, uid)
		}
	}
	s := d.Secrets
	if s.Dir != filepath.Join(work, "sub") || s.PrivateFile == nil ||
		!slices.Equal(s.Environment, []string{"VEGTAM_DOCTOR_PROXY", "VEGTAM_DOCTOR_TOKEN"}) {
		t.Fatalf("secrets %+v", s)
	}
	mine("private file", *s.PrivateFile, private, "file", "0600")
	mine("socket", d.Keeper.Socket, socket, "socket", "")
	if k := d.Keeper; k.Running || k.Why != "vegtam does not yet ask whether a keeper answers on the socket" {
		t.Errorf("keeper %+v", k)
	}
	if !slices.Equal(d.Multiplexers, []output.DoctorMultiplexer{{Name: "tmux", Variable: "TMUX"}}) {
		t.Errorf("multiplexers %+v", d.Multiplexers)
	}
	mine("config", d.Config.Dir, config, "directory", "0700")
	mine("policy file", d.Config.Policy, filepath.Join(config, "policy.json"), "file", "0600")
	want := []string{
		private + ": its secrets can be read by any process that runs as your user, agents started from this shell among them",
		"VEGTAM_DOCTOR_PROXY is set in the environment, which every process started from this shell inherits, agents among them",
		"VEGTAM_DOCTOR_TOKEN is set in the environment, which every process started from this shell inherits, agents among them",
		"this shell runs in tmux (TMUX is set): another process can read and type into a session of a multiplexer, " +
			"and so read what vegtam shows there and answer what it asks",
	}
	if got := messages(d.Warnings); !slices.Equal(got, want) {
		t.Errorf("warnings\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// As text, a row for each part and then the warnings.
	code, stdout, stderr := runCLI(t, true, "doctor")
	lines := rows(stdout)
	wantRows := []string{
		"mode no person is at a terminal (stdin or stdout is not a terminal)",
		"policy " + filepath.Join(config, "policy.json") + ": file 0600, yours",
		"unattended keeper",
		"keeper asks unbound",
		"binds 2 {{$env NAME}}: VEGTAM_DOCTOR_TOKEN, VEGTAM_DOCTOR_UNSET; 1 {{$cmd NAME}}: TOKEN",
		"private file " + private + ": file 0600, yours",
		"environment holds VEGTAM_DOCTOR_PROXY, VEGTAM_DOCTOR_TOKEN",
		"keeper " + socket + ": socket " + d.Keeper.Socket.Mode + ", yours; vegtam does not yet ask whether a keeper answers on the socket",
		"multiplexer tmux (TMUX is set)",
		"config " + config + ": directory 0700, yours",
		"",
	}
	for _, w := range want {
		wantRows = append(wantRows, "warning: "+w)
	}
	if code != exitOK || stderr != "" || !slices.Equal(lines, wantRows) {
		t.Errorf("as text = %d, %s\n%s\nwant\n%s", code, stderr, stdout, strings.Join(wantRows, "\n"))
	}

	// No secret value, in any mode: doctor reads none.
	for _, mode := range []struct {
		name        string
		tty, person bool
		args        []string
	}{
		{"not a terminal", false, false, nil},
		{"text, not a person", true, false, nil},
		{"a person", true, true, nil},
		{"a person, --json", true, true, []string{"--json"}},
	} {
		code, stdout, stderr := runAs(t, mode.tty, mode.person, append([]string{"doctor"}, mode.args...)...)
		if code != exitOK {
			t.Errorf("%s = %d\n%s", mode.name, code, stderr)
		}
		for _, m := range []string{doctorMarker, "M4rker", "someone:"} {
			if strings.Contains(stdout+stderr, m) {
				t.Errorf("%s: %q in the output\n%s\n%s", mode.name, m, stdout, stderr)
			}
		}
	}
	if _, stdout, _ := runAt(t, "doctor"); rows(stdout)[0] != "mode a person is at a terminal (stdin and stdout are terminals)" {
		t.Errorf("a person:\n%s", stdout)
	}
}

// TestDoctorNothing runs doctor where there is nothing to find: no
// policy, no private environment file, no keeper and no multiplexer.
func TestDoctorNothing(t *testing.T) {
	_, runtime, work := doctorEnv(t, `{}`, false)
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	d := runDoctor(t)
	config := filepath.Join(home, "vegtam")
	if p := d.Policy; p.Path != filepath.Join(config, "policy.json") || p.Found || p.Error != nil || p.SecretsMode == nil ||
		*p.SecretsMode != (output.PolicySecretsMode{Unattended: "deny", KeeperAsks: "always"}) || p.Env != nil || p.Cmd != nil {
		t.Errorf("policy %+v", p)
	}
	socket := filepath.Join(runtime, "vegtam", "keeper.sock")
	if s := d.Secrets; s.PrivateFile != nil || s.Environment != nil || s.Dir != filepath.Join(work, "sub") {
		t.Errorf("secrets %+v", s)
	}
	if k := d.Keeper; k.Socket != (output.DoctorPath{Path: socket}) || k.Running || k.Why != "nothing is at the socket" {
		t.Errorf("keeper %+v", k)
	}
	if c := d.Config; c.Dir != (output.DoctorPath{Path: config}) || c.Policy != (output.DoctorPath{Path: filepath.Join(config, "policy.json")}) {
		t.Errorf("config %+v", c)
	}
	if d.Multiplexers != nil || d.Warnings != nil {
		t.Errorf("multiplexers %+v, warnings %+v", d.Multiplexers, d.Warnings)
	}
	_, stdout, _ := runCLI(t, true, "doctor")
	for _, want := range []string{
		"policy " + filepath.Join(config, "policy.json") + ", not found: vegtam does what it does on its own",
		"unattended deny",
		"binds no {{$env NAME}} or {{$cmd NAME}}: their values go nowhere",
		"private file none in " + filepath.Join(work, "sub") + " or above",
		"keeper " + socket + ": nothing is there",
		"config " + config + ": nothing is there",
		"Nothing to warn of.",
	} {
		if !slices.Contains(rows(stdout), want) {
			t.Errorf("as text, no line %q\n%s", want, stdout)
		}
	}

	// Both multiplexers, and something at the socket that is not one.
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1,0")
	t.Setenv("STY", "4242.pts-0.host")
	if err := os.Mkdir(filepath.Join(runtime, "vegtam"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	d = runDoctor(t)
	if want := []output.DoctorMultiplexer{{Name: "tmux", Variable: "TMUX"}, {Name: "screen", Variable: "STY"}}; !slices.Equal(d.Multiplexers, want) ||
		len(d.Warnings) != 2 || !strings.HasPrefix(d.Warnings[1].Message, "this shell runs in screen (STY is set): ") {
		t.Errorf("multiplexers %+v, warnings %+v", d.Multiplexers, d.Warnings)
	}
	if k := d.Keeper; k.Socket.Type != "file" || k.Socket.Mode != "0600" || k.Running || k.Why != "what is at the path is not a socket" {
		t.Errorf("keeper %+v", k)
	}
}

// TestDoctorPolicyError runs doctor with a policy file that cannot be
// read: it says why, and exits with 0 all the same.
func TestDoctorPolicyError(t *testing.T) {
	config, _, _ := doctorEnv(t, `{"network": {"alow": []}}`, false)
	path := filepath.Join(config, "policy.json")
	d := runDoctor(t)
	if p := d.Policy; p.Path != path || !p.Found || p.Error == nil || p.Error.Kind != core.KindPolicy || p.Error.File != path ||
		!strings.Contains(p.Error.Message, `unknown field "alow"`) || p.SecretsMode != nil || p.Env != nil {
		t.Errorf("policy %+v, error %+v", p, p.Error)
	}
	// As text, the reason below the file; and nothing of what the file
	// would say.
	code, stdout, stderr := runAt(t, "doctor")
	if code != exitOK || stderr != "" || !slices.Contains(rows(stdout), `cannot be read: json: unknown field "alow"`) ||
		!slices.Contains(rows(stdout), "policy "+path+": file 0600, yours") ||
		strings.Contains(stdout, "unattended") || strings.Contains(stdout, "binds") {
		t.Errorf("as text = %d\n%s\n%s", code, stdout, stderr)
	}
	if code, stdout, stderr = runAt(t, "doctor", "--json"); code != exitOK || stderr != "" || !strings.Contains(stdout, `unknown field \"alow\"`) {
		t.Errorf("--json = %d\n%s\n%s", code, stdout, stderr)
	}
}

// TestDoctorPermissions checks the warnings of doctor on the modes of
// vegtam's configuration directory, of the policy file and of the private
// environment file.
func TestDoctorPermissions(t *testing.T) {
	config, _, work := doctorEnv(t, `{}`, true)
	policy, private := filepath.Join(config, "policy.json"), filepath.Join(work, "http-client.private.env.json")
	const readers = "its secrets can be read by any process that runs as your user, agents started from this shell among them"
	for _, tt := range []struct {
		name     string
		modes    [3]os.FileMode // of the directory, the policy and the private file
		shown    [3]string      // as doctor shows them
		readable bool           // the policy is read
		want     []string
	}{
		{"private", [3]os.FileMode{0o700, 0o600, 0o600}, [3]string{"0700", "0600", "0600"}, true, []string{private + ": " + readers}},
		{"readable", [3]os.FileMode{0o700, 0o644, 0o640}, [3]string{"0700", "0644", "0640"}, true, []string{
			private + ": " + readers,
			private + ": others can read it too: chmod 600 " + private,
			policy + ": others can read the policy; it holds no secret, but says what vegtam may do: chmod 600 " + policy,
		}},
		{"writable", [3]os.FileMode{0o777, 0o666, 0o662}, [3]string{"0777", "0666", "0662"}, false, []string{
			private + ": " + readers,
			private + ": others can write it, and so change its secrets and where they go: chmod 600 " + private,
			config + ": others can write it, so neither the policy nor the trust store in it is read; make it private: chmod 700 " + config,
			policy + ": others can write it, so the policy is not read; make it private: chmod 600 " + policy,
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for i, path := range []string{config, policy, private} {
				if err := os.Chmod(path, tt.modes[i]); err != nil {
					t.Fatal(err)
				}
			}
			d := runDoctor(t)
			if got := messages(d.Warnings); !slices.Equal(got, tt.want) {
				t.Errorf("warnings\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tt.want, "\n"))
			}
			if (d.Policy.Error == nil) != tt.readable {
				t.Errorf("policy error %+v", d.Policy.Error)
			}
			if got := [3]string{d.Config.Dir.Mode, d.Config.Policy.Mode, d.Secrets.PrivateFile.Mode}; got != tt.shown {
				t.Errorf("modes %q, want %q", got, tt.shown)
			}
		})
	}
}

// TestDoctorHelp checks that the help of doctor says what each part
// means, and that its exit code is 0.
func TestDoctorHelp(t *testing.T) {
	_, stdout, _ := runCLI(t, true, "doctor", "--help")
	help := strings.Join(strings.Fields(stdout), " ")
	for _, want := range []string{
		"Its exit code is 0 whatever it finds",
		"mode is whether a person is at a terminal",
		"policy is the operator's policy file",
		"private file is the nearest http-client.private.env.json",
		"agents started from this shell among them",
		"keeper is the unix socket of the keeper, a process you run in your terminal",
		"$XDG_RUNTIME_DIR/vegtam/keeper.sock",
		"multiplexer is tmux or screen",
		"config is vegtam's configuration directory",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q\n%s", want, stdout)
		}
	}
}
