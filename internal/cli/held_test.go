package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
)

// heldRequests need a secret value each, of each kind and in each place,
// but the sign-in, whose response gives the session that the last one
// sends.
const heldRequests = `# @name query
GET {{host}}/echo?key={{token}}

###
# @name header
GET {{host}}/echo
X-Api-Key: {{token}}

###
# @name body
POST {{host}}/echo

{"key": "{{token}}"}

###
# @name basic
GET {{host}}/echo
Authorization: Basic alice:{{token}}

###
# @name host
GET {{base}}/echo

###
# @name env
GET {{host}}/echo
X-Api-Key: {{$env VEGTAM_TEST_KEY}}

###
# @name cmd
GET {{host}}/echo?key={{$cmd TOUCH}}

###
# @name login
# @capture session = $.session
GET {{host}}/login

###
# @name captured
GET {{host}}/me
Authorization: Bearer {{session}}
`

// heldSecrets are the secrets the requests of heldRequests need, by name.
var heldSecrets = map[string]string{
	"query": "{{token}}", "header": "{{token}}", "body": "{{token}}", "basic": "{{token}}", "host": "{{base}}",
	"env": "{{$env VEGTAM_TEST_KEY}}", "cmd": "{{$cmd TOUCH}}", "captured": "{{session}}",
}

// TestHeldGate checks that a run without a person gets no secret value,
// as the policy has it by default and when it says "deny": each request
// that needs one, of each kind and in each place, is an error of kind
// policy, exit code 6, in every mode, confirmed or not, in a dry run too.
// The error names the secret and the command a person runs; no value
// reaches stdout, stderr or the history; no command runs; and the server
// gets no value. The request that needs none is sent.
func TestHeldGate(t *testing.T) {
	fx := newFixture(t)
	t.Setenv("VEGTAM_TEST_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0") // a helper built with -race would wait a second
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv("VEGTAM_TEST_TOUCH", marker)
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("VEGTAM_NO_HISTORY", "")
	cmds, _ := json.Marshal(map[string]any{"TOUCH": map[string]any{"argv": []string{os.Args[0], "-test.run=^TestHelperProcess$", "--", "touch"}}})
	for name, src := range map[string]string{"http-client.cmd.json": string(cmds), "held.http": heldRequests} {
		if err := os.WriteFile(fx.path(name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file := fx.path("held.http")
	for _, pol := range []string{`{"network": {"allow": ["127.0.0.1", "::1"]}}`, `{"network": {"allow": ["127.0.0.1", "::1"]}, "secrets": {"unattended": "deny"}}`} {
		writePolicy(t, pol) // and a trust store of its own
		if code, _, stderr := runAt(t, "trust", fx.dir); code != exitOK {
			t.Fatalf("trust = %d: %s", code, stderr)
		}
		for _, mode := range []struct {
			name string
			tty  bool
			args []string
		}{{"not a terminal", false, nil}, {"--json", true, []string{"--json"}}, {"text", true, nil}} {
			for _, flags := range [][]string{nil, {"--confirm"}, {"--dry-run"}, {"--confirm", "--dry-run"}} {
				name := pol + " " + mode.name + " " + strings.Join(flags, " ")
				args := append(append([]string{"run", file, "-e", "test"}, mode.args...), flags...)
				code, stdout, stderr := runCLI(t, mode.tty, args...)
				if code != exitPolicy {
					t.Errorf("%s = %d, want %d\n%s\n%s", name, code, exitPolicy, stdout, stderr)
				}
				// The origins a secret may go to are not hidden: see valueLeaks.
				if leaks := fx.valueLeaks(stdout + stderr); len(leaks) > 0 || strings.Contains(stdout+stderr, cmdSecret) {
					t.Errorf("%s: %q in the output\n%s\n%s", name, leaks, stdout, stderr)
				}
				if !mode.tty || mode.args != nil {
					heldResults(t, name, file, stdout)
					continue
				}
				for ref, secret := range heldSecrets {
					want := "vegtam: " + file + ":"
					line := "secret " + secret + ` is not available to a run without a person (policy: secrets.unattended is "deny"); ` +
						"ask the operator to run it: vegtam run " + core.ShellQuote(file+"#"+ref) + " -e test\n"
					if !strings.Contains(stderr, want) || !strings.Contains(stderr, line) {
						t.Errorf("%s: %s: no %q in\n%s", name, ref, line, stderr)
					}
				}
			}
		}
	}
	if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the command ran: %v", err)
	}
	history, err := os.ReadFile(filepath.Join(data, "vegtam", "history.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if leaks := fx.valueLeaks(string(history)); len(leaks) > 0 || !strings.Contains(string(history), `"result":"policy"`) {
		t.Errorf("the history: %q\n%s", leaks, history)
	}
	fx.mu.Lock()
	defer fx.mu.Unlock()
	for _, q := range fx.seen {
		if len(fx.valueLeaks(q)) > 0 || strings.Contains(q, cmdSecret) || q != "" && q != "key="+"{{token}}" {
			t.Errorf("the server got %q", q)
		}
	}
}

// heldResults checks the JSON document of a run of heldRequests without a
// person: each request that needs a secret value has the error of kind
// policy that names it and the command a person runs, and the sign-in
// none.
func heldResults(t *testing.T, name, file, stdout string) {
	t.Helper()
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if len(doc.Results) != len(heldSecrets)+1 {
		t.Fatalf("%s: %d results\n%s", name, len(doc.Results), stdout)
	}
	for _, r := range doc.Results {
		ref := r.Ref[strings.LastIndex(r.Ref, "#")+1:]
		secret, ok := heldSecrets[ref]
		if !ok {
			if r.Error != nil {
				t.Errorf("%s: %s: %+v", name, ref, r.Error)
			}
			continue
		}
		cmd := "vegtam run " + core.ShellQuote(file+"#"+ref) + " -e test"
		if e := r.Error; e == nil || e.Kind != core.KindPolicy || e.Secret == nil || e.Secret.Name != secret || e.PersonCommand != cmd ||
			!strings.HasPrefix(e.Message, "secret "+secret+" is not available to a run without a person") || r.Response != nil {
			t.Errorf("%s: %s: %+v", name, ref, r.Error)
		}
	}
}

// TestSterile checks what a run without a person is shown of a response
// that hands out credentials vegtam does not know as secrets: no
// Set-Cookie, WWW-Authenticate or credential header, no field named as a
// token or a password, no JWT, each as ***, and where in redacted; the
// history says so. A person's run shows the response as it came, but for
// the values of cookies.
func TestSterile(t *testing.T) {
	fx := newFixture(t)
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("VEGTAM_NO_HISTORY", "")
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sid=St3r1le-c00kie; HttpOnly")
		w.Header().Set("WWW-Authenticate", `Bearer realm="st3r1le"`)
		w.Header().Set("X-Api-Key", "St3r1le-k3y")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "St3r1le-t0ken", "expires_in": 3600, "user": {"name": "ada", "Password": "St3r1le-pa55"}, "note": "%s"}`, jwt)
	}))
	t.Cleanup(srv.Close)
	file := fx.path("sterile.http")
	if err := os.WriteFile(file, []byte("GET "+srv.URL+"/token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values := []string{"St3r1le-c00kie", "st3r1le", "St3r1le-k3y", "St3r1le-t0ken", "St3r1le-pa55", jwt}
	shown := func(s string) []string {
		var found []string
		for _, v := range values {
			if strings.Contains(s, v) {
				found = append(found, v)
			}
		}
		return found
	}
	want := []string{"header Set-Cookie", "header Www-Authenticate", "header X-Api-Key", "$.access_token", "$.user.Password", "$.note"}

	code, stdout, stderr := runCLI(t, false, "run", file+"#1")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if r := doc.Result; code != exitOK || r == nil || r.Response == nil || !slices.Equal(r.Redacted, want) || len(shown(stdout+stderr)) > 0 ||
		!strings.Contains(r.Response.Body, `"expires_in": 3600, "user": {"name": "ada", "Password": "***"}`) {
		t.Errorf("without a person = %d, shown %q\n%s\n%s", code, shown(stdout+stderr), stdout, stderr)
	}
	code, stdout, _ = runCLI(t, true, "run", file+"#1", "-v")
	if code != exitOK || len(shown(stdout)) > 0 || !strings.Contains(stdout, "Set-Cookie: ***\n") ||
		!strings.Contains(stdout, "redacted (no person at a terminal): "+strings.Join(want, ", ")+"\n") {
		t.Errorf("as text without a person = %d\n%s", code, stdout)
	}
	code, stdout, _ = runAt(t, "run", file+"#1", "-v")
	if found := shown(stdout); code != exitOK || !slices.Equal(found, values[1:]) || strings.Contains(stdout, "redacted") ||
		!strings.Contains(stdout, "Set-Cookie: sid=***; HttpOnly\n") {
		t.Errorf("a person = %d, shown %q\n%s", code, found, stdout)
	}
	history, err := os.ReadFile(filepath.Join(data, "vegtam", "history.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(history)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"redacted":true`) || !strings.Contains(lines[1], `"redacted":true`) ||
		strings.Contains(lines[2], "redacted") || len(shown(string(history))) > 0 {
		t.Errorf("the history:\n%s", history)
	}
}
