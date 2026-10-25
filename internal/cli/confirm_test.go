package cli

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core/output"
)

// methodRequests send each method to /echo, which records the query.
const methodRequests = `# @name get
GET {{host}}/echo?m=GET

###
# @name head
HEAD {{host}}/echo?m=HEAD

###
# @name options
OPTIONS {{host}}/echo?m=OPTIONS

###
# @name post
POST {{host}}/echo?m=POST&key={{token}}

###
# @name put
PUT {{host}}/echo?m=PUT

###
# @name patch
PATCH {{host}}/echo?m=PATCH

###
# @name delete
DELETE {{host}}/echo?m=DELETE

###
# @name trace
TRACE {{host}}/echo?m=TRACE
`

// methodFile writes the method requests and returns their file.
func (fx *fixture) methodFile(t *testing.T) string {
	t.Helper()
	path := fx.path("methods.http")
	if err := os.WriteFile(path, []byte(methodRequests), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sent reports whether the server got the request of method m since
// from, the length of fx.seen then.
func (fx *fixture) sent(from int, m string) bool {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return slices.ContainsFunc(fx.seen[from:], func(q string) bool { return strings.HasPrefix(q, "m="+m) })
}

func (fx *fixture) seenCount() int {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return len(fx.seen)
}

// runAs runs args with stdout a terminal or not, and with a person at the
// terminal, stdin and stdout both terminals, or not.
func runAs(t *testing.T, tty, person bool, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	if person {
		return runAt(t, args...)
	}
	return runCLI(t, tty, args...)
}

// TestConfirmModes sends each method in each mode: without a person at a
// terminal, only GET, HEAD and OPTIONS go without --confirm, and the rest
// is an error of kind confirm, exit code 5, before anything is sent; a
// person's run sends them all.
func TestConfirmModes(t *testing.T) {
	fx := newFixture(t)
	file := fx.methodFile(t)
	modes := []struct {
		name              string
		tty, person, json bool
		unattended        bool
		extra             []string
	}{
		{"not a terminal", false, false, true, true, nil},
		{"stdin not a terminal", true, false, false, true, nil},
		{"a person, --json", true, true, true, true, []string{"--json"}},
		{"a person", true, true, false, false, nil},
	}
	for _, m := range modes {
		for _, method := range []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"} {
			t.Run(m.name+"/"+method, func(t *testing.T) {
				from := fx.seenCount()
				args := append([]string{"run", file + "#" + strings.ToLower(method), "-e", "test"}, m.extra...)
				code, stdout, stderr := runAs(t, m.tty, m.person, args...)
				refused := m.unattended && !slices.Contains([]string{"GET", "HEAD", "OPTIONS"}, method)
				want := exitOK
				if refused {
					want = exitConfirm
				}
				if code != want || fx.sent(from, method) == refused {
					t.Errorf("exit code %d, want %d; sent %v\n%s\n%s", code, want, fx.sent(from, method), stdout, stderr)
				}
				if refused && !strings.Contains(stderr, "is not sent without a confirmation, and no person is at a terminal: --confirm="+file+"#"+strings.ToLower(method)+" sends it") {
					t.Errorf("stderr: %s", stderr)
				}
				if m.json {
					validateJSON(t, stdout)
				}
				if found := fx.leaks(stdout + stderr); len(found) > 0 {
					t.Errorf("secret forms %q in the output\n%s\n%s", found, stdout, stderr)
				}
				// --confirm sends it in every mode.
				from = fx.seenCount()
				if code, stdout, stderr := runAs(t, m.tty, m.person, append(args, "--confirm")...); code != exitOK || !fx.sent(from, method) {
					t.Errorf("--confirm: %d\n%s\n%s", code, stdout, stderr)
				}
			})
		}
	}
}

// TestConfirmJSON checks the document of a refused request: the error
// names the request, its method, its URL as written, and the flag.
func TestConfirmJSON(t *testing.T) {
	fx := newFixture(t)
	file := fx.methodFile(t)
	code, stdout, stderr := runCLI(t, false, "run", file+"#post", "-e", "test")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	want := output.Confirm{Reason: "method", Method: "POST", URL: "{{host}}/echo?m=POST&key={{token}}", Flag: "--confirm=" + file + "#post"}
	if r := doc.Result; code != exitConfirm || r == nil || r.Ref != file+"#post" || r.Error == nil || r.Error.Kind != "confirm" ||
		r.Error.Confirm == nil || *r.Error.Confirm != want || r.Request != nil || r.Response != nil || r.Error.Line != 14 {
		t.Errorf("run = %d\n%s\n%s", code, stdout, stderr)
	}

	// A dry run sends nothing and needs nothing: it says what sending would
	// need, unless the flags give it.
	code, stdout, _ = runCLI(t, false, "run", file, "-e", "test", "--dry-run")
	validateJSON(t, stdout)
	doc = output.Document{}
	decode(t, stdout, &doc)
	var asked []string
	for _, r := range doc.Results {
		if r.Confirm != nil {
			asked = append(asked, r.Confirm.Method)
		}
	}
	if code != exitOK || !slices.Equal(asked, []string{"POST", "PUT", "PATCH", "DELETE", "TRACE"}) || doc.Results[3].Confirm.Flag != want.Flag {
		t.Errorf("dry run = %d, asked %q\n%s", code, asked, stdout)
	}
	code, stdout, _ = runCLI(t, false, "run", file, "-e", "test", "--dry-run", "--confirm="+file+"#post")
	if code != exitOK || strings.Count(stdout, `"confirm":`) != 4 {
		t.Errorf("dry run with a request confirmed = %d\n%s", code, stdout)
	}
	if code, stdout, _ = runCLI(t, false, "run", file, "-e", "test", "--dry-run", "--confirm"); code != exitOK || strings.Contains(stdout, `"confirm":`) {
		t.Errorf("dry run with --confirm = %d\n%s", code, stdout)
	}
}

// TestConfirmFlag checks the forms of --confirm: alone, one request, a
// list, by position, a file however it is written; and that a ref that
// names no request of the run, or a value without its =, is a usage error
// before anything is sent.
func TestConfirmFlag(t *testing.T) {
	fx := newFixture(t)
	file := fx.methodFile(t)
	t.Chdir(fx.dir)
	for _, tt := range []struct {
		name string
		args []string
		code int
		sent []string // of the mutations
	}{
		{"none", nil, exitConfirm, nil},
		{"alone", []string{"--confirm"}, exitOK, []string{"POST", "PUT", "PATCH", "DELETE", "TRACE"}},
		{"=all", []string{"--confirm=all"}, exitOK, []string{"POST", "PUT", "PATCH", "DELETE", "TRACE"}},
		{"one", []string{"--confirm=methods.http#post"}, exitConfirm, []string{"POST"}},
		{"a list", []string{"--confirm=methods.http#post,./methods.http#put"}, exitConfirm, []string{"POST", "PUT"}},
		{"twice", []string{"--confirm=methods.http#post", "--confirm=" + file + "#patch"}, exitConfirm, []string{"POST", "PATCH"}},
		{"by position", []string{"--confirm=methods.http#7"}, exitConfirm, []string{"DELETE"}},
		{"all of them", []string{"--confirm=methods.http#post,methods.http#put,methods.http#patch,methods.http#delete,methods.http#trace"}, exitOK, []string{"POST", "PUT", "PATCH", "DELETE", "TRACE"}},
		{"a request that needs none", []string{"--confirm=methods.http#get"}, exitConfirm, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			from := fx.seenCount()
			code, stdout, stderr := runCLI(t, false, append([]string{"run", "methods.http", "-e", "test"}, tt.args...)...)
			validateJSON(t, stdout)
			var sent []string
			for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "TRACE"} {
				if fx.sent(from, m) {
					sent = append(sent, m)
				}
			}
			if code != tt.code || !slices.Equal(sent, tt.sent) || !fx.sent(from, "GET") {
				t.Errorf("%q = %d, sent %q and GET %v; want %d, %q\n%s", tt.args, code, sent, fx.sent(from, "GET"), tt.code, tt.sent, stderr)
			}
		})
	}

	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"an unknown request", []string{"run", "methods.http", "--confirm=methods.http#nope"}, `--confirm=methods.http#nope: methods.http: no request "nope"`},
		{"a position past the end", []string{"run", "methods.http", "--confirm=methods.http#9"}, `no request "9"`},
		{"another file", []string{"run", "methods.http", "--confirm=api.http#echo"}, "--confirm=api.http#echo is not a request of this run, methods.http"},
		{"another request of the file", []string{"run", "methods.http#post", "--confirm=methods.http#put"}, "is not a request of this run, methods.http#post"},
		{"a file outside the directory", []string{"run", "more", "--confirm=methods.http#post"}, "is not a request of this run, more"},
		{"a missing file", []string{"run", "methods.http", "--confirm=none.http#a"}, "--confirm=none.http#a: open none.http"},
		{"no request named", []string{"run", "methods.http", "--confirm=methods.http"}, `"methods.http": want file#name or file#N`},
		{"empty", []string{"run", "methods.http", "--confirm="}, `"": want file#name or file#N`},
		{"an empty ref in the list", []string{"run", "methods.http", "--confirm=methods.http#post,"}, `"": want file#name or file#N`},
		{"without =", []string{"run", "methods.http", "--confirm", "methods.http#post"}, `accepts 1 arg(s), received 2`},
		{"without =, first", []string{"run", "--confirm", "methods.http#post", "methods.http"}, `accepts 1 arg(s), received 2`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			from := fx.seenCount()
			code, stdout, stderr := runCLI(t, false, append(tt.args, "-e", "test")...)
			validateJSON(t, stdout)
			if code != exitUsage || !strings.Contains(stderr, tt.want) || fx.seenCount() != from {
				t.Errorf("%q = %d, sent %d; want %d, %q\n%s", tt.args, code, fx.seenCount()-from, exitUsage, tt.want, stderr)
			}
		})
	}

	// --confirm before the one argument confirms that argument's requests,
	// and no more.
	from := fx.seenCount()
	if code, _, stderr := runCLI(t, false, "run", "--confirm", "methods.http#post", "-e", "test"); code != exitOK || !fx.sent(from, "POST") || fx.seenCount()-from != 1 {
		t.Errorf("run --confirm methods.http#post = %d, sent %d\n%s", code, fx.seenCount()-from, stderr)
	}
}

// TestConfirmSeveral runs a file whose requests fail in different ways:
// a refused one stops only itself, and the exit code is the highest.
func TestConfirmSeveral(t *testing.T) {
	fx := newFixture(t)
	from := fx.seenCount()
	code, stdout, stderr := runCLI(t, false, "run", fx.path("api.http"), "-e", "test", "--max-time", "100ms")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	kinds := map[string]string{}
	for _, r := range doc.Results {
		if r.Error != nil {
			kinds[r.Ref[strings.LastIndex(r.Ref, "#")+1:]] = string(r.Error.Kind)
		}
	}
	if code != exitConfirm || kinds["echo"] != "confirm" || kinds["refused"] != "network" || kinds["slow"] != "timeout" || fx.seenCount()-from < 4 {
		t.Errorf("run = %d, %v, sent %d\n%s", code, kinds, fx.seenCount()-from, stderr)
	}
	// A policy error, 6, is higher.
	setPolicy(t, fx, `{"network": {"allow": ["127.0.0.1:1"]}}`)
	if code, _, _ := runCLI(t, false, "run", fx.path("api.http"), "-e", "test", "--max-time", "100ms"); code != exitPolicy {
		t.Errorf("with a policy error: %d", code)
	}
}

// TestConfirmCaptures checks that the captures of a refused request are
// lost, as those of a request that did not run: the request after it
// that uses one is an error of kind variable.
func TestConfirmCaptures(t *testing.T) {
	dir, _ := newFlowFixture(t)
	t.Chdir(dir)
	code, stdout, _ := runCLI(t, false, "run", "login.http", "-e", "test")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if code != exitConfirm || len(doc.Results) != 3 || doc.Results[0].Error != nil || doc.Results[1].Error.Kind != "confirm" ||
		doc.Results[2].Error == nil || doc.Results[2].Error.Kind != "variable" ||
		!strings.Contains(doc.Results[2].Error.Message, "token (login.http#login took no value)") {
		t.Errorf("run = %d\n%s", code, stdout)
	}
}

// TestConfirmPolicy checks network.confirm: "never" lets a run without a
// person send any method, and vegtam policy says which rule applies.
func TestConfirmPolicy(t *testing.T) {
	fx := newFixture(t)
	file := fx.methodFile(t)
	for _, tt := range []struct {
		policy, confirm string
		code            int
		run             bool // confirm_mutations
		text            string
	}{
		{`{"network": {"allow": ["127.0.0.1"], "confirm": "never"}}`, "never", exitOK, false, "Any method is sent without --confirm; a request with # @note only with it."},
		{`{"network": {"allow": ["127.0.0.1"], "confirm": "mutations"}}`, "mutations", exitConfirm, true, "A method other than GET, HEAD or OPTIONS, and a request with # @note, are sent only with --confirm."},
		{loopbackPolicy, "", exitConfirm, true, "A method other than GET, HEAD or OPTIONS, and a request with # @note, are sent only with --confirm."},
	} {
		setPolicy(t, fx, tt.policy)
		from := fx.seenCount()
		if code, _, stderr := runCLI(t, false, "run", file+"#delete", "-e", "test"); code != tt.code || fx.sent(from, "DELETE") != (tt.code == exitOK) {
			t.Errorf("%s: run = %d\n%s", tt.policy, code, stderr)
		}
		code, stdout, _ := runCLI(t, false, "policy")
		validateJSON(t, stdout)
		var doc struct {
			Policy struct {
				Network struct{ Confirm string }
				Run     struct {
					ConfirmMutations *bool `json:"confirm_mutations"`
				}
			}
		}
		decode(t, stdout, &doc)
		if r := doc.Policy.Run.ConfirmMutations; code != exitOK || r == nil || *r != tt.run || doc.Policy.Network.Confirm != tt.confirm {
			t.Errorf("%s: policy = %d\n%s", tt.policy, code, stdout)
		}
		if _, stdout, _ = runCLI(t, true, "policy"); !strings.Contains(stdout, tt.text) {
			t.Errorf("%s: policy as text:\n%s", tt.policy, stdout)
		}
	}
	// A person's run sends any method, whatever the policy says.
	if _, stdout, _ := runAt(t, "policy"); !strings.Contains(stdout, "Any method is sent without --confirm; a request with # @note only with it.") {
		t.Errorf("policy for a person:\n%s", stdout)
	}
	setPolicy(t, fx, `{"network": {"confirm": "sometimes"}}`)
	if code, _, stderr := runCLI(t, false, "run", file+"#get", "-e", "test"); code != exitPolicy || !strings.Contains(stderr, `network.confirm "sometimes": want "mutations", the default, or "never"`) {
		t.Errorf("an unknown value = %d, %s", code, stderr)
	}
}

// TestConfirmBeforeCommands checks that a request is refused before it is
// resolved: the {{$cmd NAME}} of a refused request does not run.
func TestConfirmBeforeCommands(t *testing.T) {
	fx := newFixture(t)
	t.Setenv("VEGTAM_TEST_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0") // a helper built with -race would wait a second
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv("VEGTAM_TEST_TOUCH", marker)
	cmds, _ := json.Marshal(map[string]any{"TOUCH": map[string]any{"argv": []string{os.Args[0], "-test.run=^TestHelperProcess$", "--", "touch"}}})
	if err := os.Mkdir(fx.path("cmd"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"cmd/http-client.cmd.json": string(cmds), "cmd/post.http": "POST {{host}}/echo?key={{$cmd TOUCH}}\n"}
	for name, src := range files {
		if err := os.WriteFile(fx.path(name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code, _, stderr := runAt(t, "trust", fx.path("cmd")); code != exitOK {
		t.Fatalf("trust = %d: %s", code, stderr)
	}
	post := fx.path("cmd/post.http") + "#1"
	if code, _, stderr := runCLI(t, false, "run", post, "-e", "test"); code != exitConfirm {
		t.Errorf("run = %d, %s", code, stderr)
	}
	if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the command of a refused request ran: %v", err)
	}
	if code, stdout, stderr := runCLI(t, false, "run", post, "-e", "test", "--confirm"); code != exitOK || len(cmdLeaks(stdout+stderr)) > 0 {
		t.Errorf("run --confirm = %d\n%s\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the command of a confirmed request did not run: %v", err)
	}
}

// noteRequests have an @note: one with a text that holds a secret value
// and what would drive a terminal, one without a text.
const noteRequests = "# @name purge\n# @note Deletes {{what}} for good, " + privateSecret + " \x1b]0;t\x07 \u202eok\nGET {{host}}/echo?m=NOTE\n\n" +
	"###\n# @name quiet\n# @note\nPOST {{host}}/echo?m=QUIET\n"

// TestNote checks that a request with an @note needs --confirm in every
// mode, a person's too, whatever the policy says, and that the note
// shows masked and made fit for a terminal.
func TestNote(t *testing.T) {
	fx := newFixture(t)
	file := fx.path("notes.http")
	if err := os.WriteFile(file, []byte(noteRequests), 0o600); err != nil {
		t.Fatal(err)
	}
	purge := file + "#purge"
	shown := `Deletes {{what}} for good, *** \x1b]0;t\x07 \u202eok`

	// A person at a terminal: the note, and exit 5, until --confirm.
	from := fx.seenCount()
	code, stdout, stderr := runAt(t, "run", purge, "-e", "test")
	want := "vegtam: " + file + ":3: GET {{host}}/echo?m=NOTE is not sent without a confirmation, which its @note asks for (--confirm=" + purge + " sends it): " + shown + "\n"
	if code != exitConfirm || stdout != "" || stderr != want || fx.sent(from, "NOTE") {
		t.Errorf("a person = %d\n%s\n%q\nwant %q", code, stdout, stderr, want)
	}
	for _, flag := range []string{"--confirm", "--confirm=" + purge, "--confirm=" + file + "#1"} {
		from = fx.seenCount()
		if c, _, errOut := runAt(t, "run", purge, "-e", "test", flag); c != exitOK || !fx.sent(from, "NOTE") {
			t.Errorf("a person, %s = %d, %s", flag, c, errOut)
		}
	}

	// Without a person: the same, in JSON, and the policy cannot lift it.
	// Such a run holds no secret value, so it cannot mask one that the file
	// itself writes out, which the program that runs it can read anyway.
	setPolicy(t, fx, `{"network": {"allow": ["127.0.0.1"], "confirm": "never"}}`)
	from = fx.seenCount()
	code, stdout, stderr = runCLI(t, false, "run", file, "-e", "test")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	note := "Deletes {{what}} for good, " + privateSecret + " \x1b]0;t\x07 \u202eok"
	if code != exitConfirm || len(doc.Results) != 2 || fx.seenCount() != from {
		t.Fatalf("run = %d, sent %d\n%s\n%s", code, fx.seenCount()-from, stdout, stderr)
	}
	if c := doc.Results[0].Error.Confirm; c == nil || c.Reason != "note" || c.Note == nil || *c.Note != note || c.Method != http.MethodGet {
		t.Errorf("purge: %+v", doc.Results[0].Error)
	}
	if e := doc.Results[1].Error; e.Confirm == nil || e.Confirm.Note == nil || *e.Confirm.Note != "" ||
		e.Message != "POST {{host}}/echo?m=QUIET is not sent without a confirmation, which its @note asks for: --confirm="+file+"#quiet sends it" {
		t.Errorf("quiet: %+v", e)
	}
	if !strings.Contains(stderr, strings.Replace(shown, "***", privateSecret, 1)) {
		t.Errorf("the note not shown as text\n%s\n%s", stdout, stderr)
	}
	code, stdout, _ = runCLI(t, false, "run", file, "-e", "test", "--dry-run")
	if code != exitOK || strings.Count(stdout, `"reason":"note"`) != 2 {
		t.Errorf("dry run = %d\n%s", code, stdout)
	}

	// list shows it, as text and in JSON.
	code, stdout, _ = runCLI(t, true, "list", file)
	if code != exitOK || !strings.Contains(stdout, `@note Deletes {{what}} for good, `+privateSecret+` \x1b]0;t\x07 \u202eok`) ||
		!strings.Contains(stdout, "{{host}}/echo?m=QUIET  @note\n") {
		t.Errorf("list = %d\n%s", code, stdout)
	}
	code, stdout, _ = runCLI(t, false, "list", file)
	validateJSON(t, stdout)
	doc = output.Document{}
	decode(t, stdout, &doc)
	if l := doc.Requests; code != exitOK || len(l) != 2 || l[0].Note == nil || !strings.HasPrefix(*l[0].Note, "Deletes {{what}}") || l[1].Note == nil || *l[1].Note != "" {
		t.Errorf("list = %d\n%s", code, stdout)
	}
}
