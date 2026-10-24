package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/exec"
	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// local is a keeper in the test's process: a session that holds the
// values, as the person's process would, and says yes to every question,
// or what answer says. What goes between it and the run goes through JSON,
// as on the keeper's socket.
type local struct {
	s      *Session
	answer error
	mu     sync.Mutex
	asked  []string // the requests it asked about: method, URL and secrets
	sent   int      // the requests it was given
}

// errDeclined is the answer of a keeper's person who says no.
var errDeclined = errors.New("declined")

// newLocal returns a keeper whose session has opts, with Serve, that asks
// before every request with a secret.
func newLocal(t *testing.T, opts Options) *local {
	t.Helper()
	return newKeeper(t, opts, true, nil)
}

// newKeeper returns a keeper whose session has opts, with Serve, that asks
// before every request with a secret with always, and otherwise before one
// that sends a secret where it is not bound; its person gives answer.
func newKeeper(t *testing.T, opts Options, always bool, answer error) *local {
	t.Helper()
	k := &local{answer: answer}
	opts.Serve = &Serve{Always: always, Ask: func(_ context.Context, p *core.Prepared, bs []core.Bound) error {
		k.mu.Lock()
		defer k.mu.Unlock()
		var names []string
		for _, b := range bs {
			names = append(names, b.Name+" to "+b.Origin)
		}
		k.asked = append(k.asked, p.Method+" "+p.URL.Masked()+" "+strings.Join(names, ","))
		return k.answer
	}}
	k.s = New(opts)
	return k
}

func (k *local) Send(ctx context.Context, o *Outbound) (*Inbound, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	var got Outbound
	if uerr := json.Unmarshal(b, &got); uerr != nil {
		return nil, uerr
	}
	k.mu.Lock()
	k.sent++
	k.mu.Unlock()
	in := k.s.Relay(ctx, &got)
	if b, err = json.Marshal(in); err != nil {
		return nil, err
	}
	var back Inbound
	return &back, json.Unmarshal(b, &back)
}

// counted counts what a run asks of the secrets of its requests.
type counted struct {
	core.Secrets
	values *int
}

func (c counted) SecretValue(s core.Secret) (string, error) {
	*c.values++
	return c.Secrets.SecretValue(s)
}

// heldFile writes a request for each place a secret may be needed in a
// run without a person, of each kind, and returns the file, a command
// that leaves a mark each time it runs, and the server's record.
func heldFile(t *testing.T) (f *core.File, ran string, got func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.String())
		mu.Unlock()
		fmt.Fprint(w, `{"token": "h3ld/t0ken", "id": "42"}`)
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ran = filepath.Join(t.TempDir(), "ran")
	t.Setenv("VEGTAM_HELD_KEY", "h3ld-env-v4lue")
	src := strings.Join([]string{
		"# @name url\nGET {{host}}/x?k={{secret}}",
		"# @name header\nGET {{host}}/x\nX-Key: {{secret}}",
		"# @name body\nPOST {{host}}/x\n\n{\"k\": \"{{secret}}\"}",
		"# @name basic\nGET {{host}}/x\nAuthorization: Basic {{user}}:{{secret}}",
		"# @name env\nGET {{host}}/x\nX-Key: {{$env VEGTAM_HELD_KEY}}",
		"# @name unset\nGET {{host}}/x\nX-Key: {{$env VEGTAM_HELD_UNSET}}",
		"# @name cmd\nGET {{host}}/x\nX-Key: {{$cmd KEY}}",
		"# @name host\nGET {{base}}/x",
		"# @name login\n# @capture token = $.token\n# @capture plain id = $.id\nGET {{host}}/login",
		"# @name captured\nGET {{host}}/x\nAuthorization: Bearer {{token}}",
		"# @name plain\nGET {{host}}/x?id={{id}}",
		"# @name public\nGET {{host}}/x",
		"# @name note\n# @note look\nGET {{host}}/x?k={{secret}}",
	}, "\n\n###\n")
	allow := `["` + srv.URL + `"]`
	t.Setenv("VEGTAM_TEST_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0") // a helper built with -race would wait before it exits
	cmd, err := json.Marshal(map[string]any{"KEY": map[string]any{"argv": []string{os.Args[0], "-test.run=^TestHelperProcess$", "--", ran}}})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"api.http": src, "http-client.env.json": `{"test": {"host": "` + srv.URL + `", "user": "ada"}}`,
		"http-client.private.env.json": `{"test": {"secret": "h3ld-s3cret", "base": "` + srv.URL + `", "$allow": {"secret": ` + allow + `, "base": ` + allow + `}}}`,
		"http-client.cmd.json":         string(cmd),
	}
	for name, data := range files {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err = httpfile.ParseFile(filepath.Join(dir, "api.http"))
	if err != nil {
		t.Fatal(err)
	}
	return f, ran, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// TestHelperProcess is not a test. The command of heldFile runs the test
// binary, which leaves a mark in the file it is given and prints a value.
func TestHelperProcess(*testing.T) {
	if os.Getenv("VEGTAM_TEST_HELPER") != "1" {
		return
	}
	if err := os.WriteFile(os.Args[len(os.Args)-1], []byte("ran"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "h3ld-cmd-v4lue")
	os.Exit(0)
}

// trustAll returns a trust store that trusts the command file of f.
func trustAll(t *testing.T, f *core.File) *policy.Store {
	t.Helper()
	cf, err := env.ReadCommandFile(filepath.Join(filepath.Dir(f.Path), env.CommandFileName))
	if err != nil {
		t.Fatal(err)
	}
	sum, err := cf.Sum()
	if err != nil {
		t.Fatal(err)
	}
	store := policy.NewStore(filepath.Join(t.TempDir(), "vegtam", "trust.json"))
	if err := store.Trust(cf.Path, sum); err != nil {
		t.Fatal(err)
	}
	return store
}

// TestHeldDenied checks that a run without a person and without a keeper
// gets no secret value at all, of any kind, in any place, in a run or a
// dry run, confirmed or not: each such request is an error of kind policy
// that names the secret and the command a person runs, nothing is sent,
// no command runs, and the secrets are asked for no value. A request
// without a secret goes as before.
func TestHeldDenied(t *testing.T) {
	f, ran, got := heldFile(t)
	want := map[string]string{
		"url": "{{secret}}", "header": "{{secret}}", "body": "{{secret}}", "basic": "{{secret}}", "env": "{{$env VEGTAM_HELD_KEY}}",
		"unset": "{{$env VEGTAM_HELD_UNSET}}", "cmd": "{{$cmd KEY}}", "host": "{{base}}", "captured": "{{token}}", "note": "{{secret}}",
	}
	for _, dry := range []bool{false, true} {
		for _, c := range []Confirm{{}, {All: true}, {Mutations: true}} {
			log := history.New(filepath.Join(t.TempDir(), "vegtam"))
			s := New(Options{Env: "test", DryRun: dry, MaxBody: 1 << 20, Trust: trustAll(t, f), History: log, Confirm: c})
			values := 0
			s.peek = func(v core.Secrets) core.Secrets { return counted{v, &values} }
			jobs := make([]*Job, len(f.Requests))
			for i := range f.Requests {
				jobs[i] = s.Prepare(t.Context(), f, i)
			}
			for i, j := range jobs {
				res := s.Run(t.Context(), j)
				name := f.Requests[i].Name
				secret, ok := want[name]
				switch {
				case !ok:
					if res.Error != nil {
						t.Errorf("dry %v, %+v: %s: %+v", dry, c, name, res.Error)
					}
				case res.Error == nil || res.Error.Kind != core.KindPolicy || res.Error.Secret == nil || res.Error.Secret.Name != secret:
					t.Errorf("dry %v, %+v: %s: %+v; want the policy error of %s", dry, c, name, res.Error, secret)
				default:
					cmd := "vegtam run " + core.ShellQuote(f.Path+"#"+name) + " -e test"
					if name == "note" {
						cmd += " --confirm=" + core.ShellQuote(f.Path+"#note")
					}
					msg := "secret " + secret + ` is not available to a run without a person (policy: secrets.unattended is "deny"); ask the operator to run it: ` + cmd
					if res.Error.Message != msg || res.Error.PersonCommand != cmd {
						t.Errorf("dry %v, %+v: %s: %q\nwant %q", dry, c, name, res.Error.Message, msg)
					}
					if dry && res.SecretOrigins == nil {
						t.Errorf("dry %s: no secret_origins", name)
					}
				}
			}
			if values != 0 {
				t.Errorf("dry %v, %+v: the secrets were asked for %d values", dry, c, values)
			}
			if _, err := os.Stat(ran); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("dry %v, %+v: the command ran: %v", dry, c, err)
			}
			for _, v := range []string{"h3ld-s3cret", "h3ld-env-v4lue", "h3ld-cmd-v4lue"} {
				if s.Masker().Mask(v) != v {
					t.Errorf("dry %v, %+v: the session knows %s", dry, c, v)
				}
			}
		}
	}
	for _, g := range got() {
		if strings.Contains(g, "h3ld") || !strings.HasSuffix(g, "/x") && !strings.HasSuffix(g, "/login") && !strings.Contains(g, "id=42") {
			t.Errorf("the server got %q", g)
		}
	}
}

// TestHeldKeeper checks that a run without a person whose requests need a
// secret sends every one of them through the keeper, which holds the
// values and asks its person; that the run never holds a value, and gets
// those its captures take by name alone, but the plain ones.
func TestHeldKeeper(t *testing.T) {
	f, ran, got := heldFile(t)
	trust := trustAll(t, f)
	k := newLocal(t, Options{Env: "test", MaxBody: 1 << 20, Trust: trust})
	s := New(Options{Env: "test", MaxBody: 1 << 20, Trust: trust, Keeper: k, Confirm: Confirm{Mutations: true}})
	values := 0
	s.peek = func(v core.Secrets) core.Secrets { return counted{v, &values} }
	var jobs []*Job
	for i := range f.Requests {
		jobs = append(jobs, s.Prepare(t.Context(), f, i))
	}
	for _, j := range jobs {
		res := s.Run(t.Context(), j)
		switch name := j.Request.Name; {
		case name == "unset" || name == "note":
			if res.Error == nil {
				t.Errorf("%s: no error", name)
			}
		case res.Error != nil:
			t.Errorf("%s: %+v", name, res.Error)
		case strings.Contains(fmt.Sprint(res.Response), "h3ld"):
			t.Errorf("%s: %+v", name, res.Response)
		}
	}
	if values != 0 {
		t.Errorf("the run asked for %d values", values)
	}
	if _, err := os.Stat(ran); err != nil {
		t.Errorf("the keeper ran no command: %v", err)
	}
	if v, secret, origins, ok := s.loader.Captured("token"); !ok || !secret || v != "" || len(origins) != 1 {
		t.Errorf("token in the run: %q, %v, %q, %v", v, secret, origins, ok)
	}
	if v, secret, _, ok := s.loader.Captured("id"); !ok || secret || v != "42" {
		t.Errorf("id in the run: %q, %v, %v", v, secret, ok)
	}
	if k.sent != len(f.Requests)-1 { // the note is refused by the run
		t.Errorf("the keeper got %d requests, want %d", k.sent, len(f.Requests)-1)
	}
	var secrets int
	for _, g := range got() {
		if strings.Contains(g, "h3ld-s3cret") || strings.Contains(g, "h3ld-env") || strings.Contains(g, "h3ld-cmd") {
			secrets++
		}
	}
	if secrets == 0 {
		t.Errorf("the server got no secret: %q", got())
	}
	if len(k.asked) == 0 || !slices.ContainsFunc(k.asked, func(a string) bool { return strings.Contains(a, "{{token}}") }) {
		t.Errorf("the keeper asked %q", k.asked)
	}
}

// TestHeldAssertions checks that a run without a person checks its
// assertions on the response as it is shown it: a server that echoes a
// secret cannot tell the run the value, a guess at a time, through what
// its assertions give; nor one that a response hands out under a name of
// a credential. A person's run checks the response as it came.
func TestHeldAssertions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.URL.Query().Get("k"))
		fmt.Fprintf(w, `{"echo": %q, "access_token": "Gu3ss-me"}`, r.URL.Query().Get("k"))
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	src := "# @assert body contains \"h3ld\"\n# @assert jsonpath $.echo contains \"h3ld-s\"\n# @assert header X-Echo contains \"h3\"\n" +
		"# @assert jsonpath $.access_token contains \"Gu3ss\"\n# @assert jsonpath $.access_token exists\nGET " + srv.URL + "/?k={{secret}}\n"
	files := map[string]string{
		"api.http":                     src,
		"http-client.private.env.json": `{"test": {"secret": "h3ld-s3cret", "$allow": {"secret": ["` + srv.URL + `"]}}}`,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := httpfile.ParseFile(filepath.Join(dir, "api.http"))
	if err != nil {
		t.Fatal(err)
	}
	k := newKeeper(t, Options{Env: "test", MaxBody: 1 << 20}, false, nil)
	held := New(Options{Env: "test", MaxBody: 1 << 20, Keeper: k})
	res := held.Run(t.Context(), held.Prepare(t.Context(), f, 0))
	var passed []bool
	for _, a := range res.Asserts {
		passed = append(passed, a.Passed)
	}
	if !slices.Equal(passed, []bool{false, false, false, false, true}) || res.Error == nil || res.Error.Kind != core.KindAssert {
		t.Errorf("without a person: %v, %+v", res.Asserts, res.Error)
	}
	person := New(Options{Env: "test", MaxBody: 1 << 20, Confirm: Confirm{Person: true}})
	res = person.Run(t.Context(), person.Prepare(t.Context(), f, 0))
	for _, a := range res.Asserts {
		if !a.Passed {
			t.Errorf("a person's run: %+v", a)
		}
	}
}

// TestHeldCredentialCaptures checks that a run without a person takes as
// a secret what a plain @capture takes of a credential a response hands
// out, which it is not shown: from a member named as one, a header named
// as one, a JSON value that holds one, or a JWT. So the requests after it
// cannot show or send it, as plain text, anywhere. A person's run takes
// them as the directives say.
func TestHeldCredentialCaptures(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl"
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.RawQuery)
		mu.Unlock()
		w.Header().Set("X-Session", "S3ss-hdr")
		fmt.Fprintf(w, `{"access_token": "T0k-body", "id": "42", "note": %q}`, jwt)
	}))
	t.Cleanup(srv.Close)
	src := "# @name login\n# @capture plain tok = $.access_token\n# @capture plain hdr = header X-Session\n# @capture plain all = $\n" +
		"# @capture plain note = $.note\n# @capture plain id = $.id\nGET " + srv.URL + "/login\n\n" +
		"###\n# @name use\nGET " + srv.URL + "/?a={{tok}}&b={{hdr}}&c={{note}}&d={{id}}\n"
	f := originsFile(t, src)
	held := New(Options{MaxBody: 1 << 20})
	jobs := []*Job{held.Prepare(t.Context(), f, 0), held.Prepare(t.Context(), f, 1)}
	login := held.Run(t.Context(), jobs[0])
	secret := map[string]bool{}
	for _, c := range login.Captures {
		secret[c.Name] = c.Secret
	}
	if want := map[string]bool{"tok": true, "hdr": true, "all": true, "note": true, "id": false}; !maps.Equal(secret, want) {
		t.Errorf("without a person, the captures: %v, want %v", secret, want)
	}
	use := held.Run(t.Context(), jobs[1])
	if e := use.Error; e == nil || e.Kind != core.KindPolicy || e.Secret == nil || e.Secret.Name != "{{tok}}" {
		t.Errorf("the request after it: %+v", use.Error)
	}
	if s := fmt.Sprint(use.Request, use.Error); strings.Contains(s, "T0k-body") || strings.Contains(s, "S3ss-hdr") || strings.Contains(s, jwt) {
		t.Errorf("the run was shown a credential: %s", s)
	}
	person := New(Options{MaxBody: 1 << 20, Confirm: Confirm{Person: true}})
	person.Run(t.Context(), person.Prepare(t.Context(), f, 0))
	if res := person.Run(t.Context(), person.Prepare(t.Context(), f, 1)); res.Error != nil {
		t.Errorf("a person's run: %+v", res.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || seen[2] != "a=T0k-body&b=S3ss-hdr&c="+jwt+"&d=42" {
		t.Errorf("the server got %q", seen)
	}
}

// TestKeeperProxyCredentials checks that a keeper sends no request that
// holds the variable of the proxy's credentials, which go to the proxy
// alone, as a person's run does not: the run hands it the request as
// resolved, past the check of Prepare.
func TestKeeperProxyCredentials(t *testing.T) {
	a := newOriginsServer(t, nil)
	t.Setenv("VEGTAM_PROXY_CREDS", "us3r:pa55")
	k := newKeeper(t, Options{
		MaxBody: 1 << 20, Transport: exec.Transport{HiddenEnv: []string{"VEGTAM_PROXY_CREDS"}},
		Secrets: policy.Secrets{Env: map[string][]string{"VEGTAM_PROXY_CREDS": {a.URL}}},
	}, false, nil)
	in, err := k.Send(t.Context(), &Outbound{
		Ref: "x.http#1", Request: &core.Request{Method: "GET", URL: "{{a}}", Source: core.Source{File: filepath.Join(t.TempDir(), "x.http"), Line: 1}},
		Method: "GET", URL: core.Text{{Text: a.URL + "/?c="}, {Secret: &core.Secret{Name: "$env VEGTAM_PROXY_CREDS"}}}, MaxBody: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if e := in.Result.Error; e == nil || e.Kind != core.KindPolicy || !strings.Contains(e.Message, "holds the credentials of the proxy") {
		t.Errorf("the keeper: %+v", in.Result.Error)
	}
	if got := a.requests(); len(got) != 0 {
		t.Errorf("the server got %q", got)
	}
}

// TestKeeperAsksFirst checks that a keeper runs the {{$cmd NAME}} of a
// request only once its person says yes, and shows them no host that a
// secret gives.
func TestKeeperAsksFirst(t *testing.T) {
	f, ran, got := heldFile(t)
	trust := trustAll(t, f)
	index := func(name string) int {
		return slices.IndexFunc(f.Requests, func(r *core.Request) bool { return r.Name == name })
	}
	no := newKeeper(t, Options{Env: "test", MaxBody: 1 << 20, Trust: trust}, true, errDeclined)
	s := New(Options{Env: "test", MaxBody: 1 << 20, Trust: trust, Keeper: no})
	for _, name := range []string{"cmd", "host"} {
		if res := s.Run(t.Context(), s.Prepare(t.Context(), f, index(name))); res.Error == nil || res.Error.Kind != core.KindPolicy {
			t.Errorf("%s, not confirmed: %+v", name, res.Error)
		}
	}
	if _, err := os.Stat(ran); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the command ran before its person said yes: %v", err)
	}
	if len(got()) != 0 {
		t.Errorf("the server got %q", got())
	}
	if len(no.asked) != 2 || no.asked[1] != "GET {{base}}/x {{base}} to ***" {
		t.Errorf("the keeper asked %q; want the host that {{base}} gives masked", no.asked)
	}
	yes := newKeeper(t, Options{Env: "test", MaxBody: 1 << 20, Trust: trust}, true, nil)
	s = New(Options{Env: "test", MaxBody: 1 << 20, Trust: trust, Keeper: yes})
	if res := s.Run(t.Context(), s.Prepare(t.Context(), f, index("cmd"))); res.Error != nil {
		t.Errorf("cmd, confirmed: %+v", res.Error)
	}
	if _, err := os.Stat(ran); err != nil {
		t.Errorf("the command did not run once its person said yes: %v", err)
	}
}
