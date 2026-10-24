package session

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/output"
)

func TestConfirmNeeds(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if got := (Confirm{}).Needs(&core.Request{Method: m}); got != "" {
			t.Errorf("%s needs %q", m, got)
		}
	}
	// Fail closed: any other method, one vegtam does not know too, and a
	// safe one in another case, which no file can write.
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "PROPFIND", "get", ""} {
		r := &core.Request{Method: m}
		if got := (Confirm{}).Needs(r); got != core.ReasonMethod {
			t.Errorf("%q needs %q, want %q", m, got, core.ReasonMethod)
		}
		if got := (Confirm{Mutations: true}).Needs(r); got != "" {
			t.Errorf("%q with Mutations needs %q", m, got)
		}
		if got := (Confirm{All: true}).Needs(r); got != core.ReasonMethod {
			t.Errorf("%q with All needs %q: All confirms, it does not lift the rule", m, got)
		}
	}
}

// TestConfirmNote checks that an @note asks for a confirmation whatever
// the method, and that Mutations does not lift it.
func TestConfirmNote(t *testing.T) {
	note := []core.Directive{{Kind: core.Note, Value: ""}}
	for _, m := range []string{"GET", "HEAD", "POST"} {
		r := &core.Request{Method: m, Directives: note}
		for _, c := range []Confirm{{}, {Mutations: true}, {All: true}} {
			if got := c.Needs(r); got != core.ReasonNote {
				t.Errorf("%s with an @note, %+v: needs %q", m, c, got)
			}
		}
	}
}

func TestKey(t *testing.T) {
	t.Chdir(t.TempDir())
	a, err := Key("api.http", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"./api.http", "sub/../api.http", filepath.Join(".", "x", "..", "api.http")} {
		if b, err := Key(path, 1); err != nil || b != a {
			t.Errorf("Key(%q) = %q, %v; want %q", path, b, err, a)
		}
	}
	if !filepath.IsAbs(a) || !strings.HasSuffix(a, string(filepath.Separator)+"api.http#2") {
		t.Errorf("Key = %q", a)
	}
}

// confirmFile writes a sign-in by POST that captures a token, a GET that
// sends it, and a DELETE, for a server that records what it gets.
func confirmFile(t *testing.T) (f *core.File, got func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		fmt.Fprint(w, `{"token": "c0nfirm/t0ken"}`)
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	src := "# @name login\n# @capture token = $.token\nPOST {{host}}/login\n\n###\n# @name me\nGET {{host}}/me\nAuthorization: Bearer {{token}}\n\n" +
		"###\n# @name drop\nDELETE {{host}}/items/{{secret}}\n"
	files := map[string]string{
		"api.http": src, "http-client.env.json": `{"test": {"host": "` + srv.URL + `"}}`,
		"http-client.private.env.json": `{"test": {"secret": "c0nfirm-s3cret", "$allow": {"secret": ["` + srv.URL + `"]}}}`,
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
	return f, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// TestConfirmRefuses checks that the zero Confirm sends no request that
// needs a confirmation: it is refused, with what confirms it, and its
// captures are lost, as those of a request that did not run. The secrets
// go through a keeper, as a run without a person sends them.
func TestConfirmRefuses(t *testing.T) {
	f, got := confirmFile(t)
	log := history.New(filepath.Join(t.TempDir(), "vegtam"))
	s := New(Options{Env: "test", MaxBody: 1 << 20, History: log, Keeper: newLocal(t, Options{Env: "test", MaxBody: 1 << 20})})
	login := s.Prepare(t.Context(), f, 0)
	if login.Prepared != nil || login.Err == nil {
		t.Fatalf("login prepared %+v, error %v; want it refused", login.Prepared, login.Err)
	}
	res := s.Run(t.Context(), login)
	want := "POST {{host}}/login is not sent without a confirmation, and no person is at a terminal: --confirm=" + f.Path + "#login sends it"
	if e := res.Error; e == nil || e.Kind != core.KindConfirm || e.Message != want || e.Confirm == nil ||
		*e.Confirm != (output.Confirm{Reason: core.ReasonMethod, Method: "POST", URL: "{{host}}/login", Flag: "--confirm=" + f.Path + "#login"}) ||
		res.Request != nil || res.Response != nil {
		t.Fatalf("login = %+v, error %+v", res, res.Error)
	}
	me := s.Run(t.Context(), s.Prepare(t.Context(), f, 1))
	if me.Error == nil || me.Error.Kind != core.KindVariable || !strings.Contains(me.Error.Message, "not captured: token ("+f.Path+"#login took no value)") {
		t.Errorf("me after a refused login: %+v", me.Error)
	}
	if res := s.Run(t.Context(), s.Prepare(t.Context(), f, 2)); res.Error == nil || res.Error.Kind != core.KindConfirm ||
		res.Error.Confirm.URL != "{{host}}/items/{{secret}}" || strings.Contains(res.Error.Message, "c0nfirm-s3cret") {
		t.Errorf("drop: %+v", res.Error)
	}
	if g := got(); len(g) != 0 {
		t.Errorf("the server got %q", g)
	}
	runs, err := log.Last(10)
	if err != nil || len(runs) != 3 || runs[0].Result != "confirm" || runs[1].Result != "variable" || runs[2].Result != "confirm" {
		t.Errorf("history %+v, %v", runs, err)
	}

	// Once a person confirms it, for that time only.
	s.ConfirmOnce(f, 0)
	if res := s.Run(t.Context(), s.Prepare(t.Context(), f, 0)); res.Error != nil {
		t.Errorf("login once confirmed: %+v", res.Error)
	}
	if res := s.Run(t.Context(), s.Prepare(t.Context(), f, 0)); res.Error == nil || res.Error.Kind != core.KindConfirm {
		t.Errorf("login again: %+v", res.Error)
	}
	// A job that Prepare refused stays refused, whatever its Err says.
	j := s.Prepare(t.Context(), f, 0)
	j.Err = nil
	if res := s.Run(t.Context(), j); res.Error == nil || res.Error.Kind != core.KindConfirm {
		t.Errorf("a refused job with its error cleared: %+v", res.Error)
	}
	if g := got(); !slices.Equal(g, []string{"POST /login"}) {
		t.Errorf("the server got %q", g)
	}
}

// TestConfirmGiven checks what confirms a request: All, its key, or
// Mutations; and that a dry run sends nothing and says what sending would
// need.
func TestConfirmGiven(t *testing.T) {
	f, got := confirmFile(t)
	key, err := Key(f.Path, 2)
	if err != nil {
		t.Fatal(err)
	}
	keeper := newLocal(t, Options{Env: "test", MaxBody: 1 << 20})
	for _, c := range []Confirm{{All: true}, {Mutations: true}, {Requests: []string{key}}} {
		s := New(Options{Env: "test", MaxBody: 1 << 20, Confirm: c, Keeper: keeper})
		if res := s.Run(t.Context(), s.Prepare(t.Context(), f, 2)); res.Error != nil || res.Response == nil {
			t.Errorf("%+v: %+v", c, res.Error)
		}
	}
	s := New(Options{Env: "test", MaxBody: 1 << 20, Confirm: Confirm{Requests: []string{key}}})
	if res := s.Run(t.Context(), s.Prepare(t.Context(), f, 0)); res.Error == nil || res.Error.Kind != core.KindConfirm {
		t.Errorf("a request the keys do not name: %+v", res.Error)
	}
	if g := got(); !slices.Equal(g, []string{"DELETE /items/c0nfirm-s3cret", "DELETE /items/c0nfirm-s3cret", "DELETE /items/c0nfirm-s3cret"}) {
		t.Errorf("the server got %q", g)
	}

	dry := New(Options{Env: "test", DryRun: true, Keeper: keeper})
	for i, want := range []string{"--confirm=" + f.Path + "#login", "", "--confirm=" + f.Path + "#drop"} {
		res := dry.Run(t.Context(), dry.Prepare(t.Context(), f, i))
		switch {
		case res.Error != nil || res.Request == nil:
			t.Errorf("dry run of %d: %+v", i, res.Error)
		case want == "" && res.Confirm != nil, want != "" && (res.Confirm == nil || res.Confirm.Flag != want || res.Confirm.Reason != core.ReasonMethod):
			t.Errorf("dry run of %d: confirm %+v, want %q", i, res.Confirm, want)
		}
	}
	dry = New(Options{Env: "test", DryRun: true, Confirm: Confirm{All: true}, Keeper: keeper})
	if res := dry.Run(t.Context(), dry.Prepare(t.Context(), f, 0)); res.Confirm != nil {
		t.Errorf("a dry run with every request confirmed: %+v", res.Confirm)
	}
	if g := got(); len(g) != 3 {
		t.Errorf("a dry run sent %q", g[3:])
	}
}
