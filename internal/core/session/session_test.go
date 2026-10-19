package session

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/output"
)

const token = "s1gn/in+t0ken"

// newFile writes a sign-in and a request that needs its token, and the
// environment file for a server that checks the token.
func newFile(t *testing.T) *core.File {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"token": %q}`, token)
	})
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
		}
		fmt.Fprintf(w, `{"echo": %q}`, r.Header.Get("Authorization"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	src := "# @name login\n# @capture token = $.token\nPOST {{host}}/login\n\n###\n# @name me\nGET {{host}}/me\nAuthorization: Bearer {{token}}\n"
	files := map[string]string{"api.http": src, "http-client.env.json": `{"test": {"host": "` + srv.URL + `"}}`}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := httpfile.ParseFile(filepath.Join(dir, "api.http"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestCapturesCarryOver sends the requests one at a time, each prepared
// just before it is sent, as the terminal interface does: the token one
// request captures is sent by the next, and masked in its response.
func TestCapturesCarryOver(t *testing.T) {
	f := newFile(t)
	s := New(Options{Env: "test", MaxBody: 1 << 20})
	login := s.Run(t.Context(), s.Prepare(t.Context(), f, 0))
	if login.Error != nil || len(login.Captures) != 1 {
		t.Fatalf("login = %+v, error %+v", login, login.Error)
	}
	me := s.Run(t.Context(), s.Prepare(t.Context(), f, 1))
	if me.Error != nil || me.Response.Status != http.StatusOK {
		t.Fatalf("me = %+v, error %+v", me.Response, me.Error)
	}
	if got := me.Request.Headers[0].Value; got != "Bearer {{token}}" {
		t.Errorf("request header = %q, want the placeholder", got)
	}
	if strings.Contains(me.Response.Body, token) || !strings.Contains(me.Response.Body, "Bearer ***") {
		t.Errorf("response body = %s, want the token masked", me.Response.Body)
	}
}

// TestPreview checks a dry run that declares what a session has: the
// captured variable is a placeholder rather than unresolved.
func TestPreview(t *testing.T) {
	f := newFile(t)
	s := New(Options{Env: "test", MaxBody: 1 << 20})
	s.Run(t.Context(), s.Prepare(t.Context(), f, 0))
	if got := s.Declared(); len(got) != 1 || got[0] != "token" {
		t.Fatalf("Declared() = %q, want [token]", got)
	}

	fresh := New(Options{Env: "test", DryRun: true})
	if res := fresh.Run(t.Context(), fresh.Prepare(t.Context(), f, 1)); res.Error == nil || res.Error.Kind != core.KindVariable {
		t.Errorf("without the declaration: error %+v, want kind variable", res.Error)
	}

	preview := New(Options{Env: "test", DryRun: true})
	preview.Declare(s.Declared()...)
	j := preview.Prepare(t.Context(), f, 1)
	res := preview.Run(t.Context(), j)
	if res.Error != nil || res.Response != nil {
		t.Fatalf("preview = %+v, error %+v; want the request only", res, res.Error)
	}
	if got := output.Sent(j.Prepared, preview.Masker()).Headers[0].Value; got != "Bearer {{token}}" {
		t.Errorf("preview header = %q, want the placeholder", got)
	}
	if j.Class(core.Ref{Name: "token"}) != env.Captured || j.Class(core.Ref{Name: "host"}) != env.Plain {
		t.Errorf("classes of the preview: token %v, host %v", j.Class(core.Ref{Name: "token"}), j.Class(core.Ref{Name: "host"}))
	}
}

// TestPreviewLost checks that a preview which forgets what the session
// lost fails as sending would, and that a dry run of a whole file, in
// which nothing is captured, loses nothing.
func TestPreviewLost(t *testing.T) {
	f := newFile(t)
	path := filepath.Join(filepath.Dir(f.Path), "lost.http")
	src := "# @name login\n# @capture token = $.token\nGET {{host}}/me\n\n###\n# @name me\nGET {{host}}/me\nAuthorization: Bearer {{token}}\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	lf, err := httpfile.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Options{Env: "test", MaxBody: 1 << 20})
	if login := s.Run(t.Context(), s.Prepare(t.Context(), lf, 0)); len(login.Captures) != 0 {
		t.Fatalf("login captured %+v", login.Captures)
	}
	if got := s.Lost(); len(got) != 1 || got["token"] != path+"#login" {
		t.Fatalf("Lost() = %v", got)
	}
	sent := s.Run(t.Context(), s.Prepare(t.Context(), lf, 1))

	preview := New(Options{Env: "test", DryRun: true})
	preview.Declare(s.Declared()...)
	for name, ref := range s.Lost() {
		preview.Forget(name, ref)
	}
	res := preview.Run(t.Context(), preview.Prepare(t.Context(), lf, 1))
	if res.Error == nil || sent.Error == nil || res.Request != nil || !reflect.DeepEqual(res.Error, sent.Error) ||
		!strings.Contains(res.Error.Message, "not captured: token ("+path+"#login took no value)") {
		t.Errorf("preview error %+v, request %+v; sending gave %+v", res.Error, res.Request, sent.Error)
	}

	dry := New(Options{Env: "test", DryRun: true})
	jobs, err := dry.Jobs(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range jobs {
		if res := dry.Run(t.Context(), j); res.Error != nil {
			t.Errorf("dry run of %s: %+v", j.Ref, res.Error)
		}
	}
	if got := dry.Lost(); len(got) != 0 {
		t.Errorf("a dry run lost %v", got)
	}
}

// TestCurl checks that a dry run gives a request that it can send as a
// curl command, with what is captured as a shell variable, and the error
// it would give for one it cannot.
func TestCurl(t *testing.T) {
	f := newFile(t)
	s := New(Options{Env: "test", DryRun: true})
	if _, err := s.Curl(t.Context(), s.Prepare(t.Context(), f, 1), nil); err == nil {
		t.Error("Curl with token unresolved: no error")
	}
	s.Declare("token")
	cmd, err := s.Curl(t.Context(), s.Prepare(t.Context(), f, 1), nil)
	if err != nil || !strings.HasPrefix(cmd, "# Set first: token for {{token}} from an @capture\n: \"${token?}\" && curl --path-as-is 'http://") ||
		!strings.HasSuffix(cmd, "/me' \\\n  -H 'Authorization: Bearer '\"$token\"\n") {
		t.Errorf("Curl = %q, %v", cmd, err)
	}
	s.Forget("token", "api.http#login")
	if _, err = s.Curl(t.Context(), s.Prepare(t.Context(), f, 1), nil); err == nil || !strings.Contains(err.Error(), "not captured: token") {
		t.Errorf("Curl after the capture lost token: %v", err)
	}
}

// TestHistory checks what the history keeps of the runs of a session: a
// request sent, as written, and how it ended; nothing of a dry run, and
// nothing of a request with @no-log.
func TestHistory(t *testing.T) {
	f := newFile(t)
	dir := filepath.Dir(f.Path)
	src := "# @name quiet\n# @no-log\nGET {{host}}/me?t={{token}}\n\n###\nGET {{host}}/x/{{nothing}}\n"
	if err := os.WriteFile(filepath.Join(dir, "more.http"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	more, err := httpfile.ParseFile(filepath.Join(dir, "more.http"))
	if err != nil {
		t.Fatal(err)
	}
	log := history.New(filepath.Join(t.TempDir(), "vegtam"))
	t.Chdir(dir)
	s := New(Options{Env: "test", MaxBody: 1 << 20, History: log})
	for _, r := range []struct {
		f *core.File
		i int
	}{{f, 0}, {more, 0}, {more, 1}, {f, 1}} {
		s.Run(t.Context(), s.Prepare(t.Context(), r.f, r.i))
	}
	dry := New(Options{Env: "test", DryRun: true, History: log})
	dry.Run(t.Context(), dry.Prepare(t.Context(), f, 0))
	if err = s.HistoryError(); err != nil {
		t.Fatal(err)
	}

	got, err := log.Last(10)
	if err != nil {
		t.Fatal(err)
	}
	type kept struct{ ref, env, method, url, result string }
	var have []kept
	for _, e := range got {
		have = append(have, kept{e.Ref, e.Env, e.Method, e.URL, e.Result})
		if e.Time.Location() != time.UTC || time.Since(e.Time) > time.Minute || e.DurationMS < 0 || e.Status != 0 && e.DurationMS == 0 || e.Truncated {
			t.Errorf("%s: time %v, duration %v, truncated %v", e.Ref, e.Time, e.DurationMS, e.Truncated)
		}
	}
	abs, _ := filepath.Abs(f.Path)
	want := []kept{
		{abs + "#me", "test", "GET", "{{host}}/me", "ok"},
		{filepath.Join(dir, "more.http") + "#2", "test", "GET", "{{host}}/x/{{nothing}}", "variable"},
		{abs + "#login", "test", "POST", "{{host}}/login", "ok"},
	}
	if !reflect.DeepEqual(have, want) {
		t.Errorf("history:\n%+v\nwant\n%+v", have, want)
	}
	// One that could not be resolved was never sent: no status.
	if got[0].Status != http.StatusOK || got[1].Status != 0 {
		t.Errorf("statuses %d, %d", got[0].Status, got[1].Status)
	}

	// A history that cannot be written does not stop the run, and says why.
	blocked := filepath.Join(t.TempDir(), "file")
	if err = os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s = New(Options{Env: "test", MaxBody: 1 << 20, History: history.New(filepath.Join(blocked, "vegtam"))})
	if res := s.Run(t.Context(), s.Prepare(t.Context(), f, 0)); res.Error != nil || s.HistoryError() == nil {
		t.Errorf("with no place for the history: %+v, %v", res.Error, s.HistoryError())
	}
}
