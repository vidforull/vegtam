package session

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
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
}
