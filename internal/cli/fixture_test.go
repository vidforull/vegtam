package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The secrets of the CLI tests: one from the private environment file,
// one from the process environment. "/" and "+" give them distinct URL-
// and JSON-escaped forms.
const (
	privateSecret = "Pr1vT0k/en+x"
	envSecret     = "EnvK3y/v+al"
)

// fixture is a copy of testdata/cli with environment files for the
// environment "test", and the server its requests go to.
type fixture struct {
	dir    string
	host   string
	hidden string // the base URL in the private file, as localhost:port

	mu   sync.Mutex
	seen []string // the raw queries the server received
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	fx := &fixture{dir: t.TempDir()}
	srv := httptest.NewServer(fx.handler())
	t.Cleanup(srv.Close)
	closed, hidden := httptest.NewServer(http.NotFoundHandler()), httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	hidden.Close()
	// localhost, not 127.0.0.1 as the other servers: masking the secret
	// host must not hide them.
	fx.host, fx.hidden = srv.URL, strings.Replace(strings.TrimPrefix(hidden.URL, "http://"), "127.0.0.1", "localhost", 1)
	if err := os.CopyFS(fx.dir, os.DirFS("../../testdata/cli")); err != nil {
		t.Fatal(err)
	}
	envs := map[string]map[string]map[string]string{
		"http-client.env.json":         {"test": {"host": srv.URL, "closed": closed.URL}},
		"http-client.private.env.json": {"test": {"token": privateSecret, "base": "http://" + fx.hidden}},
	}
	for name, v := range envs {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(fx.dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VEGTAM_TEST_KEY", envSecret)
	return fx
}

func (fx *fixture) path(name string) string { return filepath.Join(fx.dir, name) }

// handler serves the requests of testdata/cli. /echo and /fail send the
// request back: as JSON, as JSON with "/" escaped as PHP does and "+" as
// .NET does, URL-escaped, with the query decoded, and in a header.
func (fx *fixture) handler() http.Handler {
	echo := func(status int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			e, _ := json.Marshal(map[string]string{
				"query": r.URL.RawQuery, "escaped": url.QueryEscape(r.URL.RawQuery),
				"authorization": r.Header.Get("Authorization"), "api_key": r.Header.Get("X-Api-Key"), "body": string(body),
				"key": r.URL.Query().Get("key"),
			})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Echo", r.URL.RawQuery)
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"echo": %s, "php": %s, "dotnet": %s}`, e,
				strings.ReplaceAll(string(e), "/", `\/`), strings.ReplaceAll(string(e), "+", `\u002B`))
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", echo(http.StatusOK))
	mux.HandleFunc("/fail", echo(http.StatusInternalServerError))
	mux.HandleFunc("/slow", func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "\xff\xfe"+r.URL.RawQuery+"\x00")
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 100)+strings.TrimPrefix(r.URL.RawQuery, "key="))
	})
	// Each hop goes to a new URL, so that the error names one that is not
	// the request's: the secrets in it are found by their values.
	mux.HandleFunc("/hops/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x?"+r.URL.RawQuery, http.StatusFound)
	})
	mux.HandleFunc("/hops", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/hops/x?"+r.URL.RawQuery, http.StatusFound)
	})
	mux.HandleFunc("/plain", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "plain\x1b]0;title\x07 \u202etext\u200b")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.mu.Lock()
		fx.seen = append(fx.seen, r.URL.RawQuery)
		fx.mu.Unlock()
		w.Header().Set("Date", "Mon, 19 Oct 2026 00:00:00 GMT")
		mux.ServeHTTP(w, r)
	})
}

// decode unmarshals the JSON document s into v.
func decode(t *testing.T, s string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatalf("%v in %s", err, s)
	}
}
