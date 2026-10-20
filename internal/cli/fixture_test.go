package cli

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
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
	cookieSecret  = "S3ss10n/c00k+ie" // the session /login hands out
)

// fixture is a copy of testdata/cli with environment files for the
// environment "test", and the server its requests go to.
type fixture struct {
	dir    string
	host   string
	hidden string // the base URL in the private file, as localhost:port
	live   string // another one, as localhost:port, where a server answers
	ca     string // a PEM file with the certificate of the TLS servers
	// config is vegtam's configuration directory, of the trust store and
	// the policy, which allows the servers of the tests: a run without a
	// person at a terminal connects to loopback only as it allows.
	config string

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
	live := httptest.NewServer(fx.handler())
	t.Cleanup(live.Close)
	// localhost, not 127.0.0.1 as the other servers: masking the secret
	// host must not hide them.
	local := func(u string) string {
		return strings.Replace(strings.TrimPrefix(u, "http://"), "127.0.0.1", "localhost", 1)
	}
	fx.host, fx.hidden, fx.live = srv.URL, local(hidden.URL), local(live.URL)
	if err := os.CopyFS(fx.dir, os.DirFS("../../testdata/cli")); err != nil {
		t.Fatal(err)
	}
	// TLS servers, one of which wants a client certificate, any one. Their
	// failed handshakes are logged by net/http unless told otherwise.
	secure, mtls := httptest.NewUnstartedServer(fx.handler()), httptest.NewUnstartedServer(fx.handler())
	mtls.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	for _, s := range []*httptest.Server{secure, mtls} {
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		s.StartTLS()
		t.Cleanup(s.Close)
	}
	// A server that takes connections and says nothing: no TLS handshake.
	silent, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	quiet := make(chan struct{})
	t.Cleanup(func() {
		close(quiet)
		if err := silent.Close(); err != nil {
			t.Error(err)
		}
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				<-quiet
				if err := c.Close(); err != nil {
					t.Error(err)
				}
			})
		}
	})
	fx.config = writePolicy(t, loopbackPolicy)
	fx.ca = filepath.Join(fx.dir, "ca.pem")
	if err := os.WriteFile(fx.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	envs := map[string]map[string]map[string]string{
		"http-client.env.json": {"test": {
			"host": srv.URL, "closed": closed.URL, "tls": secure.URL, "mtls": mtls.URL, "silent": silent.Addr().String(),
		}},
		"http-client.private.env.json": {"test": {"token": privateSecret, "base": "http://" + fx.hidden, "live": "http://" + fx.live}},
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

// loopbackPolicy allows the servers of the tests, on loopback.
const loopbackPolicy = `{"network": {"allow": ["127.0.0.1", "::1"]}}`

// setPolicy makes the fixture's policy say doc until the test ends.
func setPolicy(t *testing.T, fx *fixture, doc string) {
	t.Helper()
	path := filepath.Join(fx.config, "policy.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(path, []byte(loopbackPolicy), 0o600); err != nil {
			t.Error(err)
		}
	})
}

// writePolicy makes a configuration directory, private as vegtam wants it
// (t.TempDir is group-writable where the umask is 0002), with a policy
// file that says doc; XDG_CONFIG_HOME points to it. It returns vegtam's
// directory in it.
func writePolicy(t *testing.T, doc string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, "vegtam")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", home)
	return dir
}

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
	// The session comes as a cookie and in the body; /me echoes the
	// cookies it gets.
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "session="+cookieSecret+"; Path=/; HttpOnly")
		w.Header().Add("Set-Cookie", "lang=en; Path=/")
		fmt.Fprintf(w, `{"session": %q}`, cookieSecret)
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cookie", r.Header.Get("Cookie"))
		fmt.Fprintf(w, `{"cookie": %q}`, r.Header.Get("Cookie"))
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/echo?"+r.URL.RawQuery, http.StatusFound)
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
