package exec

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
)

// originsServer is a server that records what it gets and counts the
// connections it accepts: a request refused before it is sent makes none.
type originsServer struct {
	*httptest.Server
	conns atomic.Int32
	mu    sync.Mutex
	got   []string // each request: its URL, then its Authorization header and its body
}

func newOriginsServer(t *testing.T, h http.HandlerFunc) *originsServer {
	t.Helper()
	s := &originsServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.got = append(s.got, r.URL.String()+" "+r.Header.Get("Authorization")+" "+string(b))
		s.mu.Unlock()
		if h != nil {
			h(w, r)
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

// policyError returns err as an error of kind policy for a secret, or
// fails the test.
func policyError(t *testing.T, err error) *core.Error {
	t.Helper()
	e, ok := errors.AsType[*core.Error](err)
	if !ok || e.Kind != core.KindPolicy || e.Secret == nil {
		t.Fatalf("error = %v, want one of kind policy for a secret", err)
	}
	return e
}

// TestOriginsFirstHop checks that a request that holds a secret not bound
// to where it goes is refused before anything is sent, wherever the
// secret is: the server never hears of it.
func TestOriginsFirstHop(t *testing.T) {
	trap := newOriginsServer(t, nil)
	const elsewhere = "https://api.example.test"
	s := secrets{"token": "t0ken", "user": "alice", "password": "pa55"}
	auth := func(v ...core.Segment) core.PreparedHeader { return header("Authorization", v) }
	for _, tt := range []struct {
		name string
		p    *core.Prepared
		want string // the first secret refused
	}{
		{"query", prepared(http.MethodGet, core.Text{{Text: trap.URL + "/?t="}, {Secret: &core.Secret{Name: "token"}}}, nil), "{{token}}"},
		{"path", prepared(http.MethodGet, core.Text{{Text: trap.URL + "/items/"}, {Secret: &core.Secret{Name: "token"}}}, nil), "{{token}}"},
		{"header", prepared(http.MethodGet, lit(trap.URL), nil, header("X-Api-Key", secret("token"))), "{{token}}"},
		{"body", prepared(http.MethodPost, lit(trap.URL), core.Text{{Text: `{"t": "`}, {Secret: &core.Secret{Name: "token"}}, {Text: `"}`}}), "{{token}}"},
		{"Basic", prepared(http.MethodGet, lit(trap.URL), nil, auth(core.Segment{Text: "Basic "}, core.Segment{Secret: &core.Secret{Name: "user"}},
			core.Segment{Text: " "}, core.Segment{Secret: &core.Secret{Name: "password"}})), "{{user}}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, tr, err := New(Options{MaxBody: 1 << 20}).Do(t.Context(), tt.p, s.to(elsewhere))
			e := policyError(t, err)
			if r != nil || tr != nil {
				t.Errorf("response %+v, trace %+v; want nothing sent", r, tr)
			}
			if e.Secret.Name != tt.want || e.Secret.Origin != trap.URL || !slices.Equal(e.Secret.Allowed, []string{elsewhere}) || e.Secret.Capture {
				t.Errorf("secret %+v", e.Secret)
			}
			if want := tt.p.Method + " " + tt.p.URL.Masked() + " is not sent: secret " + tt.want + " may not go to " + trap.URL; !strings.HasPrefix(e.Msg, want) {
				t.Errorf("message %q, want it to start with %q", e.Msg, want)
			}
			for _, v := range s {
				if strings.Contains(e.Error(), v) {
					t.Errorf("the secret value %q in %q", v, e)
				}
			}
		})
	}
	// Bound to nothing, a secret goes nowhere.
	_, _, err := New(Options{MaxBody: 1 << 20}).Do(t.Context(), prepared(http.MethodGet, lit(trap.URL), nil, header("X-Api-Key", secret("token"))), s)
	if e := policyError(t, err); len(e.Secret.Allowed) != 0 || !strings.Contains(e.Msg, "it is bound to no origin") {
		t.Errorf("a secret bound to none: %+v", e)
	}
	// Basic with one of its two secrets bound there is refused for the
	// other one.
	each := boundEach{secrets: s, origins: map[string][]string{"user": {trap.URL}, "password": {elsewhere}}}
	basic := prepared(http.MethodGet, lit(trap.URL), nil, auth(core.Segment{Text: "Basic "}, core.Segment{Secret: &core.Secret{Name: "user"}},
		core.Segment{Text: " "}, core.Segment{Secret: &core.Secret{Name: "password"}}))
	_, _, err = New(Options{MaxBody: 1 << 20}).Do(t.Context(), basic, each)
	if e := policyError(t, err); e.Secret.Name != "{{password}}" {
		t.Errorf("Basic with the user bound there: %+v", e.Secret)
	}
	if n := trap.conns.Load(); n != 0 {
		t.Errorf("the server took %d connections, got %q", n, trap.requests())
	}
	// Both bound there, it goes.
	each.origins["password"] = []string{trap.URL}
	if r, _, err := New(Options{MaxBody: 1 << 20}).Do(t.Context(), basic, each); err != nil || r.Status != http.StatusOK {
		t.Fatalf("Basic with both bound there: %v, %v", r, err)
	}
	if got := trap.requests(); len(got) != 1 || got[0] != "/ Basic YWxpY2U6cGE1NQ== " {
		t.Errorf("the server got %q", got)
	}
}

// boundEach are secrets each bound to origins of its own.
type boundEach struct {
	secrets
	origins map[string][]string
}

func (b boundEach) SecretOrigins(s core.Secret) []string { return b.origins[s.Name] }

// TestOriginsRedirect checks the redirects of a request whose URL holds a
// secret: to an origin the secret is not bound to, the redirect is
// refused before it is followed, as an open redirect would send the query
// on; one that the secret may go to is followed. A secret in a header is
// dropped on the way to another origin, as before, and the redirect is
// followed.
func TestOriginsRedirect(t *testing.T) {
	b := newOriginsServer(t, nil)
	a := newOriginsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, b.URL+"/stolen?"+r.URL.RawQuery, http.StatusFound)
		case "/here":
			http.Redirect(w, r, "/landed?"+r.URL.RawQuery, http.StatusFound)
		}
	})
	inQuery := func(path string) *core.Prepared {
		return prepared(http.MethodGet, core.Text{{Text: a.URL + path + "?t="}, {Secret: &core.Secret{Name: "token"}}}, nil)
	}
	c := New(Options{MaxBody: 1 << 20})

	_, tr, err := c.Do(t.Context(), inQuery("/away"), testSecrets.to(a.URL))
	e := policyError(t, err)
	if e.Secret.Name != "{{token}}" || e.Secret.Origin != b.URL || !slices.Equal(e.Secret.Allowed, []string{a.URL}) ||
		!strings.HasPrefix(e.Msg, "refused a redirect to "+b.URL+" of a URL that holds a secret: secret {{token}} may not go to "+b.URL) ||
		strings.Contains(e.Error(), "t0ken") {
		t.Errorf("redirect to another origin: %+v", e)
	}
	if tr == nil || len(tr.Hops) != 1 || tr.Hops[0].Status != http.StatusFound {
		t.Errorf("trace %+v, want the hop to a alone", tr)
	}
	if n := b.conns.Load(); n != 0 {
		t.Fatalf("the other origin took %d connections, got %q", n, b.requests())
	}

	// Within the origin it is bound to, the redirect is followed.
	r, _, err := c.Do(t.Context(), inQuery("/here"), testSecrets.to(a.URL))
	if err != nil || r.Status != http.StatusOK || !slices.Equal(r.Origins, []string{a.URL}) {
		t.Errorf("redirect within the origin: %+v, %v", r, err)
	}
	// Bound to the other origin too, it goes there.
	r, _, err = c.Do(t.Context(), inQuery("/away"), testSecrets.to(a.URL, b.URL))
	if err != nil || !slices.Equal(r.Origins, []string{b.URL}) {
		t.Fatalf("redirect to an origin it may go to: %+v, %v", r, err)
	}
	if got := b.requests(); len(got) != 1 || got[0] != "/stolen?t=t0ken  " {
		t.Errorf("the other origin got %q", got)
	}

	// A secret in a header alone: followed, the header dropped.
	p := prepared(http.MethodGet, lit(a.URL+"/away?plain=1"), nil, header("Authorization", append(lit("Bearer "), secret("token")...)))
	r, tr, err = c.Do(t.Context(), p, testSecrets.to(a.URL))
	if err != nil || !slices.Equal(r.Origins, []string{b.URL}) || !slices.Equal(tr.Hops[0].Dropped, []string{"Authorization"}) {
		t.Fatalf("a secret header: %+v, %+v, %v", r, tr, err)
	}
	if got := b.requests(); len(got) != 2 || got[1] != "/stolen?plain=1  " {
		t.Errorf("the other origin got %q", got)
	}
}

// TestOriginsGrant checks what a person's confirmation gives: the request
// goes to the origin confirmed with a secret bound elsewhere, and a
// redirect to another origin with the secret in its URL is still refused.
func TestOriginsGrant(t *testing.T) {
	b := newOriginsServer(t, nil)
	a := newOriginsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/away" {
			http.Redirect(w, r, b.URL+"/stolen?"+r.URL.RawQuery, http.StatusFound)
		}
	})
	c := New(Options{MaxBody: 1 << 20})
	s := core.Grant(testSecrets.to("https://api.example.test"), a.URL)
	at := func(path string) *core.Prepared {
		return prepared(http.MethodGet, core.Text{{Text: a.URL + path + "?t="}, {Secret: &core.Secret{Name: "token"}}}, nil,
			header("X-Key", secret("$env KEY")))
	}
	if r, _, err := c.Do(t.Context(), at("/"), s); err != nil || r.Status != http.StatusOK {
		t.Fatalf("granted: %+v, %v", r, err)
	}
	_, _, err := c.Do(t.Context(), at("/away"), s)
	if e := policyError(t, err); e.Secret.Origin != b.URL || !slices.Equal(e.Secret.Allowed, []string{a.URL, "https://api.example.test"}) {
		t.Errorf("granted, redirected: %+v", e.Secret)
	}
	if n := b.conns.Load(); n != 0 {
		t.Errorf("the other origin took %d connections", n)
	}
	if got := a.requests(); len(got) != 2 || got[0] != "/?t=t0ken  " {
		t.Errorf("a got %q", got)
	}
}

// TestOriginsResponse checks that a response says the origin it came
// from: that of the last hop.
func TestOriginsResponse(t *testing.T) {
	b := newOriginsServer(t, nil)
	a := newOriginsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/away" {
			http.Redirect(w, r, b.URL+"/end", http.StatusFound)
		}
	})
	for path, want := range map[string]string{"/": a.URL, "/away": b.URL} {
		if r, err := do(t, Options{}, prepared(http.MethodGet, lit(a.URL+path), nil)); err != nil || !slices.Equal(r.Origins, []string{want}) {
			t.Errorf("%s: %+v, %v; want the origin %s", path, r, err, want)
		}
	}
	// As core.Origin writes it: in lower case.
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(a.URL, "http://"))
	if r, err := do(t, Options{}, prepared(http.MethodGet, lit("http://LOCALHOST:"+port+"/"), nil)); err != nil || !slices.Equal(r.Origins, []string{"http://localhost:" + port}) {
		t.Errorf("by name: %+v, %v", r, err)
	}
}

// TestOriginsHostHeader checks that a Host header that names another
// host is a second origin of the request: a server that routes by it, as
// a CDN does, would take the secret there. Bound to the origin of the URL
// alone, the request is refused before anything is sent; bound to both,
// it goes. A Host header that names the URL's own host is none.
func TestOriginsHostHeader(t *testing.T) {
	a := newOriginsServer(t, nil)
	auth := header("Authorization", append(lit("Bearer "), secret("token")...))
	p := prepared(http.MethodGet, lit(a.URL+"/x"), nil, auth, header("Host", lit("Exfil.example")))
	_, err := do(t, Options{}, p, a.URL)
	if e := policyError(t, err); e.Secret.Origin != "http://exfil.example" || !slices.Equal(e.Secret.Allowed, []string{a.URL}) {
		t.Errorf("bound to the origin of the URL alone: %+v", e.Secret)
	}
	if n := a.conns.Load(); n != 0 {
		t.Fatalf("the server took %d connections: %q", n, a.requests())
	}
	if r, err := do(t, Options{}, p, a.URL, "http://exfil.example"); err != nil || !slices.Equal(r.Origins, []string{a.URL, "http://exfil.example"}) {
		t.Errorf("bound to both: %+v, %v", r, err)
	}
	same := prepared(http.MethodGet, lit(a.URL+"/x"), nil, auth, header("Host", lit(strings.TrimPrefix(a.URL, "http://"))))
	if r, err := do(t, Options{}, same, a.URL); err != nil || !slices.Equal(r.Origins, []string{a.URL}) {
		t.Errorf("a Host header of the URL's host: %+v, %v", r, err)
	}
}
