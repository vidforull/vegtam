package exec

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
)

type secrets map[string]string

func (s secrets) SecretValue(sec core.Secret) (string, error) {
	if v, ok := s[sec.Name]; ok {
		return v, nil
	}
	return "", errors.New("no secret " + sec.Name)
}

var testSecrets = secrets{"token": "t0ken", "$env KEY": "k3y"}

func lit(s string) core.Text       { return core.Text{{Text: s}} }
func secret(name string) core.Text { return core.Text{{Secret: &core.Secret{Name: name}}} }
func header(name string, v core.Text) core.PreparedHeader {
	return core.PreparedHeader{Name: name, Value: v}
}

func prepared(method string, url core.Text, body core.Text, headers ...core.PreparedHeader) *core.Prepared {
	return &core.Prepared{
		Request: &core.Request{Source: core.Source{File: "t.http", Line: 1}},
		Method:  method, URL: url, Body: body, Headers: headers,
	}
}

func do(t *testing.T, opts Options, p *core.Prepared) (*Response, error) {
	t.Helper()
	if opts.MaxBody == 0 {
		opts.MaxBody = 1 << 20
	}
	return New(opts).Do(t.Context(), p, testSecrets)
}

func TestDo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Seen", fmt.Sprintf("%s %s %s %s %s", r.Method, r.Host, r.URL, r.UserAgent(), r.Header.Get("Authorization")))
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "body=%s", body)
	}))
	defer srv.Close()
	p := prepared("POST", lit(srv.URL+"/items?a=1"), core.Text{{Text: "token="}, {Secret: &core.Secret{Name: "token"}}},
		header("Authorization", core.Text{{Text: "Bearer "}, {Secret: &core.Secret{Name: "$env KEY"}}}),
		header("Host", lit("api.example.test")))
	r, err := do(t, Options{UserAgent: "vegtam/test"}, p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != 201 || r.Reason != "Created" || r.Proto != "HTTP/1.1" || string(r.Body) != "body=token=t0ken" ||
		r.Header.Get("X-Seen") != "POST api.example.test /items?a=1 vegtam/test Bearer k3y" || r.Truncated || r.Duration <= 0 {
		t.Errorf("response = %+v", r)
	}
}

func TestMaxBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 100))
	}))
	defer srv.Close()
	for _, tt := range []struct {
		max       int64
		size      int
		truncated bool
	}{{10, 10, true}, {99, 99, true}, {100, 100, false}, {1 << 20, 100, false}, {math.MaxInt64, 100, false}} {
		r, err := do(t, Options{MaxBody: tt.max}, prepared("GET", lit(srv.URL), nil))
		if err != nil || len(r.Body) != tt.size || r.Truncated != tt.truncated {
			t.Errorf("MaxBody %d: %d bytes, truncated %v, %v; want %d, %v", tt.max, len(r.Body), r.Truncated, err, tt.size, tt.truncated)
		}
	}
}

// The chain is A/start -> A/same -> B/end -> A/back: secrets and the
// Referer reach A/same, and neither B nor A once the chain has left A.
func TestRedirectDropsSecrets(t *testing.T) {
	seen := map[string]http.Header{}
	var a, b *httptest.Server
	record := func(next string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			seen[r.URL.Path] = r.Header.Clone()
			if next != "" {
				http.Redirect(w, r, next+"?"+r.URL.RawQuery, http.StatusFound)
			}
		}
	}
	muxA, muxB := http.NewServeMux(), http.NewServeMux()
	a, b = httptest.NewServer(muxA), httptest.NewServer(muxB)
	defer a.Close()
	defer b.Close()
	muxA.HandleFunc("/start", record("/same"))
	muxA.HandleFunc("/same", func(w http.ResponseWriter, r *http.Request) { record(b.URL+"/end")(w, r) })
	muxB.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) { record(a.URL+"/back")(w, r) })
	muxA.HandleFunc("/back", record(""))

	p := prepared("GET", core.Text{{Text: a.URL + "/start?key="}, {Secret: &core.Secret{Name: "token"}}}, nil,
		header("Authorization", secret("token")),
		header("Cookie", lit("session=abc")),
		header("X-Api-Key", secret("$env KEY")),
		header("Accept", lit("application/json")))
	if r, err := do(t, Options{}, p); err != nil || r.Status != 200 {
		t.Fatalf("Do = %v, %v", r, err)
	}
	if h := seen["/same"]; h.Get("Authorization") != "t0ken" || h.Get("Cookie") != "session=abc" || h.Get("X-Api-Key") != "k3y" {
		t.Errorf("same origin lost headers: %v", h)
	}
	// net/http would send the URL redirected from, with the token in its
	// query, as the Referer, on the same origin too.
	if _, ok := seen["/same"]["Referer"]; ok {
		t.Errorf("same origin: Referer %q", seen["/same"].Get("Referer"))
	}
	for _, path := range []string{"/end", "/back"} {
		h := seen[path]
		if h.Get("Accept") != "application/json" {
			t.Errorf("%s: plain header dropped: %v", path, h)
		}
		for _, name := range []string{"Authorization", "Cookie", "X-Api-Key", "Referer"} {
			if v := h.Get(name); v != "" {
				t.Errorf("%s: %s = %q followed a redirect to another origin", path, name, v)
			}
		}
	}

	// A Referer of the request's own goes as far as its origin.
	clear(seen)
	p.Headers = append(p.Headers, header("Referer", lit("https://app.example.test/page")))
	if r, err := do(t, Options{}, p); err != nil || r.Status != 200 {
		t.Fatalf("Do = %v, %v", r, err)
	}
	if got := seen["/same"].Get("Referer"); got != "https://app.example.test/page" {
		t.Errorf("same origin: the request's Referer became %q", got)
	}
	if got := seen["/end"].Get("Referer"); got != "" {
		t.Errorf("another origin: Referer %q", got)
	}
}

func TestRedirectLimit(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if n := r.URL.Query().Get("n"); n != "0" {
			left, _ := strconv.Atoi(n)
			http.Redirect(w, r, fmt.Sprintf("/?n=%d", left-1), http.StatusFound)
		}
	}))
	defer srv.Close()
	if r, err := do(t, Options{}, prepared("GET", lit(srv.URL+"/?n=10"), nil)); err != nil || r.Status != 200 || hits != 11 {
		t.Errorf("10 redirects: %v, %v after %d requests", r, err, hits)
	}
	_, err := do(t, Options{}, prepared("GET", lit(srv.URL+"/?n=11"), nil))
	if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != core.KindNetwork || !strings.Contains(e.Msg, "stopped after 10 redirects") {
		t.Errorf("11 redirects: error = %v", err)
	}
}

// A redirect from https to http is refused anywhere in the chain, with or
// without secrets: the plain server never hears of the request.
func TestRedirectDowngrade(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { plainHits.Add(1) }))
	defer plain.Close()
	var secure *httptest.Server
	secure = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, secure.URL+"/same", http.StatusFound) // https to https: followed
		case "/same":
			http.Redirect(w, r, plain.URL+"/down", http.StatusFound)
		}
	}))
	defer secure.Close()
	roots := x509.NewCertPool()
	roots.AddCert(secure.Certificate())
	opts := Options{TLS: &tls.Config{RootCAs: roots}}
	for _, p := range []*core.Prepared{
		prepared(http.MethodGet, lit(secure.URL+"/start"), nil),
		prepared(http.MethodGet, lit(secure.URL+"/start"), nil, header("Authorization", secret("token"))),
	} {
		_, err := do(t, opts, p)
		if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != core.KindNetwork || !strings.Contains(e.Msg, "refused a redirect from https to http") {
			t.Errorf("error = %v, want the redirect to http refused", err)
		}
	}
	if n := plainHits.Load(); n != 0 {
		t.Errorf("the plain server got %d requests", n)
	}
	// The other way is fine.
	up := httptest.NewServer(http.RedirectHandler(secure.URL+"/same-no-more", http.StatusFound))
	defer up.Close()
	if r, err := do(t, opts, prepared(http.MethodGet, lit(up.URL), nil)); err != nil || r.Status != http.StatusOK {
		t.Errorf("http to https: %v, %v", r, err)
	}
}

// A 307 or 308 sends the body again: to another origin, a body that holds
// a secret is refused. A 302 turns the POST into a GET without a body, and
// a body without secrets may follow.
func TestRedirectSecretBody(t *testing.T) {
	var mu sync.Mutex
	var got []string // what the other origin received
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		got = append(got, r.Method+" "+string(b))
	}))
	defer other.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, _ := strconv.Atoi(r.URL.Query().Get("code"))
		http.Redirect(w, r, other.URL, code)
	}))
	defer first.Close()
	secretBody := core.Text{{Text: "password="}, {Secret: &core.Secret{Name: "token"}}}
	tests := []struct {
		code int
		body core.Text
		want string // what the other origin receives; "" if the redirect is refused
	}{
		{http.StatusTemporaryRedirect, secretBody, ""},
		{http.StatusPermanentRedirect, secretBody, ""},
		{http.StatusFound, secretBody, "GET "},
		{http.StatusTemporaryRedirect, lit("plain"), "POST plain"},
	}
	for _, tt := range tests {
		mu.Lock()
		got = nil
		mu.Unlock()
		_, err := do(t, Options{}, prepared(http.MethodPost, lit(first.URL+"/?code="+strconv.Itoa(tt.code)), tt.body))
		mu.Lock()
		seen := strings.Join(got, "\n")
		mu.Unlock()
		switch {
		case tt.want == "" && (err == nil || !strings.Contains(err.Error(), "the body holds a secret") || seen != ""):
			t.Errorf("%d, %s: %v; the other origin got %q", tt.code, tt.body.Masked(), err, seen)
		case tt.want != "" && (err != nil || seen != tt.want):
			t.Errorf("%d, %s: %v; the other origin got %q, want %q", tt.code, tt.body.Masked(), err, seen, tt.want)
		}
	}
}

func TestHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	r, err := do(t, Options{TLS: &tls.Config{RootCAs: roots}}, prepared("GET", lit(srv.URL), nil))
	if err != nil || r.Proto != "HTTP/2.0" {
		t.Errorf("Do = %+v, %v; want HTTP/2.0", r, err)
	}
}

func TestErrors(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	tests := []struct {
		name string
		p    *core.Prepared
		kind core.Kind
		want string
	}{
		{"connection refused", prepared("GET", lit(closed.URL), nil), core.KindNetwork, "connect"},
		{"timeout", prepared("GET", lit(slow.URL), nil), core.KindTimeout, "no complete response within 50ms"},
		{"scheme", prepared("GET", lit("ftp://example.com/"), nil), core.KindRequest, "want an http or https URL"},
		{"no host", prepared("GET", lit("http:///path"), nil), core.KindRequest, "has no host"},
		{
			"bad URL", prepared("GET", core.Text{{Text: "http://a b/"}, {Secret: &core.Secret{Name: "token"}}}, nil),
			core.KindRequest, `invalid URL http://a b/{{token}}: invalid character " " in host name`,
		},
		{
			"line break", prepared("GET", lit("http://example.com"), nil, header("X", lit("a\r\nb"))),
			core.KindRequest, "header X: the value contains a line break",
		},
		{
			"control character", prepared("GET", lit("http://example.com"), nil, header("X", lit("a\x01b"))),
			core.KindRequest, "header X: the value contains a line break or another control character",
		},
		{
			"Host", prepared("GET", lit("http://example.com"), nil, header("Host", lit("a/b"))),
			core.KindRequest, `header Host: invalid host "a/b"`,
		},
		{"missing secret", prepared("GET", secret("nope"), nil), core.KindVariable, "no secret nope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := do(t, Options{Timeout: 50 * time.Millisecond}, tt.p)
			if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != tt.kind || !strings.Contains(e.Error(), "t.http:1: ") ||
				!strings.Contains(e.Msg, tt.want) {
				t.Errorf("error = %v; want %s error with %q", err, tt.kind, tt.want)
			}
			// Check finds the same errors, short of sending.
			wantCheck := tt.kind != core.KindNetwork && tt.kind != core.KindTimeout
			if err := New(Options{}).Check(t.Context(), tt.p, testSecrets); (err != nil) != wantCheck {
				t.Errorf("Check = %v, want an error: %v", err, wantCheck)
			}
		})
	}
}

// lateSecrets are the secrets of a dry run: "late" is known only when the
// request is sent.
type lateSecrets struct{ secrets }

func (s lateSecrets) SecretValue(sec core.Secret) (string, error) {
	if sec.Name == "late" {
		return "", core.ErrLate
	}
	return s.secrets.SecretValue(sec)
}

func TestCheckLate(t *testing.T) {
	late := lateSecrets{testSecrets}
	tests := []struct {
		name string
		p    *core.Prepared
		want string // "" for no error
	}{
		{"late URL", prepared("GET", secret("late"), nil), ""},
		{"late host and header", prepared("GET", core.Text{{Text: "https://"}, {Secret: &core.Secret{Name: "late"}}}, secret("late"),
			header("Authorization", core.Text{{Text: "Bearer "}, {Secret: &core.Secret{Name: "late"}}}), header("Host", secret("late"))), ""},
		{
			"the rest is checked", prepared("GET", secret("late"), nil, header("X", secret("late")), header("Y", lit("a\nb"))),
			"header Y: the value contains a line break",
		},
		{"URL with a late part", prepared("GET", core.Text{{Text: "ftp://example.com/"}, {Secret: &core.Secret{Name: "late"}}}, nil), ""},
		{"late body", prepared("POST", lit("https://example.com/"), core.Text{{Text: "t="}, {Secret: &core.Secret{Name: "late"}}}), ""},
		{"bad URL", prepared("GET", lit("ftp://example.com/"), nil, header("X", secret("late"))), "want an http or https URL"},
	}
	for _, tt := range tests {
		err := New(Options{}).Check(t.Context(), tt.p, late)
		if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s: Check = %v, want %q", tt.name, err, tt.want)
		}
	}
	// Sending needs the value.
	_, err := New(Options{}).Do(t.Context(), prepared("GET", secret("late"), nil), late)
	if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != core.KindVariable {
		t.Errorf("Do = %v, want a variable error", err)
	}
}

// net/http quotes the URL in its errors; no secret value may reach a
// core.Error through it, through a redirect URL or through a host or port.
func TestErrorsHideSecrets(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, closed.URL+"/next?"+r.URL.RawQuery, http.StatusFound)
	}))
	defer redirect.Close()
	query := core.Text{{Text: "/?key="}, {Secret: &core.Secret{Name: "token"}}, {Text: "&k="}, {Secret: &core.Secret{Name: "$env KEY"}}}
	at := func(base string) core.Text { return append(lit(base), query...) }
	port := func(v string) secrets { return secrets{"port": v} }
	base := func(v string) secrets { return secrets{"base": v} }
	withPort := core.Text{{Text: "http://127.0.0.1:"}, {Secret: &core.Secret{Name: "port"}}}
	tests := []struct {
		name    string
		p       *core.Prepared
		secrets secrets
		kind    core.Kind
		want    string
	}{
		{
			"connection refused", prepared("GET", at(closed.URL), nil), testSecrets, core.KindNetwork,
			`Get "` + closed.URL + `/?key={{token}}&k={{$env KEY}}": dial tcp`,
		},
		{
			"timeout", prepared("GET", at(slow.URL), nil), testSecrets, core.KindTimeout,
			`Get "` + slow.URL + `/?key={{token}}&k={{$env KEY}}": `,
		},
		{
			"redirect", prepared("GET", at(redirect.URL), nil), testSecrets, core.KindNetwork,
			`Get "` + closed.URL + `/next?key=***&k=***": dial tcp`,
		},
		{"port when dialling", prepared("GET", withPort, nil), port("99999"), core.KindNetwork, "address ***: invalid port"},
		{
			"port in the URL", prepared("GET", withPort, nil), port("8o8o"), core.KindRequest,
			`invalid URL http://127.0.0.1:{{port}}: invalid port "***" after host`,
		},
		// A secret base URL: the host and port alone must not show either.
		{
			"base URL refused", prepared("GET", append(secret("base"), lit("/v1")...), nil),
			base(closed.URL), core.KindNetwork, `Get "{{base}}/v1": dial tcp ***: connect: connection refused`,
		},
		{
			"base URL with a bad port", prepared("GET", append(secret("base"), lit("/v1")...), nil),
			base("http://int.example.test:12ab"), core.KindRequest, `invalid URL {{base}}/v1: invalid port "***" after host`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Options{Timeout: 100 * time.Millisecond, MaxBody: 1}).Do(t.Context(), tt.p, tt.secrets)
			e, ok := errors.AsType[*core.Error](err)
			if !ok || e.Kind != tt.kind || !strings.Contains(e.Msg, tt.want) {
				t.Fatalf("error = %v; want %s error with %q", err, tt.kind, tt.want)
			}
			for _, v := range tt.secrets {
				parts := []string{v}
				if u, err := url.Parse(v); err == nil && u.Host != "" {
					parts = append(parts, u.Host, u.Port())
				}
				for _, part := range parts {
					if strings.Contains(e.Error(), part) {
						t.Errorf("error %q holds %q from the secret value %q", e, part, v)
					}
				}
			}
		})
	}
}
