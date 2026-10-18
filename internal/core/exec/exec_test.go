package exec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
)

type secrets map[string]string

func (s secrets) SecretValue(name string) (string, error) {
	if v, ok := s[name]; ok {
		return v, nil
	}
	return "", errors.New("no secret " + name)
}

var testSecrets = secrets{"token": "t0ken", "$env KEY": "k3y"}

func lit(s string) core.Text       { return core.Text{{Text: s}} }
func secret(name string) core.Text { return core.Text{{Secret: &core.Secret{Name: name}}} }
func header(name string, v core.Text) core.PreparedHeader {
	return core.PreparedHeader{Name: name, Value: v}
}

func prepared(method string, url core.Text, body core.Text, headers ...core.PreparedHeader) *core.Prepared {
	return &core.Prepared{Request: &core.Request{Source: core.Source{File: "t.http", Line: 1}},
		Method: method, URL: url, Body: body, Headers: headers}
}

func do(t *testing.T, opts Options, p *core.Prepared) (*Response, error) {
	t.Helper()
	if opts.MaxBody == 0 {
		opts.MaxBody = 1 << 20
	}
	return New(opts).Do(context.Background(), p, testSecrets)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", 100))
	}))
	defer srv.Close()
	for _, tt := range []struct {
		max       int64
		size      int
		truncated bool
	}{{10, 10, true}, {99, 99, true}, {100, 100, false}, {1 << 20, 100, false}} {
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
	if h := seen["/same"]; h.Get("Authorization") != "t0ken" || h.Get("Cookie") != "session=abc" ||
		h.Get("X-Api-Key") != "k3y" || !strings.Contains(h.Get("Referer"), "key=t0ken") {
		t.Errorf("same origin lost headers: %v", h)
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
}

func TestRedirectLimit(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if n := r.URL.Query().Get("n"); n != "0" {
			var left int
			fmt.Sscan(n, &left)
			http.Redirect(w, r, fmt.Sprintf("/?n=%d", left-1), http.StatusFound)
		}
	}))
	defer srv.Close()
	if r, err := do(t, Options{}, prepared("GET", lit(srv.URL+"/?n=10"), nil)); err != nil || r.Status != 200 || hits != 11 {
		t.Errorf("10 redirects: %v, %v after %d requests", r, err, hits)
	}
	_, err := do(t, Options{}, prepared("GET", lit(srv.URL+"/?n=11"), nil))
	if e, ok := err.(*core.Error); !ok || e.Kind != core.KindNetwork || !strings.Contains(e.Msg, "stopped after 10 redirects") {
		t.Errorf("11 redirects: error = %v", err)
	}
}

func TestHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
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
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		{"bad URL", prepared("GET", core.Text{{Text: "http://a b/"}, {Secret: &core.Secret{Name: "token"}}}, nil),
			core.KindRequest, `invalid URL http://a b/{{token}}: invalid character " " in host name`},
		{"line break", prepared("GET", lit("http://example.com"), nil, header("X", lit("a\r\nb"))),
			core.KindRequest, "header X: the value contains a line break"},
		{"missing secret", prepared("GET", secret("nope"), nil), core.KindVariable, "no secret nope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := do(t, Options{Timeout: 50 * time.Millisecond}, tt.p)
			if e, ok := err.(*core.Error); !ok || e.Kind != tt.kind || !strings.Contains(e.Error(), "t.http:1: ") ||
				!strings.Contains(e.Msg, tt.want) {
				t.Errorf("error = %v; want %s error with %q", err, tt.kind, tt.want)
			}
		})
	}
}
