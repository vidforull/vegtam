package exec

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// traced sends a GET to u with c and returns its trace, which a failure
// has too.
func traced(t *testing.T, c *Client, u string) *Trace {
	t.Helper()
	_, tr, _ := c.Do(t.Context(), prepared(http.MethodGet, lit(u), nil), testSecrets)
	if tr == nil {
		t.Fatal("no trace")
	}
	return tr
}

// TestTrace checks the phases of a request over TLS, then of one on the
// same connection. localhost resolves to ::1 first here, where nothing
// listens: Happy Eyeballs then connects to 127.0.0.1, and the trace has
// the connection that won.
func TestTrace(t *testing.T) {
	p := newPKI(t)
	srv := p.server(t, tls.NoClientCert, http.NotFoundHandler())
	u := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	c := New(Options{MaxBody: 1 << 20, Transport: Transport{TLS: TLS{Roots: p.pool()}}})
	first, again := traced(t, c, u).Hops, traced(t, c, u).Hops
	if len(first) != 1 || len(again) != 1 {
		t.Fatalf("hops %+v, %+v", first, again)
	}
	h := first[0]
	ordered := slices.IsSorted([]int64{0, int64(h.DNS), int64(h.Connect), int64(h.TLSDone), int64(h.FirstByte), int64(h.Total)})
	switch {
	case h.DNS == 0 || !ordered || h.Reused:
		t.Errorf("first: %+v; want each phase, in order, on a new connection", h)
	case h.RemoteAddr != srv.Listener.Addr().String() || h.Status != http.StatusNotFound || h.Redirect:
		t.Errorf("first: %+v", h)
	case h.TLS == nil || h.TLS.Version != tls.VersionTLS13 || !h.TLS.Verified || h.TLS.ALPN != "http/1.1" || h.TLS.Peer.Subject.CommonName != "server":
		t.Errorf("first TLS: %+v", h.TLS)
	}
	h = again[0]
	switch {
	case !h.Reused || h.DNS != 0 || h.Connect != 0 || h.TLSDone != 0 || h.FirstByte == 0:
		t.Errorf("again: %+v; want a connection used before, and only the first byte", h)
	case h.RemoteAddr != srv.Listener.Addr().String() || h.TLS == nil || !h.TLS.Verified || h.TLS.Peer == nil:
		t.Errorf("again: %+v, TLS %+v; want those of the connection", h, h.TLS)
	}
}

// TestTraceHTTP2 checks that a request on an HTTP/2 connection used
// before says so.
func TestTraceHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	c := New(Options{MaxBody: 1 << 20, Transport: Transport{TLS: TLS{Roots: roots}}})
	first, again := traced(t, c, srv.URL).Hops[0], traced(t, c, srv.URL).Hops[0]
	if first.Reused || first.TLS.ALPN != "h2" || !again.Reused || again.TLS.ALPN != "h2" || again.Connect != 0 {
		t.Errorf("first %+v, again %+v", first, again)
	}
}

// TestTraceRedirects follows a redirect within the origin, then one to
// another server: each hop is traced, and the second redirect says which
// headers did not go on.
func TestTraceRedirects(t *testing.T) {
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next", http.StatusFound)
		} else {
			http.Redirect(w, r, other.URL+"/end", http.StatusTemporaryRedirect)
		}
	}))
	defer srv.Close()
	p := prepared(http.MethodGet, lit(srv.URL+"/start"), nil,
		header("Authorization", append(lit("Bearer "), secret("token")...)), header("X-Key", secret("$env KEY")), header("X-Plain", lit("1")))
	_, tr, err := New(Options{MaxBody: 1 << 20}).Do(t.Context(), p, testSecrets)
	if err != nil || len(tr.Hops) != 3 {
		t.Fatalf("Do: %+v, %v", tr, err)
	}
	type hop struct {
		url, location string
		status        int
		redirect      bool
		dropped       []string
		reused        bool
	}
	want := []hop{
		{srv.URL + "/start", "/next", http.StatusFound, true, nil, false},
		{srv.URL + "/next", other.URL + "/end", http.StatusTemporaryRedirect, true, []string{"Authorization", "X-Key"}, true},
		{other.URL + "/end", "", http.StatusNotFound, false, nil, false},
	}
	for i, h := range tr.Hops {
		got := hop{h.URL.String(), h.Location, h.Status, h.Redirect, h.Dropped, h.Reused}
		if got.url != want[i].url || got.location != want[i].location || got.status != want[i].status ||
			got.redirect != want[i].redirect || !slices.Equal(got.dropped, want[i].dropped) || got.reused != want[i].reused {
			t.Errorf("hop %d = %+v, want %+v", i, got, want[i])
		}
	}
	if tr.Total < tr.Hops[0].Total+tr.Hops[1].Total {
		t.Errorf("total %s, less than the hops before the last", tr.Total)
	}
}

// TestTraceFailures checks what the trace of a request that fails says:
// a redirect refused, no connection, a certificate of an unknown CA.
func TestTraceFailures(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	p := newPKI(t)
	downgrade := p.server(t, tls.NoClientCert, http.RedirectHandler(plain.URL, http.StatusFound))
	c := New(Options{MaxBody: 1 << 20, Transport: Transport{TLS: TLS{Roots: p.pool()}}})
	if h := traced(t, c, downgrade.URL).Hops; len(h) != 1 || !h[0].Redirect || h[0].Location != plain.URL || h[0].Status != http.StatusFound {
		t.Errorf("refused redirect: %+v", h)
	}
	if h := traced(t, c, down.URL).Hops; len(h) != 1 || h[0].RemoteAddr != "" || h[0].Connect != 0 || h[0].Status != 0 {
		t.Errorf("no connection: %+v", h)
	}
	h := traced(t, New(Options{}), downgrade.URL).Hops
	if len(h) != 1 || h[0].TLS == nil || h[0].TLS.Verified || h[0].TLS.Peer == nil || h[0].TLS.Peer.Issuer.CommonName != "vegtam test CA" {
		t.Errorf("unknown CA: %+v; want the server's certificate, not verified", h)
	}
}

// TestTraceProxy checks that the proxy a request goes through is traced,
// and that the address is the proxy's.
func TestTraceProxy(t *testing.T) {
	var target string
	proxy := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { target = r.URL.String() }))
	defer proxy.Close()
	u, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("me", "pr0xy")
	c := New(Options{MaxBody: 1 << 20})
	c.proxy = func(*http.Request) (*url.URL, error) { return u, nil }
	// Not a host that resolves: only the proxy is connected to.
	h := traced(t, c, "http://127.0.0.1:1/x").Hops[0]
	if h.Proxy == nil || h.Proxy.String() != u.String() || h.RemoteAddr != proxy.Listener.Addr().String() || target != "http://127.0.0.1:1/x" {
		t.Errorf("hop %+v through %v; the proxy got %q", h, h.Proxy, target)
	}
}

// TestTraceTLSProxy checks that the TLS of an https proxy is not taken for
// the server's: the request goes over http, and has none.
func TestTraceTLSProxy(t *testing.T) {
	var target string
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { target = r.URL.String() }))
	defer proxy.Close()
	roots := x509.NewCertPool()
	roots.AddCert(proxy.Certificate())
	via, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := New(Options{MaxBody: 1 << 20, Transport: Transport{TLS: TLS{Roots: roots}}})
	c.proxy = func(*http.Request) (*url.URL, error) { return via, nil }
	h := traced(t, c, "http://127.0.0.1:1/x").Hops[0]
	if target != "http://127.0.0.1:1/x" || h.TLS != nil || h.TLSDone != 0 || h.RemoteAddr != proxy.Listener.Addr().String() {
		t.Errorf("hop %+v, TLS %+v; the proxy got %q", h, h.TLS, target)
	}
}
