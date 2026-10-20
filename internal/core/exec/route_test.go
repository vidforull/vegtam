package exec

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vidforull/vegtam/internal/core/netguard"
)

func routes(t *testing.T, resolve, connectTo []string) netguard.Routes {
	t.Helper()
	var r netguard.Routes
	for _, s := range resolve {
		res, err := netguard.ParseResolve(s)
		if err != nil {
			t.Fatal(err)
		}
		r.Resolve = append(r.Resolve, res)
	}
	for _, s := range connectTo {
		c, err := netguard.ParseConnectTo(s)
		if err != nil {
			t.Fatal(err)
		}
		r.ConnectTo = append(r.ConnectTo, c)
	}
	return r
}

// TestRoutes sends to api.example.test, a name that is never looked up,
// at the address --resolve or --connect-to gives: the Host header, the
// SNI and the check of the certificate keep the name, the trace says
// which flag sent the connection there, and the guard checks the address
// connected to.
func TestRoutes(t *testing.T) {
	p := newPKI(t)
	type seen struct{ host, sni string }
	var mu sync.Mutex
	var got []seen
	srv := p.server(t, tls.NoClientCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, seen{r.Host, r.TLS.ServerName})
		mu.Unlock()
		if r.URL.Path == "/away" {
			http.Redirect(w, r, "https://localhost:"+r.URL.Query().Get("port")+"/here", http.StatusFound)
		}
	}))
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	name := "api.example.test:" + port
	tests := []struct {
		name   string
		routes netguard.Routes
		guard  netguard.Rules
		url    string
		by     []string // of each hop
		want   string   // an error; "" for none
	}{
		{"--resolve", routes(t, []string{name + ":127.0.0.1"}, nil), netguard.Rules{}, "https://" + name + "/x", []string{"--resolve"}, ""},
		{"--resolve, more addresses", routes(t, []string{name + ":127.0.0.2,127.0.0.1"}, nil), netguard.Rules{}, "https://" + name + "/x", []string{"--resolve"}, ""},
		{"--connect-to", routes(t, nil, []string{"api.example.test:1:127.0.0.1:" + port}), netguard.Rules{}, "https://api.example.test:1/x", []string{"--connect-to"}, ""},
		{"a redirect to a host it does not route", routes(t, []string{name + ":127.0.0.1"}, nil), netguard.Rules{}, "https://" + name + "/away?port=" + port, []string{"--resolve", ""}, ""},
		{"alone, not allowed", routes(t, []string{name + ":127.0.0.1"}, nil), netguard.Rules{Unattended: true}, "https://" + name + "/x", nil, "address 127.0.0.1:" + port + " is private"},
		{"alone, the name allowed", routes(t, []string{name + ":127.0.0.1"}, nil), netguard.Rules{Unattended: true, Allow: allow(t, name)}, "https://" + name + "/x", []string{"--resolve"}, ""},
		{"to a metadata address", routes(t, []string{"api.example.test:80:169.254.169.254"}, nil), netguard.Rules{}, "http://api.example.test/latest", nil, "never connects"},
	}
	for _, tt := range tests {
		mu.Lock()
		got = nil
		mu.Unlock()
		c := New(Options{MaxBody: 1, Transport: Transport{TLS: TLS{Roots: p.pool()}, Routes: tt.routes, Guard: tt.guard}})
		_, trace, err := c.Do(t.Context(), prepared(http.MethodGet, lit(tt.url), nil), testSecrets)
		if tt.want != "" {
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("%s: %v; want %q", tt.name, err, tt.want)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		var by []string
		for _, h := range trace.Hops {
			by = append(by, h.ResolvedBy)
		}
		mu.Lock()
		first := got[0]
		mu.Unlock()
		host := strings.Split(tt.url, "/")[2]
		if strings.Join(by, " ") != strings.Join(tt.by, " ") || first.host != host || first.sni != "api.example.test" ||
			trace.Hops[0].RemoteAddr != "127.0.0.1:"+port {
			t.Errorf("%s: resolved by %q, the server saw %+v, connected to %s", tt.name, by, first, trace.Hops[0].RemoteAddr)
		}
	}
}

// TestRouteThroughProxy checks that a host that --resolve sends elsewhere
// does not go through a proxy, which would look it up itself: an error,
// with nothing sent.
func TestRouteThroughProxy(t *testing.T) {
	proxy := newConnectProxy(t, 0)
	via, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := New(Options{MaxBody: 1, Transport: Transport{Routes: routes(t, []string{"api.example.test:443:127.0.0.1"}, nil)}})
	c.proxy = func(*http.Request) (*url.URL, error) { return via, nil }
	_, _, err = c.Do(t.Context(), prepared(http.MethodGet, lit("https://api.example.test/x"), nil), testSecrets)
	if !isUsage(err, "--resolve does not apply through a proxy, which looks api.example.test up itself: pass --noproxy api.example.test to go direct") {
		t.Errorf("%v", err)
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if len(proxy.asked) != 0 {
		t.Errorf("the proxy got %q", proxy.asked)
	}
}

// TestRouteNotTheProxy checks that a route that matches the proxy's port
// leaves the connection to the proxy be: the routes are for the hosts of
// requests, and the guard lets the proxy be as the proxy only.
func TestRouteNotTheProxy(t *testing.T) {
	proxy := newConnectProxy(t, 0)
	via, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer backend.Close()
	c := New(Options{MaxBody: 1, Transport: Transport{
		Guard:  netguard.Rules{Unattended: true},
		Routes: routes(t, nil, []string{":" + via.Port() + ":127.0.0.1:" + strings.TrimPrefix(backend.URL, "http://127.0.0.1:")}),
	}})
	c.proxy = func(*http.Request) (*url.URL, error) { return via, nil }
	if _, _, err := c.Do(t.Context(), prepared(http.MethodGet, lit("http://192.0.2.1/x"), nil), testSecrets); err != nil {
		t.Fatal(err)
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if hits.Load() != 0 || len(proxy.asked) != 1 {
		t.Errorf("the backend got %d requests, the proxy %q", hits.Load(), proxy.asked)
	}
}

// TestRouteForms checks that a route matches a port with leading zeros and
// a name not in ASCII as net/http dials them, and that resolved_by says so.
func TestRouteForms(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	c := New(Options{MaxBody: 1, Transport: Transport{Routes: routes(t, []string{"api.example.test:" + port + ":127.0.0.1", "xn--bcher-kva.example.test:" + port + ":127.0.0.1"}, nil)}})
	for _, u := range []string{"http://api.example.test:0" + port + "/x", "http://bücher.example.test:" + port + "/x"} {
		_, trace, err := c.Do(t.Context(), prepared(http.MethodGet, lit(u), nil), testSecrets)
		if err != nil || trace.Hops[0].ResolvedBy != "--resolve" {
			t.Errorf("%s: %v; resolved by %q", u, err, trace.Hops[0].ResolvedBy)
		}
	}
}
