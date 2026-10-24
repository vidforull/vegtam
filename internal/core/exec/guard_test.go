package exec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/netguard"
)

func allow(t *testing.T, list ...string) []netguard.Entry {
	t.Helper()
	var es []netguard.Entry
	for _, s := range list {
		e, err := netguard.ParseEntry(s)
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, e)
	}
	return es
}

// hostOf returns the host and port of a test server's URL.
func hostOf(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "http://") }

// isPolicy reports whether err is an error of kind policy that says want.
func isPolicy(err error, want string) bool { return isKind(err, core.KindPolicy, want) }

// isUsage reports whether err is an error of kind usage that says want.
func isUsage(err error, want string) bool { return isKind(err, core.KindUsage, want) }

func isKind(err error, k core.Kind, want string) bool {
	e, ok := errors.AsType[*core.Error](err)
	return ok && e.Kind == k && strings.Contains(e.Msg, want)
}

// TestGuard sends to a server on loopback: with a person at a terminal;
// without one, refused unless the policy allows it; and a redirect from
// an allowed address to one that is not. An address the guard refuses
// never reaches the dialer's next control, which would fail the test
// rather than connect: on a cloud's machine, 169.254.169.254 answers.
func TestGuard(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	other := httptest.NewServer(http.RedirectHandler(srv.URL+"/moved", http.StatusFound))
	defer other.Close()
	_, port, _ := net.SplitHostPort(hostOf(srv))
	tests := []struct {
		name  string
		guard netguard.Rules
		url   string
		want  string // the error of kind policy; "" for none
		hits  int32
	}{
		{"a person", netguard.Rules{}, srv.URL, "", 1},
		{"alone", netguard.Rules{Unattended: true}, srv.URL, "address " + hostOf(srv) + " is private (loopback), and no person is at a terminal; allow it in policy: network.allow", 0},
		{"alone, the address allowed", netguard.Rules{Unattended: true, Allow: allow(t, "127.0.0.1")}, srv.URL, "", 1},
		{"alone, the address and port allowed", netguard.Rules{Unattended: true, Allow: allow(t, hostOf(srv))}, srv.URL, "", 1},
		{"alone, the name allowed", netguard.Rules{Unattended: true, Allow: allow(t, "localhost:"+port)}, "http://localhost:" + port, "", 1},
		{"alone, another port allowed", netguard.Rules{Unattended: true, Allow: allow(t, "127.0.0.1:1")}, srv.URL, "is private", 0},
		{"alone, a redirect to an address not allowed", netguard.Rules{Unattended: true, Allow: allow(t, hostOf(other))}, other.URL, "address " + hostOf(srv) + " is private", 0},
		{"a cloud's metadata", netguard.Rules{}, "http://169.254.169.254/latest/meta-data/", "address 169.254.169.254:80 is a cloud metadata address, which vegtam never connects to", 0},
		{"a cloud's metadata, allowed", netguard.Rules{Unattended: true, Allow: allow(t, "169.254.0.0/16")}, "http://169.254.169.254/", "never connects", 0},
		{"unspecified", netguard.Rules{}, "http://0.0.0.0:" + port, "address 0.0.0.0:" + port + " is unspecified", 0},
	}
	for _, tt := range tests {
		hits.Store(0)
		c := New(Options{MaxBody: 1, Transport: Transport{Guard: tt.guard}})
		c.control = func(_ context.Context, _, address string, _ syscall.RawConn) error {
			if ap, err := netip.ParseAddrPort(address); err != nil || !ap.Addr().IsLoopback() {
				t.Errorf("%s: the guard let %s through", tt.name, address)
				return errors.New("not connected: a test")
			}
			return nil
		}
		_, _, err := c.Do(t.Context(), prepared(http.MethodGet, lit(tt.url), nil), testSecrets)
		switch {
		case tt.want == "" && err != nil, tt.want != "" && !isPolicy(err, tt.want):
			t.Errorf("%s: %v; want %q", tt.name, err, tt.want)
		case hits.Load() != tt.hits:
			t.Errorf("%s: the server got %d requests, want %d", tt.name, hits.Load(), tt.hits)
		}
	}
}

// TestGuardEveryConnection checks that each connection is checked, not
// only the first one to a host: a client that got through once does not
// keep a pass.
func TestGuardEveryConnection(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	var dials atomic.Int32
	c := New(Options{MaxBody: 1, Transport: Transport{Guard: netguard.Rules{Unattended: true, Allow: allow(t, "127.0.0.1")}}})
	c.control = func(context.Context, string, string, syscall.RawConn) error {
		dials.Add(1)
		return nil
	}
	for range 2 {
		if _, _, err := c.Do(t.Context(), prepared(http.MethodGet, lit(srv.URL), nil, header("Connection", lit("close"))), testSecrets); err != nil {
			t.Fatal(err)
		}
	}
	if dials.Load() != 2 {
		t.Errorf("%d connections checked, want 2", dials.Load())
	}
}

// TestGuardSecretHost checks that the error of a host from a secret hides
// it, and its address, which would tell it.
func TestGuardSecretHost(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	_, port, _ := net.SplitHostPort(hostOf(srv))
	s := secrets{"base": "http://localhost:" + port}.to("http://localhost:" + port)
	_, _, err := New(Options{MaxBody: 1, Transport: Transport{Guard: netguard.Rules{Unattended: true}}}).Do(t.Context(), prepared(http.MethodGet, append(secret("base"), lit("/x")...), nil), s)
	if !isPolicy(err, "address *** is private") {
		t.Fatalf("%v; want the address hidden", err)
	}
	for _, part := range []string{"localhost", "127.0.0.1", port} {
		if strings.Contains(err.Error(), part) {
			t.Errorf("%q in %v", part, err)
		}
	}
}

// TestGuardProxy checks the target of a request that goes to a proxy,
// which connects to it where the dialer does not see: before anything
// goes to the proxy.
func TestGuardProxy(t *testing.T) {
	var got atomic.Value
	got.Store("")
	proxy := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got.Store(r.URL.String()) }))
	defer proxy.Close()
	via, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	res := tableResolver{
		"api.example.test": {"93.184.216.34"}, "inside.example.test": {"10.1.2.3"}, "meta.example.test": {"169.254.169.254"},
		"xn--80ajuz.example.test": {"169.254.169.254"}, "blocked.example.test": {"0.0.0.0"},
	}
	alone := netguard.Rules{Unattended: true}
	tests := []struct {
		name  string
		guard netguard.Rules
		url   string
		want  string // the error of kind policy; "" for none, and the proxy gets the request
	}{
		{"public", alone, "http://api.example.test/x", ""},
		{"metadata", netguard.Rules{}, "http://169.254.169.254/latest", "address 169.254.169.254:80 is a cloud metadata address"},
		{"metadata, by a name", netguard.Rules{}, "http://meta.example.test/latest", "address 169.254.169.254:80 is a cloud metadata address"},
		// Forms the resolver here does not read, and a proxy may.
		{"metadata, as one number", netguard.Rules{}, "http://2852039166/latest", "address 169.254.169.254:80 is a cloud metadata address"},
		{"metadata, in octal", netguard.Rules{}, "http://0251.0376.0251.0376/latest", "address 169.254.169.254:80 is a cloud metadata address"},
		{"metadata, by a name not in ASCII", netguard.Rules{}, "http://мета.example.test/latest", "is a cloud metadata address"}, // its address hidden: see hide
		{"private, with a person", netguard.Rules{}, "http://inside.example.test/x", ""},
		{"private, alone", alone, "http://inside.example.test/x", "address 10.1.2.3:80 is private"},
		{"private, alone, allowed", netguard.Rules{Unattended: true, Allow: allow(t, "inside.example.test:80")}, "http://inside.example.test/x", ""},
		{"unknown here, with a person", netguard.Rules{}, "http://elsewhere.example.test/x", ""},
		{"unknown here, alone", alone, "http://elsewhere.example.test/x", "cannot check the address of elsewhere.example.test:80 through the proxy"},
		{"blocked here, alone", alone, "http://blocked.example.test/x", "only to an unspecified address"},
	}
	for _, tt := range tests {
		got.Store("")
		c := New(Options{MaxBody: 1, Transport: Transport{Guard: tt.guard}})
		c.proxy, c.resolver = func(*http.Request) (*url.URL, error) { return via, nil }, res
		_, _, err := c.Do(t.Context(), prepared(http.MethodGet, lit(tt.url), nil), testSecrets)
		switch {
		case tt.want == "" && (err != nil || got.Load() != tt.url):
			t.Errorf("%s: %v; the proxy got %q, want %q", tt.name, err, got.Load(), tt.url)
		case tt.want != "" && (!isPolicy(err, tt.want) || got.Load() != ""):
			t.Errorf("%s: %v, the proxy got %q; want %q and nothing sent", tt.name, err, got.Load(), tt.want)
		}
	}
	// The proxy, on loopback, is connected to as the proxy, and only so:
	// a request to its address goes direct, and is refused.
	c := New(Options{MaxBody: 1, Transport: Transport{Guard: alone, Proxy: func(r *http.Request) (*url.URL, error) {
		if r.URL.Host == hostOf(proxy) {
			return nil, nil // as net/http's ProxyFromEnvironment does for loopback
		}
		return via, nil
	}}})
	c.resolver = res
	if _, _, err := c.Do(t.Context(), prepared(http.MethodGet, lit("http://api.example.test/"), nil), testSecrets); err != nil {
		t.Errorf("through the transport's proxy: %v", err)
	}
	if _, _, err := c.Do(t.Context(), prepared(http.MethodGet, lit(proxy.URL+"/admin"), nil), testSecrets); !isPolicy(err, "address "+hostOf(proxy)+" is private") {
		t.Errorf("to the proxy's address, not through it: %v", err)
	}
}

// TestGuardProxyLookup checks the lookup of the target of a request that
// goes to a proxy: within the time of getting a connection, and out of
// the hop's trace, whose lookup it is not.
func TestGuardProxyLookup(t *testing.T) {
	proxy := httptest.NewServer(http.NotFoundHandler())
	defer proxy.Close()
	via, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	var traced, limited atomic.Bool
	c := New(Options{MaxBody: 1, Transport: Transport{Connect: 5 * time.Second}})
	c.proxy = func(*http.Request) (*url.URL, error) { return via, nil }
	c.resolver = resolverFunc(func(ctx context.Context, _ string) ([]netip.Addr, error) {
		_, ok := ctx.Deadline()
		traced.Store(httptrace.ContextClientTrace(ctx) != nil)
		limited.Store(ok)
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	_, trace, err := c.Do(t.Context(), prepared(http.MethodGet, lit("http://api.example.test/"), nil), testSecrets)
	if err != nil || traced.Load() || !limited.Load() || trace.Hops[0].DNS != 0 {
		t.Errorf("%v: traced %v, limited %v, DNS %v", err, traced.Load(), limited.Load(), trace.Hops[0].DNS)
	}
}

// TestInsecureProxy checks that a request whose certificate --insecure
// leaves unchecked does not go through an https proxy, whose certificate
// net/http would leave unchecked too, and with it the proxy's
// credentials.
func TestInsecureProxy(t *testing.T) {
	via, err := url.Parse("https://vegtam:pr0xy-p4ss@127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range []Transport{{TLS: TLS{Insecure: true}}, {InsecureOrigins: []string{"https://api.example.test:443"}}} {
		c := New(Options{MaxBody: 1, Transport: tr})
		c.proxy, c.resolver = func(*http.Request) (*url.URL, error) { return via, nil }, tableResolver{"api.example.test": {"93.184.216.34"}}
		if _, _, err := c.Do(t.Context(), prepared(http.MethodGet, lit("https://api.example.test/"), nil), testSecrets); !isUsage(err, "--insecure would leave its certificate unchecked too") {
			t.Errorf("%+v: %v", tr, err)
		}
	}
}

// TestGuardProxyLookupTimeout checks that a target that gets no answer to
// its lookup within the connect timeout is a timeout of that phase, not a
// refusal of the guard's.
func TestGuardProxyLookupTimeout(t *testing.T) {
	via, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	c := New(Options{MaxBody: 1, Transport: Transport{Connect: 50 * time.Millisecond, Guard: netguard.Rules{Unattended: true}}})
	c.proxy = func(*http.Request) (*url.URL, error) { return via, nil }
	c.resolver = resolverFunc(func(ctx context.Context, host string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, &net.DNSError{Err: "timeout", Name: host, IsTimeout: true}
	})
	_, _, err = c.Do(t.Context(), prepared(http.MethodGet, lit("http://slow.example.test/"), nil), testSecrets)
	e, ok := errors.AsType[*core.Error](err)
	if !ok || e.Kind != core.KindTimeout || e.Phase != core.PhaseConnect || !strings.Contains(e.Msg, "no answer to the lookup of the target, which vegtam checks before the proxy, within 50ms (connect timeout)") {
		t.Errorf("%v", err)
	}
}

// resolverFunc is a resolver of the tests.
type resolverFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	return f(ctx, host)
}

// tableResolver answers lookups from a table, for the tests that go
// through a proxy: no name of theirs is looked up in the DNS.
type tableResolver map[string][]string

func (r tableResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	list, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var ips []netip.Addr
	for _, s := range list {
		ips = append(ips, netip.MustParseAddr(s))
	}
	return ips, nil
}
