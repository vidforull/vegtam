package exec

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// connectProxy is a proxy of the tests that tunnels CONNECT, as a
// company's does, or answers it with refuse; a request that is not
// CONNECT it answers itself, with the Proxy-Authorization it got in the
// body. It records what each request asked and the Proxy-Authorization
// it had.
type connectProxy struct {
	*httptest.Server
	refuse int // the status of CONNECT; 0 tunnels

	mu    sync.Mutex
	asked []string // method and target of each request
	auth  []string // its Proxy-Authorization
	conns []net.Conn
	errs  []error // of the tunnels, but for closed connections
	wg    sync.WaitGroup
}

func newConnectProxy(t *testing.T, refuse int) *connectProxy {
	t.Helper()
	p := &connectProxy{refuse: refuse}
	p.Server = httptest.NewUnstartedServer(http.HandlerFunc(p.serve))
	p.Config.ErrorLog = log.New(io.Discard, "", 0)
	p.Start()
	t.Cleanup(func() {
		p.Close()
		p.mu.Lock()
		for _, c := range p.conns {
			shut(c)
		}
		p.mu.Unlock()
		p.wg.Wait()
		for _, err := range p.errs {
			t.Logf("the proxy's tunnel: %v", err)
		}
	})
	return p
}

// shut closes c, a connection that may be closed already.
func shut(c io.Closer) { c.Close() }

// pipe copies from to to, and closes to once from is done.
func (p *connectProxy) pipe(to, from net.Conn) {
	if _, err := io.Copy(to, from); err != nil && !errors.Is(err, net.ErrClosed) {
		p.mu.Lock()
		p.errs = append(p.errs, err)
		p.mu.Unlock()
	}
	shut(to)
}

func (p *connectProxy) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.asked = append(p.asked, r.Method+" "+r.RequestURI)
	p.auth = append(p.auth, r.Header.Get("Proxy-Authorization"))
	p.mu.Unlock()
	switch {
	case r.Method != http.MethodConnect:
		fmt.Fprintf(w, `{"proxy_authorization": %q}`, r.Header.Get("Proxy-Authorization"))
		return
	case p.refuse != 0:
		w.Header().Set("Proxy-Authenticate", `Basic realm="tests"`)
		w.WriteHeader(p.refuse)
		return
	}
	dst, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijacking", http.StatusInternalServerError)
		shut(dst)
		return
	}
	src, _, err := hj.Hijack()
	if err != nil {
		shut(dst)
		return
	}
	p.mu.Lock()
	p.conns = append(p.conns, src, dst)
	p.mu.Unlock()
	if _, err := io.WriteString(src, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	p.wg.Go(func() { p.pipe(dst, src) })
	p.pipe(src, dst)
}

// TestProxyCredentials checks that the user and password of a proxy go to
// the proxy alone: on CONNECT, and never through the tunnel to the
// server; and that a proxy that refuses CONNECT, as for wrong
// credentials, ends the request, with nothing sent to the server.
func TestProxyCredentials(t *testing.T) {
	p := newPKI(t)
	var mu sync.Mutex
	var got []string // the Proxy-Authorization of each request the server got
	srv := p.server(t, tls.NoClientCert, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, r.Header.Get("Proxy-Authorization"))
	}))
	send := func(proxy *connectProxy) error {
		via, err := url.Parse(proxy.URL)
		if err != nil {
			t.Fatal(err)
		}
		via.User = url.UserPassword("vegtam", "pr0xy-p4ss")
		c := New(Options{MaxBody: 1, Transport: Transport{TLS: TLS{Roots: p.pool()}}})
		c.proxy = func(*http.Request) (*url.URL, error) { return via, nil }
		_, _, err = c.Do(t.Context(), prepared(http.MethodGet, lit(srv.URL+"/x"), nil, header("Connection", lit("close"))), testSecrets)
		return err
	}
	const basic = "Basic dmVndGFtOnByMHh5LXA0c3M=" // vegtam:pr0xy-p4ss
	tunnel := newConnectProxy(t, 0)
	if err := send(tunnel); err != nil {
		t.Fatal(err)
	}
	refusing := newConnectProxy(t, http.StatusProxyAuthRequired)
	if err := send(refusing); err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
		t.Errorf("a proxy that refuses CONNECT: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(got, []string{""}) {
		t.Errorf("the server got %q; want one request, without Proxy-Authorization", got)
	}
	for _, proxy := range []*connectProxy{tunnel, refusing} {
		proxy.mu.Lock()
		if !slices.Equal(proxy.auth, []string{basic}) || len(proxy.asked) != 1 || !strings.HasPrefix(proxy.asked[0], "CONNECT ") {
			t.Errorf("the proxy got %q with %q; want one CONNECT with the credentials", proxy.asked, proxy.auth)
		}
		proxy.mu.Unlock()
	}
}
