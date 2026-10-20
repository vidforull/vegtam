package exec

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"

	"github.com/vidforull/vegtam/internal/core/netguard"
)

// socketServer starts a server of the tests on the unix socket at path,
// which records the Host of each request.
func socketServer(t *testing.T, path string) *[]string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var hosts []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hosts = append(hosts, r.Host)
	}))
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return &hosts
}

// TestUnixSocket sends to a server on a unix socket: the host of the URL
// goes in Host, the guard has no address to refuse, and no proxy is used.
func TestUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	hosts := socketServer(t, path)
	c := New(Options{MaxBody: 1, Transport: Transport{Socket: path, Guard: netguard.Rules{Unattended: true}}})
	c.proxy = func(*http.Request) (*url.URL, error) { return url.Parse("http://127.0.0.1:1") }
	_, trace, err := c.Do(t.Context(), prepared(http.MethodGet, lit("http://docker/v1.43/info"), nil), testSecrets)
	if err != nil {
		t.Fatal(err)
	}
	h := trace.Hops[0]
	if h.ResolvedBy != "--unix-socket" || h.RemoteAddr != path || h.Proxy != nil || len(*hosts) != 1 || (*hosts)[0] != "docker" {
		t.Errorf("hop %+v; the server saw %q", h, *hosts)
	}
}
