package output

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/exec"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestDiagnose checks the trace of a request whose host is a secret,
// redirected to a public one: the secret host's address is hidden, as are
// the secrets of the Location and the password of the proxy.
func TestDiagnose(t *testing.T) {
	ms := time.Millisecond
	m := core.NewMasker([]string{"http://localhost:8080", "t0ken/x"})
	tr := &exec.Trace{Total: 11 * ms, Hops: []exec.Hop{{
		URL: mustURL(t, "http://localhost:8080/a?key=t0ken%2Fx"), DNS: ms, Connect: 2 * ms, FirstByte: 3 * ms, Total: 4 * ms,
		RemoteAddr: "127.0.0.1:8080", Proxy: mustURL(t, "http://me:pr0xy@proxy.example.test:3128"),
		Status: 302, Location: "https://api.example.test/b?key=t0ken%2Fx", Redirect: true, Dropped: []string{"Authorization"},
	}, {
		URL: mustURL(t, "https://api.example.test/b"), FirstByte: 5 * ms, Total: 6 * ms, Reused: true, RemoteAddr: "192.0.2.1:443", Status: 200,
		TLS: &exec.TLSInfo{Version: tls.VersionTLS13, Cipher: tls.TLS_AES_128_GCM_SHA256, ALPN: "h2", Verified: true, Peer: &x509.Certificate{
			Subject: pkix.Name{CommonName: "api.example.test"}, Issuer: pkix.Name{CommonName: "Test CA", Organization: []string{"Test"}},
			NotAfter: time.Date(2026, 12, 1, 0, 0, 0, 0, time.FixedZone("", 3600)),
		}},
	}}}
	res := &Result{}
	Diagnose(res, tr, m)
	got, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"timing":{"total_ms":11,"name_lookup_ms":1,"connect_ms":2,"start_transfer_ms":8,"reused":false},` +
		`"remote_addr":"192.0.2.1:443",` +
		`"tls":{"version":"TLS 1.3","cipher":"TLS_AES_128_GCM_SHA256","alpn":"h2","verified":true,` +
		`"peer":{"subject":"CN=api.example.test","issuer":"CN=Test CA,O=Test","not_after":"2026-11-30T23:00:00Z"}},` +
		`"redirects":[{"status":302,"location":"https://api.example.test/b?key=***","dropped":["Authorization"],` +
		`"remote_addr":"***","proxy":"http://***@proxy.example.test:3128",` +
		`"timing":{"total_ms":4,"name_lookup_ms":1,"connect_ms":2,"start_transfer_ms":3,"reused":false}}]}`
	if string(got) != want {
		t.Errorf("Diagnose =\n%s\nwant\n%s", got, want)
	}
	var b strings.Builder
	WriteTrace(&b, res)
	text := "* 302 → https://api.example.test/b?key=*** · dropped Authorization · connected to *** · through http://***@proxy.example.test:3128 · dns 1ms connect 2ms ttfb 3ms total 4ms\n" +
		"* connected to 192.0.2.1:443 (reused) · TLS 1.3 · h2 · ttfb 5ms total 6ms\n" +
		"* certificate CN=api.example.test, issuer CN=Test CA,O=Test, expires 2026-11-30T23:00:00Z\n"
	if b.String() != text {
		t.Errorf("WriteTrace =\n%s\nwant\n%s", b.String(), text)
	}

	// Nothing sent, nothing said; a connection that failed says so.
	none := &Result{}
	Diagnose(none, nil, m)
	if b.Reset(); none.Timing != nil {
		t.Errorf("no trace: %+v", none)
	}
	// The certificate of a secret host names it, by its address here.
	self := &x509.Certificate{Subject: pkix.Name{CommonName: "10.0.0.5"}, Issuer: pkix.Name{CommonName: "10.0.0.5"}}
	for _, peer := range []*x509.Certificate{tr.Hops[1].TLS.Peer, self} {
		hidden := &Result{}
		Diagnose(hidden, &exec.Trace{Hops: []exec.Hop{{URL: mustURL(t, "https://localhost:8080/"), RemoteAddr: "10.0.0.5:8080", TLS: &exec.TLSInfo{Peer: peer}}}}, m)
		want := "CN=Test CA,O=Test"
		if peer == self {
			want = "***"
		}
		if p := hidden.TLS.Peer; hidden.RemoteAddr != "***" || p.Subject != "***" || p.Issuer != want {
			t.Errorf("secret host: %s, %+v; want the address and the subject hidden, the issuer %s", hidden.RemoteAddr, p, want)
		}
	}
	// So does a cookie's domain, the host or a domain above it.
	jar := &Result{}
	Diagnose(jar, &exec.Trace{Hops: []exec.Hop{{URL: mustURL(t, "http://localhost:8080/"), Set: []exec.SetCookie{
		{Name: "sid", Domain: "corp.example", Reason: "its Domain is neither the host nor a domain above it"},
	}}}}, m)
	if c := jar.Cookies.Set[0]; c.Domain != "***" || c.Name != "sid" || c.Stored {
		t.Errorf("secret host: cookie %+v", c)
	}
	failed := &Result{}
	Diagnose(failed, &exec.Trace{Total: ms, Hops: []exec.Hop{{URL: mustURL(t, "http://localhost:8080/"), Total: ms}}}, m)
	if WriteTrace(&b, failed); b.String() != "* no connection · total 1ms\n" || failed.RemoteAddr != "" || failed.Redirects != nil {
		t.Errorf("no connection: %+v\n%s", failed, b.String())
	}
}
