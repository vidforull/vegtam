package exec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
)

// pki is a CA of the tests.
type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vegtam test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns a certificate named name and its key, in PEM: a client's,
// or a server's for 127.0.0.1 and localhost.
func (p *pki) issue(t *testing.T, name string, client bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
	}
	if client {
		tmpl.ExtKeyUsage, tmpl.IPAddresses, tmpl.DNSNames = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, key.Public(), p.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
}

func (p *pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.cert)
	return pool
}

// client returns a client certificate of p named name.
func (p *pki) client(t *testing.T, name string) *tls.Certificate {
	t.Helper()
	cert, err := tls.X509KeyPair(p.issue(t, name, true))
	if err != nil {
		t.Fatal(err)
	}
	return &cert
}

// server starts a TLS server with a certificate of p, which asks for a
// client certificate of p with auth.
func (p *pki) server(t *testing.T, auth tls.ClientAuthType, h http.Handler) *httptest.Server {
	t.Helper()
	cert, err := tls.X509KeyPair(p.issue(t, "server", false))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: auth, ClientCAs: p.pool()}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the handshakes that fail on purpose
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// peer returns the name of the client certificate of r, or "" for none.
func peer(r *http.Request) string {
	if len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

// TestNoReuseAcrossIdentities is a gate of the transport: a connection
// made with one TLS identity never carries a request meant to go with
// another. The client certificate goes to the origin of a request as
// written; a redirect that leads elsewhere, here to that same server,
// takes a connection of its own, without the certificate, and so does
// one that leads back to the first origin.
func TestNoReuseAcrossIdentities(t *testing.T) {
	p := newPKI(t)
	type hit struct{ path, cert, conn string }
	var mu sync.Mutex
	var hits []hit
	record := func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, hit{r.URL.Path, peer(r), r.RemoteAddr})
	}
	var other *httptest.Server
	srv := p.server(t, tls.VerifyClientCertIfGiven, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if r.URL.Path == "/redirected" {
			http.Redirect(w, r, other.URL+"/back", http.StatusFound)
		}
	}))
	other = p.server(t, tls.VerifyClientCertIfGiven, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if r.URL.Path == "/elsewhere" {
			http.Redirect(w, r, srv.URL+"/redirected", http.StatusFound)
		}
	}))
	var reused []bool
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		mu.Lock()
		defer mu.Unlock()
		reused = append(reused, i.Reused)
	}})
	send := func(c *Client, u string) {
		t.Helper()
		if _, _, err := c.Do(ctx, prepared(http.MethodGet, lit(u), nil), testSecrets); err != nil {
			t.Fatal(err)
		}
	}
	a := New(Options{MaxBody: 1 << 20, Transport: Transport{TLS: TLS{Roots: p.pool(), Cert: p.client(t, "a")}}})
	send(a, srv.URL+"/first")
	send(a, srv.URL+"/again")       // the same identity: the same connection
	send(a, other.URL+"/elsewhere") // with the certificate, then to srv and back without it
	// Another client, another certificate, another connection.
	send(New(Options{MaxBody: 1 << 20, Transport: Transport{TLS: TLS{Roots: p.pool(), Cert: p.client(t, "b")}}}), srv.URL+"/b")
	mu.Lock()
	defer mu.Unlock()
	want := []hit{{"/first", "a", ""}, {"/again", "a", ""}, {"/elsewhere", "a", ""}, {"/redirected", "", ""}, {"/back", "", ""}, {"/b", "b", ""}}
	if len(hits) != len(want) {
		t.Fatalf("hits = %v", hits)
	}
	for i, h := range hits {
		if h.path != want[i].path || h.cert != want[i].cert {
			t.Errorf("hit %d = %s with %q, want %s with %q", i, h.path, h.cert, want[i].path, want[i].cert)
		}
	}
	if conn := hits[0].conn; hits[1].conn != conn || hits[3].conn == conn || hits[5].conn == conn || hits[4].conn == hits[2].conn {
		t.Errorf("connections: %v", hits)
	}
	if !slices.Equal(reused, []bool{false, true, false, false, false, false}) {
		t.Errorf("reused = %v, want only the second request on a connection used before", reused)
	}
}

// TestTransports checks the factory: one transport for each key, cloned
// from net/http's, with a TLS config of its own.
func TestTransports(t *testing.T) {
	c := New(Options{Transport: Transport{TLS: TLS{Cert: &tls.Certificate{}}}})
	with, without := c.transport(transportKey{cert: true}), c.transport(transportKey{})
	switch {
	case with == without, c.transport(transportKey{cert: true}) != with, with == http.DefaultTransport:
		t.Fatal("not one transport for each key")
	case with.TLSClientConfig == without.TLSClientConfig:
		t.Error("the transports share a TLS config")
	case !with.ForceAttemptHTTP2 || without.Proxy == nil:
		t.Error("the defaults of net/http are lost: HTTP/2, the proxy from the environment")
	case with.TLSClientConfig.GetClientCertificate == nil || without.TLSClientConfig.GetClientCertificate != nil:
		t.Error("the client certificate is not where the key says")
	case with.TLSClientConfig.KeyLogWriter != nil || without.TLSClientConfig.KeyLogWriter != nil:
		t.Error("a transport writes TLS keys")
	}
}

// TestNoTLSProxy checks that the transport with the client certificate
// refuses an https proxy, which would get the certificate if it asked.
func TestNoTLSProxy(t *testing.T) {
	via := func(s string) func(*http.Request) (*url.URL, error) {
		return func(*http.Request) (*url.URL, error) { return url.Parse(s) }
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.test/", nil)
	if u, err := noTLSProxy(via("http://proxy.example.test:3128"))(r); err != nil || u.Host != "proxy.example.test:3128" {
		t.Errorf("http proxy: %v, %v", u, err)
	}
	if u, err := noTLSProxy(via("https://proxy.example.test"))(r); err == nil || u != nil {
		t.Errorf("https proxy: %v, %v; want an error", u, err)
	}
	if u, err := noTLSProxy(nil)(r); err != nil || u != nil {
		t.Errorf("no proxy: %v, %v", u, err)
	}
}

func TestLoadTLS(t *testing.T) {
	p := newPKI(t)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certPEM, keyPEM := p.issue(t, "me", true)
	_, otherKey := p.issue(t, "someone else", true)
	ca, cert, key := write("ca.pem", p.pem), write("me.pem", certPEM), write("me.key", keyPEM)
	both := write("both.pem", append(append([]byte{}, certPEM...), keyPEM...))

	// The CA joins the system's roots: it does not take their place.
	cfg, err := LoadTLS(ca, cert, key, false)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	want.AppendCertsFromPEM(p.pem)
	if !cfg.Roots.Equal(want) || cfg.Cert == nil || cfg.Insecure {
		t.Errorf("LoadTLS = %+v", cfg)
	}
	if cfg, err := LoadTLS(ca, both, "", false); err != nil || cfg.Cert == nil {
		t.Errorf("certificate and key in one file: %+v, %v", cfg, err)
	}
	if cfg, err := LoadTLS("", "", "", true); err != nil || cfg.Roots != nil || cfg.Cert != nil || !cfg.Insecure {
		t.Errorf("no files: %+v, %v", cfg, err)
	}

	// A key file is a secret: no error quotes it.
	const canary = "C4NARY"
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte(canary)})
	legacy := pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"}, Bytes: []byte(canary),
	})
	garbled := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(canary)})
	block, _ := pem.Decode(certPEM)
	tests := []struct {
		name               string
		ca, cert, key      string
		want               string
		forbidden, missing bool
	}{
		{"no CA file", filepath.Join(dir, "none.pem"), "", "", "--cacert: open ", false, false},
		{"CA not PEM", write("notpem", []byte("not a certificate")), "", "", "no PEM certificate in it", false, false},
		{"key without certificate", "", "", key, "--key needs --cert", false, false},
		{"encrypted key", "", cert, write("enc.key", encrypted), "the key is encrypted", true, false},
		{"encrypted legacy key", "", cert, write("legacy.key", legacy), "the key is encrypted", true, false},
		{"garbled key", "", cert, write("garbled.key", garbled), "--cert " + cert + ": tls: failed to parse private key", true, false},
		{"text key", "", cert, write("text.key", []byte(canary)), "tls: failed to find any PEM data in key input", true, false},
		{"another key", "", cert, write("other.key", otherKey), "private key does not match public key", false, false},
		{"certificate not PEM", "", write("me.p12", block.Bytes), key, "for PKCS#12 (.p12, .pfx)", false, false},
	}
	for _, tt := range tests {
		_, err := LoadTLS(tt.ca, tt.cert, tt.key, false)
		e, ok := errors.AsType[*core.Error](err)
		if !ok || e.Kind != core.KindUsage || !strings.Contains(e.Msg, tt.want) {
			t.Errorf("%s: %v, want a usage error with %q", tt.name, err, tt.want)
		}
		if err != nil && strings.Contains(err.Error(), canary) {
			t.Errorf("%s: the error quotes the key: %v", tt.name, err)
		}
	}
}

// TestTLS sends to servers of the tests' own CA: trusted with Roots,
// refused without, sent anyway with Insecure, which says so.
func TestTLS(t *testing.T) {
	p := newPKI(t)
	open := p.server(t, tls.NoClientCert, http.NotFoundHandler())
	mtls := p.server(t, tls.RequireAndVerifyClientCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cert", peer(r))
	}))
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	// A redirect from another origin to the server that wants the
	// certificate: it is not offered there.
	redirect := p.server(t, tls.NoClientCert, http.RedirectHandler(mtls.URL, http.StatusFound))
	// Over http first: whoever was on the way could have sent it anywhere.
	upgrade := httptest.NewServer(http.RedirectHandler(open.URL, http.StatusFound))
	defer upgrade.Close()
	trusted, cert := TLS{Roots: p.pool()}, TLS{Roots: p.pool(), Cert: p.client(t, "me")}
	tests := []struct {
		name     string
		tls      TLS
		url      string
		verified bool
		want     string // the error; "" for none
	}{
		{"trusted", trusted, open.URL, true, ""},
		{"plain http", trusted, plain.URL, false, ""},
		{"from http to https", trusted, upgrade.URL, false, ""},
		{"unknown CA", TLS{}, open.URL, false, "x509: certificate signed by unknown authority: add the CA that signed it with --cacert"},
		{"insecure", TLS{Insecure: true}, open.URL, false, ""},
		{"client certificate", cert, mtls.URL, true, ""},
		{"no client certificate", trusted, mtls.URL, false, "tls: certificate required: the server asks for a client certificate: pass --cert and --key"},
		{"after a redirect", cert, redirect.URL, false, "offers to the origin of the request as written only, not after a redirect"},
	}
	for _, tt := range tests {
		r, err := do(t, Options{Transport: Transport{TLS: tt.tls}}, prepared(http.MethodGet, lit(tt.url), nil))
		switch {
		case tt.want == "" && (err != nil || r.TLSVerified != tt.verified):
			t.Errorf("%s: %+v, %v; want TLSVerified %v", tt.name, r, err, tt.verified)
		case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
			t.Errorf("%s: %v, want an error with %q", tt.name, err, tt.want)
		case tt.name == "client certificate" && r.Header.Get("X-Cert") != "me":
			t.Errorf("%s: the server saw %q", tt.name, r.Header.Get("X-Cert"))
		}
	}
}

// TestNoKeyLog checks that SSLKEYLOGFILE changes nothing: Go does not
// read it, and vegtam does not either.
func TestNoKeyLog(t *testing.T) {
	p := newPKI(t)
	srv := p.server(t, tls.NoClientCert, http.NotFoundHandler())
	keys := filepath.Join(t.TempDir(), "keys.log")
	t.Setenv("SSLKEYLOGFILE", keys)
	if _, err := do(t, Options{Transport: Transport{TLS: TLS{Roots: p.pool()}}}, prepared(http.MethodGet, lit(srv.URL), nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keys); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("SSLKEYLOGFILE: %v", err)
	}
}

// TestTLSErrorsHideSecrets is the canary of TLS errors, which quote host
// names: one that comes from a secret does not show, nor its port.
func TestTLSErrorsHideSecrets(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "https://"), ":")
	u := append(secret("base"), core.Text{{Text: "/?key="}, {Secret: &core.Secret{Name: "token"}}}...)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	for _, tt := range []struct {
		name, host string
		tls        TLS
		want       string
	}{
		{"unknown CA", "127.0.0.1", TLS{}, `Get "{{base}}/?key={{token}}": tls: failed to verify certificate: x509: certificate signed by unknown authority`},
		{"another host", "localhost", TLS{Roots: roots}, "x509: certificate is valid for example.com, *.example.com, not ***"},
	} {
		s := secrets{"base": "https://" + tt.host + ":" + port, "token": "t0ken"}
		_, _, err := New(Options{MaxBody: 1, Transport: Transport{TLS: tt.tls}}).Do(t.Context(), prepared(http.MethodGet, u, nil), s)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v, want %q", tt.name, err, tt.want)
			continue
		}
		for _, part := range []string{tt.host, port, "t0ken"} {
			if strings.Contains(err.Error(), part) {
				t.Errorf("%s: %q in %v", tt.name, part, err)
			}
		}
	}
}

// TestHTTPVersions checks what each version, from a flag or a request
// line, speaks to servers of each kind, and what it refuses.
func TestHTTPVersions(t *testing.T) {
	h1, h2 := httptest.NewUnstartedServer(http.NotFoundHandler()), httptest.NewUnstartedServer(http.NotFoundHandler())
	h2.EnableHTTP2 = true
	h2c, plain := httptest.NewUnstartedServer(http.NotFoundHandler()), httptest.NewUnstartedServer(http.NotFoundHandler())
	h2c.Config.Protocols = new(http.Protocols)
	h2c.Config.Protocols.SetHTTP1(true)
	h2c.Config.Protocols.SetUnencryptedHTTP2(true)
	for _, s := range []*httptest.Server{h1, h2} {
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		s.StartTLS()
		t.Cleanup(s.Close)
	}
	for _, s := range []*httptest.Server{h2c, plain} {
		s.Start()
		t.Cleanup(s.Close)
	}
	roots := x509.NewCertPool()
	roots.AddCert(h2.Certificate()) // httptest's servers share it
	// A TLS server without ALPN, and what it is sent.
	var sent atomic.Int32
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	noALPN := &http.Server{
		Handler:  http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sent.Add(1) }),
		ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: time.Second,
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := noALPN.Serve(tls.NewListener(ln, &tls.Config{Certificates: h1.TLS.Certificates})); !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		if err := noALPN.Close(); err != nil {
			t.Error(err)
		}
		wg.Wait()
	})
	bare := "https://" + ln.Addr().String()
	tests := []struct {
		flag, line string // the versions of the flag and the request line
		url        string
		want       string // the proto of the response, or a part of the error
	}{
		{"", "", h2.URL, "HTTP/2.0"},
		{"", "", h1.URL, "HTTP/1.1"},
		{"", "", h2c.URL, "HTTP/1.1"},
		{core.HTTP11, "", h2.URL, "HTTP/1.1"},
		{"", core.HTTP11, h2.URL, "HTTP/1.1"},
		{"", core.HTTP2, h2.URL, "HTTP/2.0"},
		{core.HTTP11, core.HTTP2, h2.URL, "HTTP/1.1"},
		{core.HTTP2, "", h1.URL, "tls: no application protocol: the server does not speak HTTP/2 over TLS"},
		{core.HTTP2, "", plain.URL, "HTTP/2 over http needs HTTP/2 (Prior Knowledge)"},
		{core.HTTP2PriorKnowledge, "", h2c.URL, "HTTP/2.0"},
		{"", core.HTTP2PriorKnowledge, h2.URL, "HTTP/2.0"},
		{core.HTTP2PriorKnowledge, "", plain.URL, "the server does not speak HTTP/2 with prior knowledge"},
		{core.HTTP2, "", bare, "the server agreed on no HTTP/2 over TLS (ALPN)"},
		{"", core.HTTP2PriorKnowledge, bare, "the server agreed on no HTTP/2 over TLS (ALPN)"},
		{"", "", bare, "HTTP/1.1"},
	}
	for _, tt := range tests {
		p := prepared(http.MethodGet, lit(tt.url), nil)
		p.Request.Version = tt.line
		r, err := do(t, Options{Transport: Transport{TLS: TLS{Roots: roots}, Version: tt.flag}}, p)
		got := ""
		if err != nil {
			got = err.Error()
		} else {
			got = r.Proto
		}
		if !strings.Contains(got, tt.want) {
			t.Errorf("--http %q, line %q, %s: %s, want %s", tt.flag, tt.line, tt.url, got, tt.want)
		}
	}
	if n := sent.Load(); n != 1 {
		t.Errorf("the server without ALPN got %d requests, want only the one that asked for no version", n)
	}
	// Refused before sending, as a dry run finds it too.
	p := prepared(http.MethodGet, lit(plain.URL), nil)
	p.Request.Version = core.HTTP2
	if err := New(Options{}).Check(t.Context(), p, testSecrets); err == nil || !strings.Contains(err.Error(), "needs HTTP/2 (Prior Knowledge)") {
		t.Errorf("Check = %v", err)
	}
}
