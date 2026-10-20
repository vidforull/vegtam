package exec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vidforull/vegtam/internal/core"
)

// Transport is how requests travel, as the flags of a run say. The
// directives of a request may lower its limits (see Client.Settings).
type Transport struct {
	TLS TLS
	// Version is the HTTP version of every request, over what its line
	// says: one of core.HTTP11, core.HTTP2 and core.HTTP2PriorKnowledge.
	// With none, a request speaks HTTP/2 when the server offers it over
	// TLS, and HTTP/1.1 otherwise.
	Version string
	// Connect limits getting a connection: DNS, TCP, a proxy's CONNECT and
	// the TLS handshake, all of it. Read limits each wait for data from
	// the server once the request is written: for the headers, and for
	// each read of the body. Total limits the whole exchange, redirects
	// and body included.
	// 0 is no limit.
	Connect, Read, Total time.Duration
	// NoCookies leaves the client without a cookie jar. Otherwise it has
	// one, in memory, for as long as it lives (see Jar).
	NoCookies bool
}

// TLS is how servers are checked and how the client proves who it is.
type TLS struct {
	Roots *x509.CertPool // nil for the system's
	// Cert is offered to the origin of each request as written, until a
	// redirect leads elsewhere: never to another origin, nor to its own
	// again after that, nor to an https proxy.
	Cert     *tls.Certificate
	Insecure bool // server certificates are not checked
}

// transportKey is all that tells one transport from another: requests
// that differ in any of it never share a connection. The TLS settings
// are the client's own, the same for every key.
type transportKey struct {
	cert    bool // offers the client certificate
	connect time.Duration
	version string
}

// transport returns the transport for k, made on first use.
func (c *Client) transport(k transportKey) *http.Transport {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.pool[k]
	if !ok {
		t = c.newTransport(k)
		c.pool[k] = t
	}
	return t
}

// newTransport returns a transport for k. It starts from a clone of
// net/http's: one made from scratch with a TLS config of its own would
// not speak HTTP/2 without saying so. The TLS config is not changed
// after this: net/http clones it for each connection.
func (c *Client) newTransport(k transportKey) *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok { // replaced by the program; vegtam does not
		base = &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}
	}
	t := base.Clone()
	d := &net.Dialer{Timeout: k.connect, KeepAlive: 30 * time.Second, ControlContext: c.control}
	t.DialContext, t.TLSHandshakeTimeout = d.DialContext, k.connect
	// With HTTP/1 left out, HTTP/2 is all there is: ALPN offers only h2,
	// and plain http is h2c.
	var p http.Protocols
	switch k.version {
	case core.HTTP11:
		p.SetHTTP1(true)
	case core.HTTP2:
		p.SetHTTP2(true)
	case core.HTTP2PriorKnowledge:
		p.SetHTTP2(true)
		p.SetUnencryptedHTTP2(true)
	}
	if k.version != "" {
		t.Protocols = &p
	}
	o := c.opts.Transport.TLS
	cfg := &tls.Config{RootCAs: o.Roots}
	if o.Insecure {
		cfg.InsecureSkipVerify = true
	}
	if p.HTTP2() {
		// A server without ALPN agrees on nothing, and net/http would speak
		// HTTP/1.1 to it: the handshake fails instead, before the request.
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != "h2" {
				return errNoHTTP2
			}
			return nil
		}
	}
	proxy := t.Proxy
	if c.proxy != nil {
		proxy = c.proxy
	}
	if cert := o.Cert; k.cert && cert != nil {
		// Always this certificate, whichever CAs the server names: as
		// curl does, and unlike Certificates, which Go matches to them.
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
		proxy = noTLSProxy(proxy)
	}
	t.Proxy = func(r *http.Request) (*url.URL, error) {
		if proxy == nil {
			return nil, nil
		}
		u, err := proxy(r)
		if err == nil {
			proxied(r, u)
		}
		return u, err
	}
	t.TLSClientConfig = cfg
	return t
}

var errNoHTTP2 = errors.New("the server agreed on no HTTP/2 over TLS (ALPN)")

// noTLSProxy refuses the https proxies that proxy gives. net/http makes
// the TLS connection to such a proxy with the transport's TLS config, so
// the proxy would get the client certificate if it asked for one.
func noTLSProxy(proxy func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		if proxy == nil {
			return nil, nil
		}
		u, err := proxy(r)
		if err == nil && u != nil && u.Scheme == "https" {
			return nil, errors.New("the proxy is an https one, and could ask for the client certificate: a client certificate is not offered through an https proxy")
		}
		return u, err
	}
}

// hops sends each hop of a request with the transport for it: the hops
// to the origin of the request as written offer the client certificate,
// until a redirect has led elsewhere; from then on, none does, as no
// secret header goes on. One transport for the whole chain would offer it
// to every origin a redirect leads to. Each hop takes the cookies of the
// jar for its URL, and gives the jar those its response sets.
type hops struct {
	c     *Client
	st    Settings
	w     *watch
	t     *tracer
	jar   *Jar   // nil for none
	noJar string // why there is none
	first string // the origin of the request as written
	left  bool   // a hop has gone to another origin
	plain bool   // a hop has gone over http
}

// RoundTrip sends a hop, with hooks of its own that keep its time limits
// and trace it. net/http calls it once a hop, one after another.
func (h *hops) RoundTrip(r *http.Request) (*http.Response, error) {
	h.left = h.left || origin(r.URL) != h.first
	h.plain = h.plain || r.URL.Scheme != "https"
	ht := h.t.begin(r)
	ctx := context.WithValue(r.Context(), hopKey{}, ht)
	r = r.WithContext(httptrace.WithClientTrace(ctx, h.w.trace(ht)))
	var sent []Cookie
	if h.jar != nil {
		var cs []*http.Cookie
		if cs, sent = h.jar.cookies(r.URL); len(cs) > 0 {
			r.Header = r.Header.Clone() // r is a copy, its header not yet
			for _, c := range cs {
				r.AddCookie(c)
			}
		}
	}
	resp, err := h.c.transport(transportKey{cert: !h.left, connect: h.st.Connect, version: h.st.Version}).RoundTrip(r)
	ht.got(resp)
	var set []SetCookie
	if resp != nil {
		set = h.offer(r.URL, resp.Cookies())
	}
	ht.cookies(sent, set)
	return resp, err
}

// offer gives the jar the cookies that the response to u set, and says
// what became of each.
func (h *hops) offer(u *url.URL, cs []*http.Cookie) []SetCookie {
	if h.jar != nil {
		return h.jar.set(u, cs, time.Now())
	}
	var set []SetCookie
	for _, c := range cs {
		set = append(set, SetCookie{Name: c.Name, Domain: c.Domain, Path: c.Path, Secure: c.Secure, HTTPOnly: c.HttpOnly, Value: c.Value, Reason: h.noJar})
	}
	return set
}

// LoadTLS reads the files that the TLS flags name: caFile, PEM
// certificates trusted on top of the system's; certFile, a PEM client
// certificate; keyFile, its key, unencrypted, or "" if it is in certFile.
// A file may be anything that reads, such as <(command).
func LoadTLS(caFile, certFile, keyFile string, insecure bool) (TLS, error) {
	cfg := TLS{Insecure: insecure}
	usage := func(format string, args ...any) error {
		return core.Errorf(core.KindUsage, core.Source{}, format, args...)
	}
	if caFile != "" {
		b, err := readFlagFile(caFile)
		if err != nil {
			return TLS{}, usage("--cacert: %v", err)
		}
		if cfg.Roots, err = x509.SystemCertPool(); err != nil {
			return TLS{}, usage("--cacert: the system's certificates: %v", err)
		}
		if !cfg.Roots.AppendCertsFromPEM(b) {
			return TLS{}, usage("--cacert %s: no PEM certificate in it", caFile)
		}
	}
	switch {
	case certFile == "" && keyFile != "":
		return TLS{}, usage("--key needs --cert")
	case certFile == "":
		return cfg, nil
	}
	certPEM, err := readFlagFile(certFile)
	if err != nil {
		return TLS{}, usage("--cert: %v", err)
	}
	keyPEM, name := certPEM, "--cert "+certFile
	if keyFile != "" {
		if keyPEM, err = readFlagFile(keyFile); err != nil {
			return TLS{}, usage("--key: %v", err)
		}
		name = "--key " + keyFile
	}
	if err = checkKey(keyPEM); err != nil {
		return TLS{}, usage("%s: %v", name, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		if b, _ := pem.Decode(certPEM); b == nil {
			return TLS{}, usage("--cert %s: not PEM; for PKCS#12 (.p12, .pfx), pass --cert <(openssl pkcs12 -in FILE -nodes)", certFile)
		}
		return TLS{}, usage("--cert %s: %v", certFile, err)
	}
	cfg.Cert = &cert
	return cfg, nil
}

// checkKey refuses an encrypted PEM key: Go reads none, and its error
// would not say why.
func checkKey(b []byte) error {
	for {
		var block *pem.Block
		if block, b = pem.Decode(b); block == nil {
			return nil
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
			return errors.New("the key is encrypted, and vegtam reads unencrypted keys only: pass --key <(openssl pkey -in FILE), which asks for the passphrase and writes no file")
		}
	}
}

// readFlagFile reads a file that a flag names. It is the user's own
// choice: unlike a path in a .http file, it may be anywhere, and a pipe.
func readFlagFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:forbidigo,gosec // G304: a file a TLS flag names, not a path from a .http file
}
