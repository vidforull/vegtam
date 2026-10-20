package exec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/netguard"
)

// Transport is how requests travel, as the operator's policy and the
// flags of a run say. The directives of a request may lower its limits
// (see Client.Settings).
type Transport struct {
	TLS TLS
	// Hosts are the TLS of the origins that the policy names, by origin
	// (https://host:port): TLS's CAs and those trusted for the origin
	// alone, and the client certificate offered to it alone, which TLS's
	// takes the place of for the request as written.
	Hosts map[string]TLS
	// InsecureOrigins are origins whose certificates are not checked, as
	// TLS.Insecure leaves those of every origin.
	InsecureOrigins []string
	// Proxy returns the proxy of a request, as http.Transport's does; nil
	// for none.
	Proxy func(*http.Request) (*url.URL, error)
	// Guard says what each connection may go to: the address connected
	// to, and the target of a request that goes to a proxy.
	Guard netguard.Rules
	// Routes send the connections to some hosts elsewhere, as --resolve
	// and --connect-to say. A request to such a host does not go through
	// a proxy, which would look the name up itself: that is an error.
	Routes netguard.Routes
	// Socket is a unix socket that every connection goes to, through no
	// proxy, whatever the host of its URL: a path, or "@name" for one of
	// Linux's abstract namespace. "" for none.
	Socket string
	// Secrets are values that no output may show, such as the password of
	// the proxy; HiddenEnv the environment variables that no request may
	// read, such as the one that holds it.
	Secrets   []string
	HiddenEnv []string
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
	// ConnectFrom, ReadFrom and TotalFrom name where each limit comes
	// from, for the warning of a directive above it: the flag, or the
	// policy's ceiling. "" names the flag.
	ConnectFrom, ReadFrom, TotalFrom string
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
// that differ in any of it never share a connection. The rest of the
// configuration is the client's own, the same for every key.
type transportKey struct {
	cert     bool   // offers the client certificate of the flags
	host     string // the origin whose TLS of the policy it has; "" for none
	insecure bool   // does not check the server's certificate
	connect  time.Duration
	version  string
}

// key returns the key of the transport for a hop to u. cert is set until
// a redirect has led elsewhere.
func (c *Client) key(u *url.URL, cert bool, st Settings) transportKey {
	o, t := origin(u), c.opts.Transport
	k := transportKey{cert: cert, connect: st.Connect, version: st.Version}
	if _, ok := t.Hosts[o]; ok {
		k.host = o
	}
	k.insecure = t.TLS.Insecure || slices.Contains(t.InsecureOrigins, o)
	return k
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
	d := &net.Dialer{Timeout: k.connect, KeepAlive: 30 * time.Second, ControlContext: c.check}
	t.DialContext, t.TLSHandshakeTimeout = c.dialer(d), k.connect
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
	cert := o.Cert
	if !k.cert {
		cert = nil
	}
	if h, ok := c.opts.Transport.Hosts[k.host]; ok {
		o.Roots = h.Roots
		if cert == nil {
			cert = h.Cert
		}
	}
	cfg := &tls.Config{RootCAs: o.Roots}
	if k.insecure {
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
	proxy := c.opts.Transport.Proxy
	if c.proxy != nil {
		proxy = c.proxy
	}
	if cert != nil {
		// Always this certificate, whichever CAs the server names: as
		// curl does, and unlike Certificates, which Go matches to them.
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
		proxy = noTLSProxy(proxy, "and could ask for the client certificate: a client certificate is not offered through an https proxy")
	}
	if k.insecure {
		// net/http checks the proxy's certificate with the same config.
		proxy = noTLSProxy(proxy, "and --insecure would leave its certificate unchecked too: a request that --insecure leaves unchecked does not go through an https proxy")
	}
	if h, ok := c.opts.Transport.Hosts[k.host]; ok && h.Roots != c.opts.Transport.TLS.Roots {
		proxy = noTLSProxy(proxy, "and the CAs that the policy trusts for "+k.host+" alone would vouch for it too: a request to that origin does not go through an https proxy")
	}
	t.Proxy = c.checkProxy(proxy, k.connect)
	t.TLSClientConfig = cfg
	return t
}

// dialer returns the dial function of a transport, which makes its
// connections with d, to where the routes send each, and says to the
// guard what each is for: the name it is made to, and whether it is the
// proxy of its hop.
func (c *Client) dialer(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if s := c.opts.Transport.Socket; s != "" {
			return d.DialContext(ctx, "unix", s)
		}
		h, _ := ctx.Value(hopKey{}).(*hopTrace)
		proxy := h != nil && h.proxyAddr() == addr
		host, port, _ := net.SplitHostPort(addr)
		to, addrs := host, []string{addr}
		if !proxy { // the routes are for the hosts of requests, as curl's
			to, addrs, _ = c.opts.Transport.Routes.Route(host, port)
		}
		ctx = context.WithValue(ctx, dialKey{}, dialTo{host: to, proxy: proxy})
		var first error
		for _, a := range addrs {
			conn, err := d.DialContext(ctx, network, a)
			if err == nil {
				return conn, nil
			}
			if first == nil {
				first = err
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, first
	}
}

// checkProxy returns the proxy function of a transport, which takes the
// proxy that proxy gives, if any, once it has checked the request's
// target: the proxy connects to it where the guard does not see it, and
// would look up a name that the routes send elsewhere. The target is
// looked up here, within the time of getting a connection, and out of
// the hop's trace, whose lookup it is not.
func (c *Client) checkProxy(proxy func(*http.Request) (*url.URL, error), connect time.Duration) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		if proxy == nil || c.opts.Transport.Socket != "" {
			return nil, nil
		}
		u, err := proxy(r)
		if err != nil || u == nil {
			return u, err
		}
		if by := c.routedBy(r.URL); by != "" {
			return nil, &routeError{by: by, host: r.URL.Hostname()}
		}
		ctx := context.Context(valueless{r.Context()})
		if connect > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, connect)
			defer cancel()
		}
		if err := c.opts.Transport.Guard.CheckTarget(ctx, c.resolver, r.URL.Hostname(), port(r.URL)); err != nil {
			if ctx.Err() != nil && r.Context().Err() == nil {
				return nil, errLookup
			}
			return nil, err
		}
		proxied(r, u)
		return u, nil
	}
}

// errLookup ends a request whose target got no answer to its lookup, to
// check it before the proxy, within the connect timeout.
var errLookup = errors.New("no answer to the lookup of the target, which vegtam checks before the proxy")

// routedBy returns the flag that sends the connections to the host of u
// elsewhere, "" for none.
func (c *Client) routedBy(u *url.URL) string {
	switch s := c.opts.Transport.Socket; {
	case strings.HasPrefix(s, "@"):
		return "--abstract-unix-socket"
	case s != "":
		return "--unix-socket"
	}
	host, err := netguard.ASCII(u.Hostname()) // as net/http dials it
	if err != nil {
		return ""
	}
	_, _, by := c.opts.Transport.Routes.Route(host, strconv.Itoa(int(port(u))))
	return by
}

// routeError is a request to a host that --resolve or --connect-to sends
// elsewhere, which would go through a proxy.
type routeError struct{ by, host string }

func (e *routeError) Error() string {
	return fmt.Sprintf("%s does not apply through a proxy, which looks %s up itself: pass --noproxy %s to go direct", e.by, e.host, e.host)
}

// valueless is a context without the values of its parent, the trace of
// a hop among them.
type valueless struct{ context.Context }

func (valueless) Value(any) any { return nil }

// dialKey is the context key of what a dial is for.
type dialKey struct{}

// dialTo is what a dial is for: the host asked for, and whether it is the
// proxy of the hop.
type dialTo struct {
	host  string
	proxy bool
}

// check is the dialer's control: it checks the address of each
// connection, once the host is looked up, with the guard. The proxy of a
// hop is the operator's or the person's: only what vegtam never connects
// to is refused there.
func (c *Client) check(ctx context.Context, network, address string, raw syscall.RawConn) error {
	if network == "unix" { // a socket that a flag or the policy names: no address to check
		return c.hook(ctx, network, address, raw)
	}
	addr, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("the guard cannot check %s: %w", address, err)
	}
	to, _ := ctx.Value(dialKey{}).(dialTo)
	rules := c.opts.Transport.Guard
	if to.proxy {
		rules = netguard.Rules{}
	}
	if err := rules.Check(to.host, addr); err != nil {
		return err
	}
	return c.hook(ctx, network, address, raw)
}

// hook calls the control of the tests, if any.
func (c *Client) hook(ctx context.Context, network, address string, raw syscall.RawConn) error {
	if c.control != nil {
		return c.control(ctx, network, address, raw)
	}
	return nil
}

// port returns the port of u, given or as its scheme has it.
func port(u *url.URL) uint16 {
	if n, err := strconv.ParseUint(u.Port(), 10, 16); err == nil {
		return uint16(n)
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

var errNoHTTP2 = errors.New("the server agreed on no HTTP/2 over TLS (ALPN)")

// noTLSProxy refuses the https proxies that proxy gives, for the reason
// why. net/http makes the TLS connection to such a proxy with the
// transport's TLS config: the proxy would get the client certificate if
// it asked for one, and with InsecureSkipVerify its own certificate would
// go unchecked.
func noTLSProxy(proxy func(*http.Request) (*url.URL, error), why string) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		if proxy == nil {
			return nil, nil
		}
		u, err := proxy(r)
		if err == nil && u != nil && u.Scheme == "https" {
			return nil, &proxyError{"the proxy is an https one, " + why}
		}
		return u, err
	}
}

// proxyError is a proxy that the flags or the policy give, and that the
// request may not go through.
type proxyError struct{ msg string }

func (e *proxyError) Error() string { return e.msg }

// proxyHostPort returns the host and port that net/http connects to for
// the proxy u: its port, or that of its scheme.
func proxyHostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}[u.Scheme]
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// hops sends each hop of a request with the transport for it: the hops
// to the origin of the request as written offer the client certificate,
// until a redirect has led elsewhere; from then on, none does, as no
// secret header goes on. One transport for the whole chain would offer it
// to every origin a redirect leads to. Each hop takes the cookies of the
// jar for its URL, and gives the jar those its response sets.
type hops struct {
	c        *Client
	st       Settings
	w        *watch
	t        *tracer
	jar      *Jar   // nil for none
	noJar    string // why there is none
	first    string // the origin of the request as written
	left     bool   // a hop has gone to another origin
	plain    bool   // a hop has gone over http
	insecure bool   // a hop has not checked the server's certificate
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
	ht.routed(h.c.routedBy(r.URL))
	k := h.c.key(r.URL, !h.left, h.st)
	h.insecure = h.insecure || k.insecure && r.URL.Scheme == "https"
	resp, err := h.c.transport(k).RoundTrip(r)
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
	var err error
	if caFile != "" {
		if cfg.Roots, err = addRoots(nil, caFile, "--cacert"); err != nil {
			return TLS{}, usage("%v", err)
		}
	}
	switch {
	case certFile == "" && keyFile != "":
		return TLS{}, usage("--key needs --cert")
	case certFile == "":
		return cfg, nil
	}
	if cfg.Cert, err = loadCert(certFile, keyFile, "--cert", "--key", "pass --cert <(openssl pkcs12 -in FILE -nodes)"); err != nil {
		return TLS{}, usage("%v", err)
	}
	return cfg, nil
}

// HostTLS returns the TLS of an origin that the operator's policy names
// as name: base, the flags', with the CAs of caFile trusted on top of
// base's, and the client certificate of certFile and keyFile, if given,
// in place of base's. The policy's key must be private to its owner.
func HostTLS(base TLS, name, caFile, certFile, keyFile string) (TLS, error) {
	fail := func(err error) error {
		return core.Errorf(core.KindPolicy, core.Source{}, "policy hosts.%s: %v", name, err)
	}
	h := TLS{Roots: base.Roots, Insecure: base.Insecure}
	var err error
	if caFile != "" {
		if h.Roots, err = addRoots(base.Roots, caFile, "cacert"); err != nil {
			return TLS{}, fail(err)
		}
	}
	if certFile == "" {
		return h, nil
	}
	key := keyFile
	if key == "" {
		key = certFile
	}
	if fi, serr := os.Stat(key); serr == nil && fi.Mode().Perm()&0o077 != 0 {
		return TLS{}, fail(fmt.Errorf("others can read the key %s; make it private: chmod 600 %s", key, key))
	}
	if h.Cert, err = loadCert(certFile, keyFile, "cert", "key", "convert it: openssl pkcs12 -in FILE -nodes"); err != nil {
		return TLS{}, fail(err)
	}
	return h, nil
}

// addRoots returns base, or the system's certificates if nil, with the
// PEM certificates of file added; name names file in errors.
func addRoots(base *x509.CertPool, file, name string) (*x509.CertPool, error) {
	b, err := readFlagFile(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	roots := base
	if roots == nil {
		if roots, err = x509.SystemCertPool(); err != nil {
			return nil, fmt.Errorf("%s: the system's certificates: %w", name, err)
		}
	} else {
		roots = roots.Clone()
	}
	if !roots.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s %s: no PEM certificate in it", name, file)
	}
	return roots, nil
}

// loadCert reads the PEM client certificate of certFile and its key, in
// keyFile or in certFile if keyFile is "". certName and keyName name them
// in errors, and pkcs12 says what to do with a certificate that is not
// PEM. An error never quotes the key.
func loadCert(certFile, keyFile, certName, keyName, pkcs12 string) (*tls.Certificate, error) {
	certPEM, err := readFlagFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certName, err)
	}
	keyPEM, name := certPEM, certName+" "+certFile
	if keyFile != "" {
		if keyPEM, err = readFlagFile(keyFile); err != nil {
			return nil, fmt.Errorf("%s: %w", keyName, err)
		}
		name = keyName + " " + keyFile
	}
	if err = checkKey(keyPEM); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		if b, _ := pem.Decode(certPEM); b == nil {
			return nil, fmt.Errorf("%s %s: not PEM; for PKCS#12 (.p12, .pfx), %s", certName, certFile, pkcs12)
		}
		return nil, fmt.Errorf("%s %s: %w", certName, certFile, err)
	}
	return &cert, nil
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
