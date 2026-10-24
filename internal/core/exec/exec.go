// Package exec sends prepared requests with net/http.
package exec

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/netguard"
)

// MaxRedirects is how many redirects a request follows.
const MaxRedirects = 10

// Options configure a Client.
type Options struct {
	MaxBody   int64  // response body bytes kept; the rest is not read
	UserAgent string // sent when the request has no User-Agent header
	Transport Transport
}

// Client sends requests. It speaks HTTP/2 when the server offers it over
// TLS and HTTP/1.1 otherwise, and goes through the proxy its transport
// gives, if any. It keeps a transport, with its pool of connections, for
// each configuration it sends with.
type Client struct {
	opts Options
	mu   sync.Mutex
	pool map[transportKey]*http.Transport
	// control is the dialer's, after the guard: tests make a connection
	// hang with it.
	control func(ctx context.Context, network, address string, c syscall.RawConn) error
	// proxy takes the place of the transport's, for tests.
	proxy func(*http.Request) (*url.URL, error)
	// resolver looks up the target of a request that goes to a proxy, for
	// the guard; tests answer from a table.
	resolver netguard.Resolver
	jar      *Jar // nil without one
}

// New returns a Client, with a cookie jar of its own unless the transport
// says no.
func New(opts Options) *Client {
	c := &Client{opts: opts, pool: map[transportKey]*http.Transport{}, resolver: net.DefaultResolver}
	if !opts.Transport.NoCookies {
		c.jar = NewJar()
	}
	return c
}

// Response is a received response.
type Response struct {
	Proto     string // "HTTP/1.1", "HTTP/2.0"
	Status    int
	Reason    string // "OK", "Not Found"
	Header    http.Header
	Body      []byte
	Truncated bool // the body was longer than MaxBody
	Duration  time.Duration
	// TLSVerified is set when every hop of the request, redirects
	// included, went over TLS with the server's certificate checked: not
	// if one went over http, nor to an origin left unchecked, as
	// TLS.Insecure leaves all of them. A plain hop on the way could have
	// led anywhere.
	TLSVerified bool
	// Origins are those of the last hop, which the response came from, as
	// core.Origins gives them: its URL's, and its Host header's.
	Origins []string
}

// Do sends p with its secrets revealed from s and reads the response. The
// trace says how it went, after an error too; it is nil if nothing was
// sent. No hop goes to an origin that a secret it holds is not bound to
// (see core.Secrets): the request as written is refused before anything
// is sent, and a redirect before it is followed, as errors of kind
// policy.
func (c *Client) Do(ctx context.Context, p *core.Prepared, s core.Secrets) (*Response, *Trace, error) {
	st, _ := c.Settings(p.Request)
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	if st.Total > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeoutCause(ctx, st.Total, errMaxTime)
		defer stop()
	}
	w := &watch{connect: st.Connect, read: st.Read, cancel: cancel}
	defer w.stop()
	req, sensitive, err := c.build(ctx, p, s, false, st.Version)
	if err != nil {
		return nil, nil, err
	}
	var refused []core.Bound
	for _, o := range core.Origins(req.URL, req.Host) {
		refused = append(refused, core.Unbound(p, s, o)...)
	}
	if len(refused) > 0 {
		e := core.SecretError(core.KindPolicy, p.Request.Source, p.Method+" "+p.URL.Masked()+" is not sent", refused)
		e.Msg = hide(p, s, req.URL.String(), e.Msg) // the origin may be a secret's
		return nil, nil, e
	}
	t := &tracer{}
	h := &hops{c: c, st: st, w: w, t: t, first: origin(req.URL), jar: c.jar}
	switch {
	case c.jar == nil:
		h.noJar = "the jar is off: --no-cookies"
	case p.Request != nil && p.Request.NoCookieJar():
		h.jar, h.noJar = nil, "@no-cookie-jar"
	}
	hc := &http.Client{Transport: h, CheckRedirect: redirectPolicy(p, s, sensitive, t)}
	start := time.Now()
	resp, err := hc.Do(req)
	w.idle() // the headers are in
	if err != nil {
		return nil, t.finish(start), c.netError(ctx, p, s, req.URL.String(), err, st, w, t)
	}
	defer resp.Body.Close()
	limit := c.opts.MaxBody
	if limit < math.MaxInt64 {
		limit++ // one byte more tells whether the body is longer
	}
	body, err := io.ReadAll(io.LimitReader(watched{resp.Body, w}, limit))
	if err != nil {
		return nil, t.finish(start), c.netError(ctx, p, s, req.URL.String(), err, st, w, t)
	}
	r := &Response{
		Proto:    resp.Proto,
		Status:   resp.StatusCode,
		Reason:   strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode))),
		Header:   resp.Header,
		Body:     body,
		Duration: time.Since(start),

		TLSVerified: !h.plain && !h.insecure,
		Origins:     core.Origins(resp.Request.URL, resp.Request.Host),
	}
	if int64(len(body)) > c.opts.MaxBody {
		r.Body, r.Truncated = body[:c.opts.MaxBody], true
	}
	return r, t.finish(start), nil
}

// CookieValues returns the values of the cookies the client's jar keeps.
func (c *Client) CookieValues() []string {
	if c.jar == nil {
		return nil
	}
	return c.jar.values()
}

// Check reports the error Do would give p before sending anything: an
// invalid URL or header, or a secret that cannot be found. A part that
// holds a value s gives as core.ErrLate, one known only when the request
// is sent, is left unchecked.
func (c *Client) Check(ctx context.Context, p *core.Prepared, s core.Secrets) error {
	st, _ := c.Settings(p.Request)
	_, _, err := c.build(ctx, p, s, true, st.Version)
	return err
}

// revealed returns t with its secrets revealed from s, and whether it is
// known: not for a late value in a check. A value that s refuses to give,
// by its policy, is an error of kind policy; another error, of kind
// variable, at src.
func revealed(t core.Text, s core.Secrets, src core.Source, check bool) (string, bool, error) {
	v, err := t.Reveal(s)
	e, typed := errors.AsType[*core.Error](err)
	switch {
	case check && errors.Is(err, core.ErrLate):
		return "", false, nil
	case typed && e.Kind == core.KindPolicy:
		return "", false, core.Errorf(core.KindPolicy, src, "%s", e.Msg)
	case err != nil:
		return "", false, core.Errorf(core.KindVariable, src, "%v", err)
	}
	return v, true, nil
}

// build makes the request that goes on the wire with the HTTP version
// version. It also returns the headers that must not follow a redirect to
// another origin. With check, a late value is no error: build checks the
// rest, and returns no request if the URL holds one.
func (c *Client) build(ctx context.Context, p *core.Prepared, s core.Secrets, check bool, version string) (*http.Request, []string, error) {
	src := p.Request.Source
	var raw string
	fail := func(format string, args ...any) error {
		return core.Errorf(core.KindRequest, src, "%s", hide(p, s, raw, fmt.Sprintf(format, args...)))
	}
	reveal := func(t core.Text) (string, bool, error) { return revealed(t, s, src, check) }
	raw, urlKnown, err := reveal(p.URL)
	if err != nil {
		return nil, nil, err
	}
	if urlKnown {
		// Messages name raw; fail shows it masked.
		var u *url.URL
		u, err = url.Parse(raw)
		switch {
		case err != nil:
			return nil, nil, fail("invalid URL %s: %v", raw, errors.Unwrap(err))
		case u.Scheme != "http" && u.Scheme != "https":
			return nil, nil, fail("URL %s: want an http or https URL", raw)
		case u.Host == "":
			return nil, nil, fail("URL %s has no host", raw)
		// net/http would send HTTP/1.1 without a word.
		case version == core.HTTP2 && u.Scheme == "http":
			return nil, nil, fail("HTTP/2 over http needs HTTP/2 (Prior Knowledge), or --http2-prior-knowledge: vegtam does not upgrade a connection")
		}
	}
	body, _, err := reveal(p.Body)
	if err != nil {
		return nil, nil, err
	}
	// net/http drops these on its own only when the host is not a
	// subdomain; vegtam drops them, and every header holding a secret, on
	// any change of origin.
	sensitive := []string{"Authorization", "Cookie", "Proxy-Authorization", "Referer"}
	header, host := http.Header{}, ""
	for _, h := range p.Headers {
		var v string
		var known bool
		v, known, err = headerValue(h, reveal, fail)
		if err != nil {
			return nil, nil, err
		}
		// What net/http would refuse when sending, refused here, so that a
		// dry run finds it too.
		if strings.ContainsFunc(v, func(r rune) bool { return r < ' ' && r != '\t' || r == 0x7f }) {
			return nil, nil, fail("header %s: the value contains a line break or another control character", h.Name)
		}
		if strings.EqualFold(h.Name, "Host") && strings.ContainsFunc(v, func(r rune) bool { return !validHost(r) }) {
			return nil, nil, fail("header Host: invalid host %q", v)
		}
		if h.Value.HasSecret() {
			sensitive = append(sensitive, h.Name)
		}
		switch {
		case !known:
		case strings.EqualFold(h.Name, "Host"):
			host = v
		default:
			header.Add(h.Name, v)
		}
	}
	if !urlKnown {
		return nil, nil, nil
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, p.Method, raw, rd)
	if err != nil {
		return nil, nil, fail("%v", err)
	}
	req.Header = header
	if host != "" {
		req.Host = host
	}
	if _, ok := req.Header["User-Agent"]; !ok && c.opts.UserAgent != "" {
		req.Header.Set("User-Agent", c.opts.UserAgent)
	}
	return req, sensitive, nil
}

// headerValue returns the value of h as it goes on the wire, revealed by
// reveal, and whether it is known yet; fail makes the error of a value
// that cannot go.
func headerValue(h core.PreparedHeader, reveal func(core.Text) (string, bool, error), fail func(string, ...any) error) (string, bool, error) {
	if user, password, ok := core.BasicAuth(h); ok {
		return basic(user, password, reveal, fail)
	}
	return reveal(h.Value)
}

// basic returns the value of an Authorization header that core.BasicAuth
// reads as user and password: Basic and the base64 of user:password.
func basic(user, password core.Text, reveal func(core.Text) (string, bool, error), fail func(string, ...any) error) (string, bool, error) {
	u, userKnown, err := reveal(user)
	switch {
	case err != nil:
		return "", false, err
	// Known before the password, as in a dry run with a password that an
	// earlier request captures.
	case userKnown && strings.Contains(u, ":"):
		return "", false, fail("header Authorization: the user of Basic holds a colon, which Basic cannot carry (RFC 7617)")
	}
	pw, known, err := reveal(password)
	if err != nil || !userKnown || !known {
		return "", false, err
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+pw)), true, nil
}

// redirectPolicy follows a redirect of p, whose secrets s reveals, unless
// it goes from https to http, or to another origin with a body that holds
// a secret: a 307 or 308 sends the body again, and no header can be
// dropped from it. Nor does it follow one to an origin that a secret in
// the URL of p is not bound to, which is an error of kind policy: a
// server that sends its query on, as an open redirect does, would send
// the secret there. On the way to another origin the sensitive headers
// are dropped, and the Referer that net/http adds on every hop is dropped
// on all of them. t records each redirect, and the headers of the request
// it dropped.
func redirectPolicy(p *core.Prepared, s core.Secrets, sensitive []string, t *tracer) func(*http.Request, []*http.Request) error {
	secretBody := p.Body.HasSecret()
	return func(req *http.Request, via []*http.Request) error {
		var dropped []string
		defer func() { t.redirect(dropped) }()
		if len(via) > MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", MaxRedirects)
		}
		if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme == "http" {
			return errors.New("refused a redirect from https to http")
		}
		for _, to := range core.Origins(req.URL, req.Host) {
			if refused := core.Refused(core.Bindings(s, to, p.URL)); len(refused) > 0 {
				return core.SecretError(core.KindPolicy, p.Request.Source, "refused a redirect to "+to+" of a URL that holds a secret", refused)
			}
		}
		// net/http sends the URL it was redirected from as the Referer,
		// query and all, and a query may hold a token (RFC 9110, 10.1.3).
		// A Referer the request itself has is kept, as far as its origin.
		if via[0].Header.Get("Referer") == "" {
			req.Header.Del("Referer")
		}
		// net/http copies the headers of the first request on every hop,
		// so once the chain has left the first origin they are dropped on
		// every later hop too.
		first := origin(via[0].URL)
		left := origin(req.URL) != first
		for _, r := range via[1:] {
			left = left || origin(r.URL) != first
		}
		if left {
			if secretBody && req.Body != nil && req.Body != http.NoBody {
				return errors.New("refused a redirect to another origin: it would send the body again, and the body holds a secret")
			}
			for _, h := range sensitive {
				name := http.CanonicalHeaderKey(h)
				if _, ok := req.Header[name]; ok && !slices.Contains(dropped, name) {
					dropped = append(dropped, name)
				}
				req.Header.Del(name)
			}
		}
		return nil
	}
}

// origin returns the scheme, host and port of u.
func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// netError classifies err, an error from sending p, with settings st, to
// the URL wire, in the context ctx that w watched and t traced. A timeout
// names its phase: the context says if a limit of vegtam's ended the
// request, and w if a connection was being made.
func (c *Client) netError(ctx context.Context, p *core.Prepared, s core.Secrets, wire string, err error, st Settings, w *watch, t *tracer) error {
	msg := hide(p, s, wire, err.Error())
	// What net/http says after the URL is that it canceled the request.
	// An error that reading the body gives is the bare cause.
	where := hide(p, s, wire, "reading the body of "+strconv.Quote(wire))
	if ue, ok := errors.AsType[*url.Error](err); ok {
		where = hide(p, s, wire, ue.Op+" "+strconv.Quote(ue.URL))
	}
	timeout := func(phase, format string, args ...any) error {
		e := core.Errorf(core.KindTimeout, p.Request.Source, format, args...)
		e.Phase = phase
		return e
	}
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errMaxTime):
		return timeout(core.PhaseTotal, "%s: no complete response within %s (max time)", where, core.FormatTimeout(st.Total))
	case errors.Is(cause, errReadTimeout):
		return timeout(core.PhaseRead, "%s: no data from the server for %s (read timeout)", where, core.FormatTimeout(st.Read))
	case errors.Is(cause, errConnectTimeout):
		return timeout(core.PhaseConnect, "%s: no connection within %s (connect timeout)", where, core.FormatTimeout(st.Connect))
	case errors.Is(err, context.Canceled):
		return core.Errorf(core.KindCanceled, p.Request.Source, "%s", msg)
	}
	// A redirect refused for a secret.
	if ce, ok := errors.AsType[*core.Error](err); ok && ce.Secret != nil {
		ce.Msg = hide(p, s, wire, ce.Msg)
		return ce
	}
	if pe, ok := errors.AsType[*proxyError](err); ok {
		return core.Errorf(core.KindUsage, p.Request.Source, "%s: %s", where, pe.Error())
	}
	if errors.Is(err, errLookup) {
		return timeout(core.PhaseConnect, "%s: %v, within %s (connect timeout)", where, errLookup, core.FormatTimeout(st.Connect))
	}
	if re, ok := errors.AsType[*routeError](err); ok {
		return core.Errorf(core.KindUsage, p.Request.Source, "%s: %s", where, hide(p, s, wire, re.Error()))
	}
	if ge, ok := errors.AsType[*netguard.Error](err); ok {
		return core.Errorf(core.KindPolicy, p.Request.Source, "%s: %s", where, hide(p, s, wire, ge.Error()))
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		if w.isConnecting() {
			return timeout(core.PhaseConnect, "%s: no connection within %s (connect timeout)", msg, core.FormatTimeout(st.Connect))
		}
		return core.Errorf(core.KindTimeout, p.Request.Source, "%s", msg)
	}
	if h := c.hint(err, t); h != "" {
		msg += ": " + h
	}
	return core.Errorf(core.KindNetwork, p.Request.Source, "%s", msg)
}

// hint says what to do about err, if anything: a TLS error, or one of a
// server that the trace t shows does not speak HTTP/2 with prior
// knowledge, whatever net/http says about it.
func (c *Client) hint(err error, t *tracer) string {
	msg := err.Error()
	_, unknownCA := errors.AsType[x509.UnknownAuthorityError](err)
	switch {
	case unknownCA:
		return "add the CA that signed it with --cacert"
	case strings.Contains(msg, "tls: certificate required") && c.opts.Transport.TLS.Cert != nil:
		return "the server asks for a client certificate, which vegtam offers to the origin of the request as written only, not after a redirect"
	case strings.Contains(msg, "tls: certificate required"):
		return "the server asks for a client certificate: pass --cert and --key"
	case strings.Contains(msg, "tls: no application protocol"):
		return "the server does not speak HTTP/2 over TLS"
	case t.refusedPriorKnowledge():
		return "the server does not speak HTTP/2 with prior knowledge"
	}
	return ""
}

// validHost reports whether r may appear in a Host header, as net/http
// checks it.
func validHost(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune("!$%&'()*+,-.:;=[]_~", r)
}

// hide keeps the secret values of p out of msg, an error message. net/http
// quotes the URL it was sending to, wire, and may name a host, port or
// redirect URL taken from a secret: the URL is replaced with p's masked
// URL, and any value left is masked. If a secret is part of the host, the
// host and port are masked wherever they appear on their own.
func hide(p *core.Prepared, s core.Secrets, wire, msg string) string {
	// The masked URL goes in last, so that masking the host leaves it be.
	const mark = "\x00url\x00"
	masked := p.URL.Masked()
	if wire != "" {
		msg = strings.ReplaceAll(msg, wire, mark)
	}
	var values []string
	if a := authority(wire); a != "" && a != authority(masked) {
		// The addresses the host resolves to, which net names, tell it too.
		msg = ipRE.ReplaceAllString(msg, "***")
		values = append(values, a)
		if i := strings.LastIndex(a, ":"); i > 0 && !strings.HasSuffix(a, "]") {
			values = append(values, strings.Trim(a[:i], "[]"), a[i:])
		}
	}
	texts := []core.Text{p.URL, p.Body}
	for _, h := range p.Headers {
		texts = append(texts, h.Value)
	}
	for _, t := range texts {
		for _, seg := range t {
			if seg.Secret == nil {
				continue
			}
			if v, err := s.SecretValue(*seg.Secret); err == nil {
				values = append(values, v)
			}
		}
	}
	return strings.ReplaceAll(core.NewMasker(values).Mask(msg), mark, masked)
}

// ipRE matches an IP address, with a port or not, as net writes them.
var ipRE = regexp.MustCompile(`\[[0-9A-Fa-f:.]+(%[^\]]*)?\](:[0-9]+)?|\b[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?\b`)

// authority returns the host and port of the URL u, written as a string
// that may not parse.
func authority(u string) string {
	_, rest, ok := strings.Cut(u, "://")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	return rest
}
