// Package exec sends prepared requests with net/http.
package exec

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vidforull/vegtam/internal/core"
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
// TLS and HTTP/1.1 otherwise, and takes its proxy from the environment
// (HTTPS_PROXY, HTTP_PROXY, NO_PROXY). It keeps a transport, with its
// pool of connections, for each configuration it sends with.
type Client struct {
	opts Options
	mu   sync.Mutex
	pool map[transportKey]*http.Transport
	// control is the dialer's: tests make a connection hang with it.
	control func(ctx context.Context, network, address string, c syscall.RawConn) error
}

// New returns a Client.
func New(opts Options) *Client {
	return &Client{opts: opts, pool: map[transportKey]*http.Transport{}}
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
	// if one went over http, nor with TLS.Insecure. A plain hop on the way
	// could have led anywhere.
	TLSVerified bool
}

// Do sends p with its secrets revealed from s and reads the response.
func (c *Client) Do(ctx context.Context, p *core.Prepared, s core.Secrets) (*Response, error) {
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
	ctx = httptrace.WithClientTrace(ctx, w.trace())
	req, sensitive, err := c.build(ctx, p, s, false, st.Version)
	if err != nil {
		return nil, err
	}
	h := &hops{c: c, st: st, first: origin(req.URL)}
	hc := &http.Client{Transport: h, CheckRedirect: redirectPolicy(sensitive, p.Body.HasSecret())}
	start := time.Now()
	resp, err := hc.Do(req)
	w.idle() // the headers are in
	if err != nil {
		return nil, c.netError(ctx, p, s, req.URL.String(), err, st, w)
	}
	defer resp.Body.Close()
	limit := c.opts.MaxBody
	if limit < math.MaxInt64 {
		limit++ // one byte more tells whether the body is longer
	}
	body, err := io.ReadAll(io.LimitReader(watched{resp.Body, w}, limit))
	if err != nil {
		return nil, c.netError(ctx, p, s, req.URL.String(), err, st, w)
	}
	r := &Response{
		Proto:    resp.Proto,
		Status:   resp.StatusCode,
		Reason:   strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode))),
		Header:   resp.Header,
		Body:     body,
		Duration: time.Since(start),

		TLSVerified: !h.plain && !c.opts.Transport.TLS.Insecure,
	}
	if int64(len(body)) > c.opts.MaxBody {
		r.Body, r.Truncated = body[:c.opts.MaxBody], true
	}
	return r, nil
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
	// known is false for a late value in a check.
	reveal := func(t core.Text) (v string, known bool, err error) {
		v, err = t.Reveal(s)
		switch {
		case check && errors.Is(err, core.ErrLate):
			return "", false, nil
		case err != nil:
			return "", false, core.Errorf(core.KindVariable, src, "%v", err)
		}
		return v, true, nil
	}
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
		v, known, err = reveal(h.Value)
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

// redirectPolicy follows a redirect unless it goes from https to http, or
// to another origin with a body that holds a secret: a 307 or 308 sends
// the body again, and no header can be dropped from it. On the way to
// another origin the sensitive headers are dropped, and the Referer that
// net/http adds on every hop is dropped on all of them.
func redirectPolicy(sensitive []string, secretBody bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", MaxRedirects)
		}
		if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme == "http" {
			return errors.New("refused a redirect from https to http")
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
				req.Header.Del(h)
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
// the URL wire, in the context ctx that w watched. A timeout names its
// phase: the context says if a limit of vegtam's ended the request, and w
// if a connection was being made.
func (c *Client) netError(ctx context.Context, p *core.Prepared, s core.Secrets, wire string, err error, st Settings, w *watch) error {
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
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		if w.isConnecting() {
			return timeout(core.PhaseConnect, "%s: no connection within %s (connect timeout)", msg, core.FormatTimeout(st.Connect))
		}
		return core.Errorf(core.KindTimeout, p.Request.Source, "%s", msg)
	}
	if h := c.hint(err); h != "" {
		msg += ": " + h
	}
	return core.Errorf(core.KindNetwork, p.Request.Source, "%s", msg)
}

// hint says what to do about err, a TLS error, if anything.
func (c *Client) hint(err error) string {
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
	case strings.Contains(msg, "looked like an HTTP/1.1 header"):
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
