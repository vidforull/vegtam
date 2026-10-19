// Package exec sends prepared requests with net/http.
package exec

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vidforull/vegtam/internal/core"
)

// MaxRedirects is how many redirects a request follows.
const MaxRedirects = 10

// Options configure a Client.
type Options struct {
	Timeout   time.Duration // for the whole exchange, body included; 0 means none
	MaxBody   int64         // response body bytes kept; the rest is not read
	UserAgent string        // sent when the request has no User-Agent header
	TLS       *tls.Config   // nil means the system defaults
}

// Client sends requests. It speaks HTTP/2 when the server offers it over
// TLS and HTTP/1.1 otherwise, and takes its proxy from the environment
// (HTTPS_PROXY, HTTP_PROXY, NO_PROXY).
type Client struct {
	opts      Options
	transport *http.Transport
}

// New returns a Client.
func New(opts Options) *Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if opts.TLS != nil {
		t.TLSClientConfig = opts.TLS.Clone()
	}
	return &Client{opts: opts, transport: t}
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
}

// Do sends p with its secrets revealed from s and reads the response.
func (c *Client) Do(ctx context.Context, p *core.Prepared, s core.Secrets) (*Response, error) {
	req, sensitive, err := c.build(ctx, p, s, false)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Transport: c.transport, Timeout: c.opts.Timeout, CheckRedirect: redirectPolicy(sensitive)}
	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return nil, c.netError(p, s, req.URL.String(), err)
	}
	defer resp.Body.Close()
	limit := c.opts.MaxBody
	if limit < math.MaxInt64 {
		limit++ // one byte more tells whether the body is longer
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, c.netError(p, s, req.URL.String(), err)
	}
	r := &Response{
		Proto:    resp.Proto,
		Status:   resp.StatusCode,
		Reason:   strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode))),
		Header:   resp.Header,
		Body:     body,
		Duration: time.Since(start),
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
func (c *Client) Check(p *core.Prepared, s core.Secrets) error {
	_, _, err := c.build(context.Background(), p, s, true)
	return err
}

// build makes the request that goes on the wire. It also returns the
// headers that must not follow a redirect to another origin. With check,
// a late value is no error: build checks the rest, and returns no request
// if the URL holds one.
func (c *Client) build(ctx context.Context, p *core.Prepared, s core.Secrets, check bool) (*http.Request, []string, error) {
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
		u, err := url.Parse(raw)
		switch {
		case err != nil:
			return nil, nil, fail("invalid URL %s: %v", raw, errors.Unwrap(err))
		case u.Scheme != "http" && u.Scheme != "https":
			return nil, nil, fail("URL %s: want an http or https URL", raw)
		case u.Host == "":
			return nil, nil, fail("URL %s has no host", raw)
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
		v, known, err := reveal(h.Value)
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

func redirectPolicy(sensitive []string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", MaxRedirects)
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

// netError classifies err, an error from sending p to the URL wire.
func (c *Client) netError(p *core.Prepared, s core.Secrets, wire string, err error) error {
	msg := hide(p, s, wire, err.Error())
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return core.Errorf(core.KindTimeout, p.Request.Source, "no complete response within %s: %s", c.opts.Timeout, msg)
	}
	return core.Errorf(core.KindNetwork, p.Request.Source, "%s", msg)
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
