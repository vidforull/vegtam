// Package exec sends prepared requests with net/http.
package exec

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
	req, sensitive, err := c.build(ctx, p, s)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Transport: c.transport, Timeout: c.opts.Timeout, CheckRedirect: redirectPolicy(sensitive)}
	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return nil, c.netError(p, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.opts.MaxBody+1))
	if err != nil {
		return nil, c.netError(p, err)
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

// build makes the request that goes on the wire. It also returns the
// headers that must not follow a redirect to another origin.
func (c *Client) build(ctx context.Context, p *core.Prepared, s core.Secrets) (*http.Request, []string, error) {
	src := p.Request.Source
	fail := func(format string, args ...any) error { return core.Errorf(core.KindRequest, src, format, args...) }
	reveal := func(t core.Text) (string, error) {
		v, err := t.Reveal(s)
		if err != nil {
			return "", core.Errorf(core.KindVariable, src, "%v", err)
		}
		return v, nil
	}
	raw, err := reveal(p.URL)
	if err != nil {
		return nil, nil, err
	}
	// Errors name the masked URL: the revealed one may hold secrets.
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, nil, fail("invalid URL %s: %v", p.URL.Masked(), errors.Unwrap(err))
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, nil, fail("URL %s: want an http or https URL", p.URL.Masked())
	case u.Host == "":
		return nil, nil, fail("URL %s has no host", p.URL.Masked())
	}
	body, err := reveal(p.Body)
	if err != nil {
		return nil, nil, err
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, p.Method, raw, rd)
	if err != nil {
		return nil, nil, fail("%v", err)
	}
	// net/http drops these on its own only when the host is not a
	// subdomain; vegtam drops them, and every header holding a secret, on
	// any change of origin.
	sensitive := []string{"Authorization", "Cookie", "Proxy-Authorization", "Referer"}
	for _, h := range p.Headers {
		v, err := reveal(h.Value)
		if err != nil {
			return nil, nil, err
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return nil, nil, fail("header %s: the value contains a line break or NUL", h.Name)
		}
		if h.Value.HasSecret() {
			sensitive = append(sensitive, h.Name)
		}
		if strings.EqualFold(h.Name, "Host") {
			req.Host = v
		} else {
			req.Header.Add(h.Name, v)
		}
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

func (c *Client) netError(p *core.Prepared, err error) error {
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return core.Errorf(core.KindTimeout, p.Request.Source, "no complete response within %s: %v", c.opts.Timeout, err)
	}
	return core.Errorf(core.KindNetwork, p.Request.Source, "%v", err)
}
