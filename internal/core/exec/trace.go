package exec

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"slices"
	"sync"
	"time"
)

// Trace is what a request went through: each hop, the request as written
// and then each redirect it followed, in order. Its values are those of
// the wire: a URL, an address or a header of a response may give a secret
// away, and it is output's to mask them.
type Trace struct {
	Hops  []Hop
	Total time.Duration // from sending to the end of the body, or to the error
}

// Hop is one request of a chain of redirects, and what came of it.
type Hop struct {
	URL *url.URL
	// The time from the start of the hop to the end of each phase, as curl
	// -w gives them: the DNS lookup, the connection, the TLS handshake and
	// the first byte of the response. A phase that did not happen is 0: the
	// lookup of an IP address, the first three on a connection used before.
	// Total runs to the next hop, or to the end of the body or the error.
	DNS, Connect, TLSDone, FirstByte, Total time.Duration

	Reused     bool     // the request went on a connection used before
	RemoteAddr string   // the address connected to, the proxy's through one; "" if no connection was made
	ResolvedBy string   // the flag that sent the connection elsewhere than the host: --resolve, --connect-to, --unix-socket or --abstract-unix-socket; "" for none
	Proxy      *url.URL // the proxy the hop went through; nil for none
	TLS        *TLSInfo // nil over http, and if no handshake got far enough
	Status     int      // 0 without a response
	Location   string   // the Location of a response, as the server wrote it
	// Redirect is set when the response redirected, and the redirect was
	// followed or refused: the response then has a hop after it, or ended
	// the request with an error. Dropped are the headers of the request
	// that were dropped to follow it.
	Redirect bool
	Dropped  []string
	Sent     []Cookie    // the cookies the jar sent
	Set      []SetCookie // the cookies the response set, and what became of them
}

// TLSInfo is what the TLS handshake of a hop agreed on.
type TLSInfo struct {
	Version  uint16 // 0 if the handshake failed: net/http gives no state then
	Cipher   uint16
	ALPN     string // the protocol agreed on, such as "h2"; "" for none
	Verified bool   // the server's certificate was checked, and passed
	// Peer is the server's certificate, also when it did not pass: what
	// it says tells which CA to trust. nil if the server sent none.
	Peer *x509.Certificate
}

// tracer records a Trace. Each hop has its own hooks, which net/http calls
// on several goroutines, and some once the hop is over, such as for a
// connection that lost the race of Happy Eyeballs: the hooks of a hop
// write to it alone, and nothing written after the trace is taken is in
// it.
type tracer struct {
	mu   sync.Mutex
	hops []*hopTrace
}

type hopTrace struct {
	t     *tracer
	start time.Time
	ended bool // its Total is set
	// conn is set once the hop has its connection: what a dial says after
	// that is of a connection the hop does not use, such as one net/http
	// went on making while another came free. proxyTLS is set once the
	// handshake with an https proxy is over.
	conn, proxyTLS bool
	hop            Hop
	// preface is the connection of the hop, once it has it, if it speaks
	// HTTP/2 with prior knowledge over http. One that fails before then,
	// as when the server resets it before the client's preface is out,
	// fails with an error of the network's: the server saw no HTTP/2.
	preface *preface
}

// hopKey is the context key of the hopTrace of a request.
type hopKey struct{}

// begin starts a hop for r, and ends the hop before it.
func (t *tracer) begin(r *http.Request) *hopTrace {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if n := len(t.hops); n > 0 {
		t.hops[n-1].end(now)
	}
	u := *r.URL
	h := &hopTrace{t: t, start: now, hop: Hop{URL: &u}}
	t.hops = append(t.hops, h)
	return h
}

// redirect notes that the latest hop got a redirect, which is followed
// unless refused, after dropping the headers dropped.
func (t *tracer) redirect(dropped []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n := len(t.hops); n > 0 {
		h := &t.hops[n-1].hop
		h.Redirect, h.Dropped = true, dropped
	}
}

// finish returns the trace of a request sent at start.
func (t *tracer) finish(start time.Time) *Trace {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	tr := &Trace{Total: now.Sub(start)}
	for _, h := range t.hops {
		h.end(now)
		hop := h.hop
		hop.Dropped, hop.Sent, hop.Set = slices.Clone(hop.Dropped), slices.Clone(hop.Sent), slices.Clone(hop.Set)
		if hop.TLS != nil {
			info := *hop.TLS
			hop.TLS = &info
		}
		tr.Hops = append(tr.Hops, hop)
	}
	return tr
}

// refusedPriorKnowledge reports whether the server of the latest hop
// showed that it does not speak HTTP/2 with prior knowledge (see
// preface).
func (t *tracer) refusedPriorKnowledge() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(t.hops)
	return n > 0 && t.hops[n-1].preface != nil && t.hops[n-1].preface.refused()
}

// dialed returns conn, a connection made for the hop on a transport that
// speaks HTTP/2 with prior knowledge, to its proxy with proxy: watched
// for what the server sends first, if the hop goes over http, and
// straight to the server or through a SOCKS proxy, which carries the
// hop's own bytes once its handshake is done. Over https, the handshake
// says what the server speaks; an http proxy is spoken to itself.
func (h *hopTrace) dialed(conn net.Conn, proxy bool) net.Conn {
	h.t.mu.Lock()
	defer h.t.mu.Unlock()
	socks := h.hop.Proxy != nil && (h.hop.Proxy.Scheme == "socks5" || h.hop.Proxy.Scheme == "socks5h")
	if h.hop.URL.Scheme != "http" || proxy && !socks {
		return conn
	}
	return &preface{Conn: conn}
}

// end sets the Total of h, if not yet. The tracer's lock is held.
func (h *hopTrace) end(now time.Time) {
	if !h.ended {
		h.hop.Total, h.ended = now.Sub(h.start), true
	}
}

// record calls f with the hop and the time since it started.
func (h *hopTrace) record(f func(hop *Hop, since time.Duration)) {
	h.t.mu.Lock()
	defer h.t.mu.Unlock()
	f(&h.hop, time.Since(h.start))
}

// got records the response of the hop, or the lack of one.
func (h *hopTrace) got(resp *http.Response) {
	if resp == nil {
		return
	}
	h.record(func(hop *Hop, _ time.Duration) {
		hop.Status, hop.Location = resp.StatusCode, resp.Header.Get("Location")
		// The handshake may be that of a connection used before. Over
		// http, it is that of an https proxy, if any.
		if resp.TLS != nil && hop.URL.Scheme == "https" {
			hop.TLS = tlsInfo(*resp.TLS, nil)
		}
	})
}

// cookies records the cookies the jar sent on the hop, and those its
// response set.
func (h *hopTrace) cookies(sent []Cookie, set []SetCookie) {
	h.record(func(hop *Hop, _ time.Duration) { hop.Sent, hop.Set = sent, set })
}

// proxyAddr returns the host and port of the proxy that the hop goes
// through, "" for none.
func (h *hopTrace) proxyAddr() string {
	h.t.mu.Lock()
	defer h.t.mu.Unlock()
	if h.hop.Proxy == nil {
		return ""
	}
	return proxyHostPort(h.hop.Proxy)
}

// routed records the flag that sends the connection of the hop
// elsewhere than its host, if any.
func (h *hopTrace) routed(by string) {
	if by != "" {
		h.record(func(hop *Hop, _ time.Duration) { hop.ResolvedBy = by })
	}
}

// proxied records the proxy u that the hop of r goes through.
func proxied(r *http.Request, u *url.URL) {
	if h, ok := r.Context().Value(hopKey{}).(*hopTrace); ok && u != nil {
		p := *u
		h.record(func(hop *Hop, _ time.Duration) { hop.Proxy = &p })
	}
}

// trace returns the hooks of the hop h, which drive w too. Getting a
// connection, for each hop of a redirect too, is the connect timeout's;
// waiting for a response once the request is written is the read
// timeout's, which starts anew when the response begins, so that net/http
// reading the body of a redirect counts as data coming.
func (w *watch) trace(h *hopTrace) *httptrace.ClientTrace {
	first := func(d *time.Duration, since time.Duration) {
		if *d == 0 {
			*d = since
		}
	}
	return &httptrace.ClientTrace{
		GetConn: func(string) { w.idle(); w.setConnecting(true) },
		DNSDone: func(i httptrace.DNSDoneInfo) {
			if i.Err == nil {
				h.record(func(hop *Hop, since time.Duration) {
					if !h.conn {
						first(&hop.DNS, since)
					}
				})
			}
		},
		// With Happy Eyeballs, the first connection made wins the race.
		// Its address is known before the TLS handshake, which may fail.
		ConnectDone: func(_, addr string, err error) {
			if err == nil {
				h.record(func(hop *Hop, since time.Duration) {
					if !h.conn && hop.Connect == 0 {
						hop.Connect, hop.RemoteAddr = since, addr
					}
				})
			}
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			h.record(func(hop *Hop, since time.Duration) {
				switch {
				case h.conn:
				// The proxy's own; the server's comes after it.
				case hop.Proxy != nil && hop.Proxy.Scheme == "https" && !h.proxyTLS:
					h.proxyTLS = true
				case hop.URL.Scheme != "https":
				case err != nil:
					hop.TLSDone, hop.TLS = 0, nil
					if info := tlsInfo(cs, err); info.Peer != nil {
						hop.TLS = info
					}
				default:
					hop.TLSDone, hop.TLS = since, tlsInfo(cs, nil)
				}
			})
		},
		// On a connection used before, any phase recorded was of a dial
		// that the hop does not use.
		GotConn: func(i httptrace.GotConnInfo) {
			w.setConnecting(false)
			h.record(func(hop *Hop, _ time.Duration) {
				h.conn, hop.Reused = true, i.Reused
				h.preface, _ = i.Conn.(*preface)
				if i.Reused {
					hop.DNS, hop.Connect, hop.TLSDone, hop.TLS = 0, 0, 0, nil
				}
				if i.Conn != nil {
					hop.RemoteAddr = i.Conn.RemoteAddr().String()
				}
			})
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { w.wait() },
		GotFirstResponseByte: func() {
			w.wait()
			h.record(func(hop *Hop, since time.Duration) { first(&hop.FirstByte, since) })
		},
		Got1xxResponse: func(int, textproto.MIMEHeader) error { w.wait(); return nil },
	}
}

// tlsInfo returns what cs, the state of a handshake that err ended, says.
func tlsInfo(cs tls.ConnectionState, err error) *TLSInfo {
	info := &TLSInfo{Version: cs.Version, Cipher: cs.CipherSuite, ALPN: cs.NegotiatedProtocol, Verified: len(cs.VerifiedChains) > 0}
	if len(cs.PeerCertificates) > 0 {
		info.Peer = cs.PeerCertificates[0]
	}
	if ve, ok := errors.AsType[*tls.CertificateVerificationError](err); ok && len(ve.UnverifiedCertificates) > 0 {
		info.Peer, info.Verified = ve.UnverifiedCertificates[0], false
	}
	return info
}
