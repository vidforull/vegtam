package output

import (
	"crypto/tls"
	"net/url"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/exec"
)

// Timing is how long a request took. The phases are those of curl -w and
// Hurl: each runs from the start of the request to the end of the phase,
// and is absent if it did not happen, such as a DNS lookup of an IP
// address, or any but the first byte on a connection used before. With
// redirects, each phase is the sum over the hops, as curl adds them up.
type Timing struct {
	TotalMS         float64  `json:"total_ms"` // from sending to the end of the body, or to the error
	NameLookupMS    *float64 `json:"name_lookup_ms,omitempty"`
	ConnectMS       *float64 `json:"connect_ms,omitempty"`
	AppConnectMS    *float64 `json:"app_connect_ms,omitempty"` // the TLS handshake
	StartTransferMS *float64 `json:"start_transfer_ms,omitempty"`
	// Reused is true when no connection was made for the request: every
	// hop went on one that an earlier request had made.
	Reused bool `json:"reused"`
}

// TLS is what the TLS handshake of a response agreed on.
type TLS struct {
	Version  string `json:"version,omitempty"` // such as "TLS 1.3"; absent if the handshake failed
	Cipher   string `json:"cipher,omitempty"`  // such as "TLS_AES_128_GCM_SHA256"; the same
	ALPN     string `json:"alpn,omitempty"`    // the protocol agreed on, such as "h2"
	Verified bool   `json:"verified"`          // the server's certificate was checked, and passed
	Peer     *Peer  `json:"peer,omitempty"`
}

// Peer is the server's certificate.
type Peer struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"` // RFC 3339, UTC
}

// Redirect is a response that redirected the request, followed or not.
type Redirect struct {
	Status   int    `json:"status"`
	Location string `json:"location"`
	// Dropped are the headers of the request that were not sent on, as
	// the redirect leaves the origin of the request.
	Dropped    []string `json:"dropped,omitempty"`
	RemoteAddr string   `json:"remote_addr,omitempty"`
	ResolvedBy string   `json:"resolved_by,omitempty"`
	Proxy      string   `json:"proxy,omitempty"`
	Timing     *Timing  `json:"timing"`
}

// Cookies are the cookies of a request, in the order of its hops: those
// the jar sent, and those the responses set. Their values are never shown.
type Cookies struct {
	Sent []Cookie    `json:"sent,omitempty"`
	Set  []SetCookie `json:"set,omitempty"`
}

// Cookie is a cookie of a hop, without its value.
type Cookie struct {
	Hop      int    `json:"hop"` // 0 for the request as written, n after the n-th redirect
	Name     string `json:"name"`
	Domain   string `json:"domain,omitempty"`    // the host it goes to, and its subdomains unless host_only
	Path     string `json:"path,omitempty"`      // the paths it goes to: this one and those below it
	HostOnly bool   `json:"host_only"`           // it goes to its domain alone, not to subdomains
	Secure   bool   `json:"secure"`              // it goes over https only
	HTTPOnly bool   `json:"http_only"`           // not for scripts; vegtam has none
	SameSite string `json:"same_site,omitempty"` // Strict, Lax or None, as set
	Expires  string `json:"expires,omitempty"`   // RFC 3339, UTC; absent for a cookie of the run alone
}

// SetCookie is a cookie a response set, and what became of it.
type SetCookie struct {
	Cookie
	Stored bool   `json:"stored"`           // the jar keeps it
	Reason string `json:"reason,omitempty"` // why it does not: refused, the jar off, or "removed"
}

// Diagnose sets what t, the trace of the request of res, says in res,
// with every secret value hidden by m: the timing, the address, proxy and
// TLS of the last hop, and the redirects before it. When the host of a hop
// holds a secret, as the host is, so are its address and the subject of
// its certificate: they would tell it.
func Diagnose(res *Result, t *exec.Trace, m *core.Masker) {
	if t == nil {
		return
	}
	res.Timing, res.hops = timing(t.Hops, t.Total), len(t.Hops)
	var cookies Cookies
	for i, h := range t.Hops {
		hide := secretHost(h, m)
		for _, c := range h.Sent {
			cookies.Sent = append(cookies.Sent, cookie(i, c, m, hide))
		}
		for _, c := range h.Set {
			cookies.Set = append(cookies.Set, SetCookie{cookie(i, c.Cookie, m, hide), c.Stored, m.Mask(c.Reason)})
		}
		if i < len(t.Hops)-1 || h.Redirect {
			res.Redirects = append(res.Redirects, Redirect{
				Status: h.Status, Location: m.Mask(h.Location), Dropped: h.Dropped,
				RemoteAddr: remoteAddr(h, m), ResolvedBy: h.ResolvedBy, Proxy: proxy(h.Proxy, m), Timing: timing([]exec.Hop{h}, h.Total),
			})
		}
	}
	if cookies.Sent != nil || cookies.Set != nil {
		res.Cookies = &cookies
	}
	if len(t.Hops) == 0 {
		return
	}
	last := t.Hops[len(t.Hops)-1]
	res.RemoteAddr, res.ResolvedBy, res.Proxy, res.last = remoteAddr(last, m), last.ResolvedBy, proxy(last.Proxy, m), timing([]exec.Hop{last}, last.Total)
	if i := last.TLS; i != nil {
		res.TLS = &TLS{ALPN: m.Mask(i.ALPN), Verified: i.Verified}
		if i.Version != 0 {
			res.TLS.Version, res.TLS.Cipher = tls.VersionName(i.Version), tls.CipherSuiteName(i.Cipher)
		}
		if c := i.Peer; c != nil {
			subject, issuer := c.Subject.String(), c.Issuer.String()
			// The certificate of a host that holds a secret names it, or its
			// address; its CA does not, unless it signed it itself.
			if secretHost(last, m) {
				if issuer == subject {
					issuer = "***"
				}
				subject = "***"
			}
			res.TLS.Peer = &Peer{m.Mask(subject), m.Mask(issuer), c.NotAfter.UTC().Format(time.RFC3339)}
		}
	}
}

// cookie returns c, a cookie of the hop-th hop, with every secret value
// hidden by m. Its domain is *** with hide, for a hop whose host holds a
// secret: it is the host, or a domain above it.
func cookie(hop int, c exec.Cookie, m *core.Masker, hide bool) Cookie {
	out := Cookie{
		Hop: hop, Name: m.Mask(c.Name), Domain: m.Mask(c.Domain), Path: m.Mask(c.Path),
		HostOnly: c.HostOnly, Secure: c.Secure, HTTPOnly: c.HTTPOnly, SameSite: c.SameSite,
	}
	if hide && out.Domain != "" {
		out.Domain = "***"
	}
	if !c.Expires.IsZero() {
		out.Expires = c.Expires.UTC().Format(time.RFC3339)
	}
	return out
}

// timing returns the timing of hops, which took total.
func timing(hops []exec.Hop, total time.Duration) *Timing {
	var dns, conn, tls, first time.Duration
	t := &Timing{TotalMS: ms(total), Reused: len(hops) > 0}
	for _, h := range hops {
		dns, conn, tls, first = dns+h.DNS, conn+h.Connect, tls+h.TLSDone, first+h.FirstByte
		t.Reused = t.Reused && h.Reused
	}
	opt := func(d time.Duration) *float64 {
		if d == 0 {
			return nil
		}
		v := ms(d)
		return &v
	}
	t.NameLookupMS, t.ConnectMS, t.AppConnectMS, t.StartTransferMS = opt(dns), opt(conn), opt(tls), opt(first)
	return t
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// remoteAddr returns the address h connected to, or *** if its host holds
// a secret: the address would tell what the host is.
func remoteAddr(h exec.Hop, m *core.Masker) string {
	if h.RemoteAddr != "" && secretHost(h, m) {
		return "***"
	}
	return m.Mask(h.RemoteAddr)
}

// secretHost reports whether the host of h holds a secret.
func secretHost(h exec.Hop, m *core.Masker) bool { return m.Mask(h.URL.Host) != h.URL.Host }

// proxy returns the URL of a proxy with its user and password, which may
// come from the environment, shown as ***.
func proxy(u *url.URL, m *core.Masker) string {
	switch {
	case u == nil:
		return ""
	case u.User != nil:
		return m.Mask(u.Scheme + "://***@" + u.Host)
	}
	return m.Mask(u.Scheme + "://" + u.Host)
}
