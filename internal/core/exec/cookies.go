package exec

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// The limits of the jar, those of RFC 6265bis: what a cookie may weigh,
// how many a site may keep, how many the jar keeps in all.
const (
	maxCookieSize   = 4096 // name and value
	maxAttribute    = 1024 // Domain, Path; RFC 6265bis ignores one longer, the jar the cookie
	maxSiteCookies  = 50   // for one registrable domain, such as example.com
	maxTotalCookies = 300
)

// Cookie is a cookie of a hop, without its value.
type Cookie struct {
	Name     string
	Domain   string // where it goes: the host alone if HostOnly, and its subdomains otherwise
	Path     string
	HostOnly bool
	Secure   bool
	HTTPOnly bool
	SameSite string    // Strict, Lax, None, or "" if not given
	Expires  time.Time // zero for a cookie of the run alone
}

// SetCookie is a cookie a response set, and what the jar did with it.
type SetCookie struct {
	Cookie
	Value  string // for the masker: the value is a secret
	Stored bool
	Reason string // why it was not stored, or "removed" for one that removes the cookie; no name in it
}

// Jar keeps the cookies of a run, in memory only: it is never written to
// disk. It is net/http's jar with the public suffix list, without which
// any site could set cookies for a whole suffix such as co.uk, and the
// rules of RFC 6265bis that net/http's jar does not have: a Secure cookie
// only from https, the __Secure- and __Host- prefixes, the limits. Which
// cookie goes where is the decision of net/http's jar, with one more
// rule: a Secure cookie goes over https only. net/http's jar, as browsers
// do, sends it over http to localhost too, and to any host under
// localhost, which net/http may send through a proxy. Jar refuses cookies
// first, and keeps what it took to count them and to say what was sent.
type Jar struct {
	jar  *cookiejar.Jar
	mu   sync.Mutex
	kept map[string]map[string]Cookie // by registrable domain, by name, domain and path
	vals map[string]string            // the value of each, by the same key
	n    int
}

// NewJar returns an empty Jar.
func NewJar() *Jar {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil { // cookiejar.New never fails
		panic(err)
	}
	return &Jar{jar: jar, kept: map[string]map[string]Cookie{}, vals: map[string]string{}}
}

// cookies returns the cookies for u, and what each is, as far as the
// jar can tell: net/http's gives their names and values alone. Over http,
// a cookie goes only if the jar knows it is not Secure.
func (j *Jar) cookies(u *url.URL) ([]*http.Cookie, []Cookie) {
	var site string
	if host, err := cookieHost(u); err == nil {
		site = siteOf(host)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	ids := slices.Sorted(maps.Keys(j.kept[site]))
	var cs []*http.Cookie
	var sent []Cookie
	for _, c := range j.jar.Cookies(u) {
		var info *Cookie
		for _, id := range ids {
			if k := j.kept[site][id]; k.Name == c.Name && j.vals[site+" "+id] == c.Value {
				info = &k
				break
			}
		}
		if u.Scheme != "https" && (info == nil || info.Secure) {
			continue
		}
		if info == nil {
			info = &Cookie{Name: c.Name}
		}
		cs, sent = append(cs, c), append(sent, *info)
	}
	return cs, sent
}

// values returns the values of the cookies the jar keeps.
func (j *Jar) values() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return slices.Collect(maps.Values(j.vals))
}

// set offers the jar the cookies that the response to u set, and returns
// what it did with each.
func (j *Jar) set(u *url.URL, cs []*http.Cookie, now time.Time) []SetCookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []SetCookie
	for _, c := range cs {
		s := j.setOne(u, c, now)
		s.Value = c.Value
		out = append(out, s)
	}
	return out
}

func (j *Jar) setOne(u *url.URL, c *http.Cookie, now time.Time) SetCookie {
	refuse := func(format string, args ...any) SetCookie {
		return SetCookie{Name: c.Name, Domain: c.Domain, Path: c.Path, Secure: c.Secure, HTTPOnly: c.HttpOnly, Reason: fmt.Sprintf(format, args...)}
	}
	host, err := cookieHost(u)
	if err != nil {
		return refuse("%v", err)
	}
	secure := u.Scheme == "https"
	if why := refusal(c, secure); why != "" {
		return refuse("%s", why)
	}
	domain, hostOnly, err := cookieDomain(host, c.Domain)
	if err != nil {
		return refuse("%v", err)
	}
	path := c.Path
	if path == "" || path[0] != '/' {
		path = defaultPath(u.Path)
	}
	info := Cookie{Name: c.Name, Domain: domain, Path: path, HostOnly: hostOnly, Secure: c.Secure, HTTPOnly: c.HttpOnly, SameSite: sameSite(c.SameSite)}
	site := siteOf(host)
	if j.kept[site] == nil {
		j.kept[site] = map[string]Cookie{}
	}
	j.expire(site, now)
	id := domain + ";" + path + ";" + c.Name
	_, known := j.kept[site][id]
	switch {
	// http may not replace a Secure cookie, shadow it nor remove it.
	case !secure && j.secureNamed(site, c.Name):
		return refuse("a Secure cookie of that name is kept, which http may not replace")
	case c.MaxAge < 0, c.MaxAge == 0 && !c.Expires.IsZero() && !c.Expires.After(now):
		j.jar.SetCookies(u, []*http.Cookie{c})
		if known {
			j.forget(site, id)
		}
		return SetCookie{Cookie: info, Reason: "removed"}
	case !known && len(j.kept[site]) >= maxSiteCookies:
		return refuse("its site has %d cookies already", maxSiteCookies)
	case !known && j.n >= maxTotalCookies && !j.expireAll(now):
		return refuse("the jar has %d cookies already", maxTotalCookies)
	}
	if c.MaxAge > 0 {
		info.Expires = now.Add(time.Duration(c.MaxAge) * time.Second)
	} else if !c.Expires.IsZero() {
		info.Expires = c.Expires
	}
	j.jar.SetCookies(u, []*http.Cookie{c})
	if !known {
		j.n++
	}
	j.kept[site][id], j.vals[site+" "+id] = info, c.Value
	return SetCookie{Cookie: info, Stored: true}
}

// refusal says why c, which a response over https or not (secure) sets,
// is refused, whatever the jar holds; "" if it is not.
func refusal(c *http.Cookie, secure bool) string {
	switch name := strings.ToLower(c.Name); {
	case len(c.Name)+len(c.Value) > maxCookieSize:
		return fmt.Sprintf("its name and value are longer than %d bytes", maxCookieSize)
	case len(c.Domain) > maxAttribute, len(c.Path) > maxAttribute:
		return fmt.Sprintf("its Domain or Path is longer than %d bytes", maxAttribute)
	case c.Secure && !secure:
		return "Secure, set over http"
	case strings.HasPrefix(name, "__secure-") && (!c.Secure || !secure):
		return "__Secure- needs Secure, over https"
	case strings.HasPrefix(name, "__host-") && (!c.Secure || !secure || c.Domain != "" || c.Path != "/"):
		return "__Host- needs Secure, over https, Path=/ and no Domain"
	}
	return ""
}

// expire forgets the cookies of site that have expired at now.
func (j *Jar) expire(site string, now time.Time) {
	for id, k := range j.kept[site] {
		if !k.Expires.IsZero() && !k.Expires.After(now) {
			j.forget(site, id)
		}
	}
}

// expireAll forgets every cookie that has expired at now, and reports
// whether the jar has room for one more then.
func (j *Jar) expireAll(now time.Time) bool {
	for site := range j.kept {
		j.expire(site, now)
	}
	return j.n < maxTotalCookies
}

func (j *Jar) forget(site, id string) {
	delete(j.kept[site], id)
	delete(j.vals, site+" "+id)
	j.n--
}

// secureNamed reports whether a Secure cookie named name is kept for site.
func (j *Jar) secureNamed(site, name string) bool {
	for _, k := range j.kept[site] {
		if k.Name == name && k.Secure {
			return true
		}
	}
	return false
}

// cookieHost returns the host of u as net/http's jar has it: lower case,
// without port or trailing dot. A host that is not ASCII is refused: the
// jar would turn it into punycode first.
func cookieHost(u *url.URL) (string, error) {
	host := u.Host
	if strings.Count(host, ":") == 1 || strings.HasPrefix(host, "[") && strings.Contains(host, "]:") {
		var err error
		if host, _, err = net.SplitHostPort(host); err != nil {
			return "", err
		}
	}
	host = strings.TrimSuffix(host, ".")
	for _, r := range host {
		if r >= 0x80 {
			return "", errors.New("the host is not ASCII")
		}
	}
	return strings.ToLower(host), nil
}

// siteOf returns the registrable domain of host, such as example.co.uk,
// which the limit of cookies is for: the key of net/http's jar.
func siteOf(host string) string {
	if isIP(host) {
		return host
	}
	if site, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return site
	}
	return host
}

func isIP(host string) bool { return strings.ContainsAny(host, ":%") || net.ParseIP(host) != nil }

// cookieDomain returns where a cookie with the Domain attribute domain,
// set by host, goes, and whether to host alone, as net/http's jar decides
// it (RFC 6265, 5.3): no other site, and no public suffix.
func cookieDomain(host, domain string) (string, bool, error) {
	if domain == "" {
		return host, true, nil
	}
	if isIP(host) {
		if host != domain {
			return "", false, errors.New("its Domain is not the address that set it")
		}
		return host, true, nil
	}
	d := strings.ToLower(strings.TrimPrefix(domain, "."))
	if d == "" || d[0] == '.' || d[len(d)-1] == '.' || strings.ContainsFunc(d, func(r rune) bool { return r >= 0x80 }) {
		return "", false, errors.New("its Domain is malformed")
	}
	if ps, _ := publicsuffix.PublicSuffix(d); ps == d {
		if host == d {
			return host, true, nil
		}
		return "", false, errors.New("its Domain is a public suffix")
	}
	if host != d && !strings.HasSuffix(host, "."+d) {
		return "", false, errors.New("its Domain is neither the host nor a domain above it")
	}
	return d, false, nil
}

// defaultPath returns the default path of a cookie set by the response to
// a request for path (RFC 6265, 5.1.4).
func defaultPath(path string) string {
	i := strings.LastIndex(path, "/")
	if i <= 0 || path[0] != '/' {
		return "/"
	}
	return path[:i]
}

func sameSite(s http.SameSite) string {
	switch s {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	case http.SameSiteDefaultMode:
	}
	return ""
}
