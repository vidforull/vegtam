package exec

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
)

// cookie returns the cookie of the Set-Cookie header line.
func cookie(t *testing.T, line string) *http.Cookie {
	t.Helper()
	c, err := http.ParseSetCookie(line)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestJar checks the rules of the jar, each with a cookie that a response
// to a URL sets: what it keeps, and why it refuses the rest.
func TestJar(t *testing.T) {
	now := time.Now()
	u := func(s string) *url.URL {
		t.Helper()
		v, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	j := NewJar()
	set := func(from, line string) SetCookie {
		t.Helper()
		return j.set(u(from), []*http.Cookie{cookie(t, line)}, now)[0]
	}
	long := strings.Repeat("x", maxAttribute+1)
	for _, tt := range []struct {
		from, cookie string
		want         string // the reason it is not kept; "" if it is
	}{
		{"https://api.example.com/v1/login", "sid=1", ""},
		{"https://a.example.co.uk/", "wide=1; Domain=co.uk", "its Domain is a public suffix"},
		{"https://a.example.co.uk/", "site=1; Domain=.Example.co.uk", ""},
		{"https://api.example.com/", "other=1; Domain=example.org", "its Domain is neither the host nor a domain above it"},
		{"http://api.example.com/", "sec=1; Secure", "Secure, set over http"},
		{"https://api.example.com/", "__Secure-a=1", "__Secure- needs Secure, over https"},
		{"https://api.example.com/", "__secure-b=1; Secure", ""},
		{"https://api.example.com/", "__Host-a=1; Secure; Path=/; Domain=api.example.com", "__Host- needs"},
		{"https://api.example.com/", "__HOST-b=1; Secure; Path=/x", "__Host- needs"},
		{"https://api.example.com/", "__Host-c=1; Secure; Path=/", ""},
		{"https://api.example.com/", "big=" + strings.Repeat("v", maxCookieSize), "longer than 4096 bytes"},
		{"https://api.example.com/", "tok=1; Secure", ""},
		{"http://api.example.com/", "tok=2", "a Secure cookie of that name is kept"},
		{"http://api.example.com/", "tok=; Max-Age=0", "a Secure cookie of that name is kept"},
		{"http://127.0.0.1:8080/", "ip=1; Domain=127.0.0.1", ""},
		{"http://127.0.0.1:8080/", "ip2=1; Domain=127.0.0.2", "its Domain is not the address that set it"},
		{"http://localhost:8080/", "local=1; Secure", "Secure, set over http"}, // localhost too
		{"http://bücher.example/", "idn=1", "is not ASCII"},
		{"https://api.example.com/", "longpath=1; Path=/" + long, "its Domain or Path is longer than 1024 bytes"},
	} {
		got := set(tt.from, tt.cookie)
		if tt.want == "" && !got.Stored || tt.want != "" && (got.Stored || !strings.Contains(got.Reason, tt.want)) {
			t.Errorf("%s from %s: %+v, want %q", tt.cookie, tt.from, got, tt.want)
		}
	}
	// What goes where: net/http's jar decides it.
	names := func(to string) string {
		cs, sent := j.cookies(u(to))
		var s []string
		for i, c := range cs {
			s = append(s, c.Name+"@"+sent[i].Domain+sent[i].Path)
		}
		return strings.Join(s, " ")
	}
	for to, want := range map[string]string{
		"https://api.example.com/v1/x": "sid@api.example.com/v1 __secure-b@api.example.com/ __Host-c@api.example.com/ tok@api.example.com/",
		"http://api.example.com/v1/x":  "sid@api.example.com/v1", // not the Secure ones
		"https://b.example.co.uk/":     "site@example.co.uk/",
		"https://example.org/":         "",
		"http://127.0.0.1:9090/":       "ip@127.0.0.1/", // a cookie is for a host, whatever its port
	} {
		if got := names(to); got != want {
			t.Errorf("cookies for %s = %q, want %q", to, got, want)
		}
	}
	// A cookie that expires removes the one it names.
	if got := set("https://api.example.com/v1/", "sid=; Max-Age=0"); got.Reason != "removed" || strings.Contains(names("https://api.example.com/v1/"), "sid") {
		t.Errorf("removed: %+v, left %s", got, names("https://api.example.com/v1/"))
	}
}

// TestJarLimits checks the limits on the number of cookies: 50 for a
// site, 300 in all. A cookie that replaces one kept is no new one.
func TestJarLimits(t *testing.T) {
	j := NewJar()
	now := time.Now()
	fill := func(site string, n int) SetCookie {
		t.Helper()
		var last SetCookie
		for i := range n {
			last = j.set(&url.URL{Scheme: "https", Host: site, Path: "/"}, []*http.Cookie{cookie(t, fmt.Sprintf("c%d=v", i))}, now)[0]
		}
		return last
	}
	if got := fill("a.example.com", maxSiteCookies); !got.Stored {
		t.Fatalf("the 50th: %+v", got)
	}
	if got := fill("b.example.com", 1); got.Stored || got.Reason != "its site has 50 cookies already" {
		t.Errorf("the 51st of the site: %+v", got)
	}
	if got := fill("a.example.com", 1); !got.Stored {
		t.Errorf("one that replaces a cookie kept: %+v", got)
	}
	for i := range maxTotalCookies/maxSiteCookies - 1 {
		fill(fmt.Sprintf("example%d.com", i), maxSiteCookies)
	}
	if got := fill("example.net", 1); got.Stored || got.Reason != "the jar has 300 cookies already" {
		t.Errorf("the 301st: %+v", got)
	}
	// Cookies that have expired, of any site, make room.
	j = NewJar()
	for i := range maxTotalCookies / maxSiteCookies {
		for n := range maxSiteCookies {
			j.set(&url.URL{Scheme: "https", Host: fmt.Sprintf("example%d.com", i), Path: "/"}, []*http.Cookie{cookie(t, fmt.Sprintf("c%d=v; Max-Age=1", n))}, now)
		}
	}
	later := now.Add(2 * time.Second)
	if got := j.set(&url.URL{Scheme: "https", Host: "example.net", Path: "/"}, []*http.Cookie{cookie(t, "c=v")}, later)[0]; !got.Stored {
		t.Errorf("past expired cookies: %+v", got)
	}
}

// TestCookies sends requests that sign in, then use the session, as
// .http files do: the jar keeps the cookie for the requests after it,
// within the chain of redirects too, and sends it only where it goes.
func TestCookies(t *testing.T) {
	mu := make(chan struct{}, 1)
	var seen []string
	record := func(r *http.Request) {
		mu <- struct{}{}
		seen = append(seen, r.URL.Path+": "+r.Header.Get("Cookie"))
		<-mu
	}
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { record(r) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		switch r.URL.Path {
		case "/login":
			w.Header().Set("Set-Cookie", "sid=s3ss10n-value; Path=/; HttpOnly")
			http.Redirect(w, r, "/home", http.StatusFound)
		case "/away":
			// another host: localhost is not 127.0.0.1
			http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "localhost", 1)+"/elsewhere", http.StatusFound)
		}
	}))
	defer srv.Close()
	get := func(c *Client, path string, directives ...core.Directive) *Trace {
		t.Helper()
		p := prepared(http.MethodGet, lit(srv.URL+path), nil)
		p.Request.Directives = directives
		_, tr, err := c.Do(t.Context(), p, testSecrets)
		if err != nil {
			t.Fatal(err)
		}
		return tr
	}
	strict := core.Directive{Kind: core.NoCookieJar}
	c := New(Options{MaxBody: 1 << 20})
	login := get(c, "/login")
	get(c, "/me")
	get(c, "/me", strict)
	get(c, "/away")
	off := New(Options{MaxBody: 1 << 20, Transport: Transport{NoCookies: true}})
	noJar := get(off, "/login")
	get(off, "/me")
	fresh := New(Options{MaxBody: 1 << 20})
	notKept := get(fresh, "/login", strict)
	get(fresh, "/me")
	want := []string{
		"/login: ", "/home: sid=s3ss10n-value", // set by the redirect, sent on the next hop
		"/me: sid=s3ss10n-value",
		"/me: ",                                    // @no-cookie-jar: not read
		"/away: sid=s3ss10n-value", "/elsewhere: ", // not to another host
		"/login: ", "/home: ", "/me: ", // --no-cookies
		"/login: ", "/home: ", "/me: ", // @no-cookie-jar: not written either
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Errorf("the servers saw\n%s\nwant\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
	set, sent := login.Hops[0].Set, login.Hops[1].Sent
	if len(set) != 1 || !set[0].Stored || set[0].Value != "s3ss10n-value" || set[0].Domain != "127.0.0.1" || !set[0].HTTPOnly ||
		len(sent) != 1 || sent[0].Name != "sid" || sent[0].Path != "/" {
		t.Errorf("login: set %+v, sent %+v", set, sent)
	}
	if r := noJar.Hops[0].Set[0]; r.Stored || r.Reason != "the jar is off: --no-cookies" || r.Value != "s3ss10n-value" {
		t.Errorf("--no-cookies: %+v", r)
	}
	if r := notKept.Hops[0].Set[0]; r.Stored || r.Reason != "@no-cookie-jar" {
		t.Errorf("@no-cookie-jar: %+v", r)
	}
}

// TestSecureCookies checks that a Secure cookie does not go over http,
// and that one that is not does: to localhost and to 127.0.0.1 neither,
// to which net/http's jar would send it, and which net/http may reach
// through a proxy; nor to another host, which goes through a proxy of the
// test, which answers for it, so that nothing is looked up.
func TestSecureCookies(t *testing.T) {
	var got string
	record := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Get("Cookie") })
	plain := httptest.NewServer(record)
	defer plain.Close()
	p := newPKI(t)
	secure := p.server(t, tls.NoClientCert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "sec=1; Secure")
		w.Header().Add("Set-Cookie", "plain=2")
	}))
	c := New(Options{MaxBody: 1 << 20, Transport: Transport{TLS: TLS{Roots: p.pool()}}})
	send := func(u string) {
		t.Helper()
		if _, _, err := c.Do(t.Context(), prepared(http.MethodGet, lit(u), nil), testSecrets); err != nil {
			t.Fatal(err)
		}
	}
	for _, host := range []string{"127.0.0.1", "localhost"} {
		send(strings.Replace(secure.URL, "127.0.0.1", host, 1))
		if send(strings.Replace(plain.URL, "127.0.0.1", host, 1)); got != "plain=2" {
			t.Errorf("over http to %s: Cookie %q, want the cookie that is not Secure only", host, got)
		}
	}
	proxy := httptest.NewServer(record)
	defer proxy.Close()
	via, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	// A client of its own: a transport keeps the proxy it was made with.
	c = New(Options{MaxBody: 1 << 20})
	c.proxy = func(*http.Request) (*url.URL, error) { return via, nil }
	c.jar.set(&url.URL{Scheme: "https", Host: "api.example.test", Path: "/"},
		[]*http.Cookie{cookie(t, "sec=1; Secure"), cookie(t, "plain=2")}, time.Now())
	if send("http://api.example.test/"); got != "plain=2" {
		t.Errorf("over http to another host: Cookie %q, want the cookie that is not Secure only", got)
	}
}

// TestTooManyCookies checks the limit net/http keeps since CVE-2025-58186:
// a response that sets more than 3000 cookies sets none.
func TestTooManyCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := range 3001 {
			w.Header().Add("Set-Cookie", fmt.Sprintf("c%d=1", i))
		}
	}))
	defer srv.Close()
	c := New(Options{MaxBody: 1 << 20})
	_, tr, err := c.Do(t.Context(), prepared(http.MethodGet, lit(srv.URL), nil), testSecrets)
	if cs, _ := c.jar.cookies(&url.URL{Scheme: "http", Host: srv.Listener.Addr().String(), Path: "/"}); err != nil || len(tr.Hops[0].Set) != 0 || len(cs) != 0 {
		t.Errorf("%d set, %d kept, %v", len(tr.Hops[0].Set), len(cs), err)
	}
}
