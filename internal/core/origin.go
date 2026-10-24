package core

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Origin returns the origin of u as vegtam compares them: the scheme, the
// host in lower case without a final dot, and the port unless it is the
// scheme's own, such as https://api.example.com or http://127.0.0.1:8080.
func Origin(u *url.URL) string {
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if port == map[string]string{"http": "80", "https": "443"}[u.Scheme] {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host
}

// ParseOrigin returns s, an origin as a person writes it where a secret
// may go, as Origin writes it: an http or https URL with a host and maybe
// a port, and nothing after them but a "/". A wildcard is no origin.
func ParseOrigin(s string) (string, error) {
	want := fmt.Errorf("%q: want an origin, such as https://api.example.com or http://127.0.0.1:8080", s)
	u, err := url.Parse(s)
	switch {
	case err != nil, u.Scheme != "http" && u.Scheme != "https", u.Opaque != "":
		return "", want
	case u.User != nil, u.Path != "" && u.Path != "/", u.RawQuery != "", u.ForceQuery, strings.Contains(s, "#"):
		return "", want
	case strings.Contains(u.Host, "*"):
		return "", fmt.Errorf("%q: a secret goes to origins named one by one; a wildcard names none", s)
	}
	// A final dot is no part of the name; an empty label is no name.
	host := strings.TrimSuffix(u.Hostname(), ".")
	if host == "" || strings.Trim(strings.ToLower(host), "abcdefghijklmnopqrstuvwxyz0123456789-._:") != "" ||
		strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return "", want
	}
	if p := u.Port(); p != "" || strings.HasSuffix(u.Host, ":") {
		if n, err := strconv.ParseUint(p, 10, 16); err != nil || n == 0 {
			return "", want
		}
	}
	return Origin(u), nil
}

// Origins returns the origins a request to u goes to, whose Host header
// is host, "" for none: that of u, and, if host names another, the origin
// that host names over the scheme of u. A server that routes by the
// header, as a CDN does, sends the request where it names: a secret must
// be bound to both.
func Origins(u *url.URL, host string) []string {
	origins := []string{Origin(u)}
	if host == "" {
		return origins
	}
	if o := Origin(&url.URL{Scheme: u.Scheme, Host: host}); o != origins[0] {
		origins = append(origins, o)
	}
	return origins
}

// Origins returns where p goes, with its secrets revealed from src, as
// the function Origins says, and whether that is known: not if Text.Origin
// does not know the origin of the URL, nor if a value known only when the
// request is sent (ErrLate) is part of its Host header.
func (p *Prepared) Origins(src Secrets) ([]string, bool, error) {
	o, known, err := p.URL.Origin(src)
	if err != nil || !known {
		return nil, known, err
	}
	host := ""
	for _, h := range p.Headers {
		if !strings.EqualFold(h.Name, "Host") {
			continue
		}
		v, rerr := h.Value.Reveal(src)
		if errors.Is(rerr, ErrLate) {
			return nil, false, nil
		} else if rerr != nil {
			return nil, false, rerr
		}
		host = v // the last one, as the request takes it
	}
	u, err := url.Parse(o)
	if err != nil {
		return nil, false, err
	}
	return Origins(u, host), true, nil
}

// urlOrigin returns the origin of raw, a URL, if it is an http or https
// URL with a host.
func urlOrigin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return "", false
	}
	return Origin(u), true
}

// Origin returns the origin of t, a URL, with its secrets revealed from
// src, and whether it is known: not if the URL does not parse, nor if a
// value known only when the request is sent (ErrLate) is part of the
// scheme, host or port. One after them is no matter, as in
// https://api.example.com/?t={{$cmd TOKEN}} in a dry run, and nor is the
// error of one there; the error of one before them is returned.
func (t Text) Origin(src Secrets) (string, bool, error) {
	var b strings.Builder
	for _, s := range t {
		if s.Secret == nil {
			b.WriteString(s.Text)
			continue
		}
		v, err := src.SecretValue(*s.Secret)
		if err != nil {
			// Known if the authority has ended before it.
			if _, rest, ok := strings.Cut(b.String(), "://"); ok && strings.ContainsAny(rest, "/?#") {
				o, ok := urlOrigin(b.String())
				return o, ok, nil
			}
			if errors.Is(err, ErrLate) {
				return "", false, nil
			}
			return "", false, err
		}
		b.WriteString(v)
	}
	o, ok := urlOrigin(b.String())
	return o, ok, nil
}

// Texts returns the parts of p that may hold secrets: its URL, the values
// of its headers and its body, in that order.
func (p *Prepared) Texts() []Text {
	texts := []Text{p.URL}
	for _, h := range p.Headers {
		texts = append(texts, h.Value)
	}
	return append(texts, p.Body)
}

// Bound is a secret of a request, by name, and where it may go.
type Bound struct {
	Name    string   // its placeholder, such as {{token}} or {{$env TOKEN}}
	Origin  string   // where the request goes; "" if that is not known before it is sent
	Allowed []string // the origins it may go to, as Origin writes them; none for a secret bound to none
	// Capture is set for a value an @capture took from a response, which
	// may go back to the origin of that response alone.
	Capture bool
}

// Refused reports whether the request of b may not send it.
func (b Bound) Refused() bool { return b.Origin != "" && !slices.Contains(b.Allowed, b.Origin) }

// Bindings returns the secrets of texts, each once, in the order they
// appear, with the origins src lets each go to; origin is where the texts
// go, "" if that is not known.
func Bindings(src Secrets, origin string, texts ...Text) []Bound {
	var list []Bound
	for _, t := range texts {
		for _, seg := range t {
			s := seg.Secret
			if s == nil {
				continue
			}
			name := "{{" + s.Name + "}}"
			if slices.ContainsFunc(list, func(b Bound) bool { return b.Name == name }) {
				continue
			}
			allowed := slices.Clone(src.SecretOrigins(*s))
			slices.Sort(allowed)
			list = append(list, Bound{Name: name, Origin: origin, Allowed: slices.Compact(allowed), Capture: s.Capture})
		}
	}
	return list
}

// Refused returns those of bs that their request may not send.
func Refused(bs []Bound) []Bound {
	return slices.DeleteFunc(slices.Clone(bs), func(b Bound) bool { return !b.Refused() })
}

// Unbound returns the secrets of p that may not go to origin, as Bindings
// gives them.
func Unbound(p *Prepared, src Secrets, origin string) []Bound {
	return Refused(Bindings(src, origin, p.Texts()...))
}

// Grant returns src with every secret allowed to go to origin too: a
// person has confirmed that the request goes there with them.
func Grant(src Secrets, origin string) Secrets { return granted{src, origin} }

type granted struct {
	Secrets
	origin string
}

func (g granted) SecretOrigins(s Secret) []string {
	return append(slices.Clone(g.Secrets.SecretOrigins(s)), g.origin)
}

// SecretError returns the error of kind k of the request at src that
// would send the secrets refused, which may not go where it goes; what
// says what is refused, such as "a redirect to https://cdn.example". The
// first secret is the error's Secret.
func SecretError(k Kind, src Source, what string, refused []Bound) *Error {
	msg := Why(refused)
	if h := allowHint(refused); h != "" {
		msg += "; " + h
	}
	if what != "" {
		msg = what + ": " + msg
	}
	e := Errorf(k, src, "%s", msg)
	e.Secret = &refused[0]
	return e
}

// Why says of refused, secrets bound elsewhere, why they may not go
// where their request goes: "secret {{token}} may not go to
// https://exfil.example: its allowed origins are https://api.example.com".
func Why(refused []Bound) string {
	var b strings.Builder
	for i, r := range refused {
		switch {
		case i == 0:
			fmt.Fprintf(&b, "secret %s may not go to %s: ", r.Name, r.Origin)
		case r.Origin != refused[0].Origin:
			fmt.Fprintf(&b, "; nor may %s go to %s: ", r.Name, r.Origin)
		default:
			fmt.Fprintf(&b, "; nor may %s: ", r.Name)
		}
		switch {
		case r.Capture && len(r.Allowed) > 0:
			fmt.Fprintf(&b, "it was captured from a response of %s, and goes back there alone", strings.Join(r.Allowed, ", "))
		case r.Capture:
			b.WriteString("it was captured from a response whose origin is not known, and goes nowhere")
		case len(r.Allowed) == 0:
			b.WriteString("it is bound to no origin")
		default:
			fmt.Fprintf(&b, "its allowed origins are %s", strings.Join(r.Allowed, ", "))
		}
	}
	return b.String()
}

// allowHint says where a person binds the secrets of refused to more
// origins: a value of the private environment file in its $allow, one of
// {{$env NAME}} or {{$cmd NAME}} in the policy's secrets; "" if they are
// all captured, which Why says go back where they came from alone.
func allowHint(refused []Bound) string {
	var file, machine bool
	for _, b := range refused {
		switch {
		case b.Capture:
		case strings.HasPrefix(b.Name, "{{$"):
			machine = true
		default:
			file = true
		}
	}
	switch {
	case file && machine:
		return "allow it in http-client.private.env.json ($allow), or for {{$env NAME}} and {{$cmd NAME}} in the policy (secrets)"
	case file:
		return "allow it in http-client.private.env.json ($allow)"
	case machine:
		return "allow it in the policy (secrets)"
	}
	return ""
}
