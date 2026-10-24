package postman

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/vidforull/vegtam/internal/core"
)

// shared is the environment whose values every other one has, and
// allowKey the key under which an environment of the private file binds
// its secrets to the origins they may go to.
const (
	shared   = "$shared"
	allowKey = "$allow"
)

// written is a request written as a request, not commented out: its URL
// as written, and the variables its URL, headers and body send.
type written struct {
	url  string
	uses map[string]bool
}

// newWritten returns q, a request written as a request, as allow needs
// it.
func newWritten(q *rq) written {
	w := written{url: q.url, uses: map[string]bool{}}
	texts := []string{q.url, q.body}
	for _, h := range q.headers {
		texts = append(texts, h.Value)
	}
	for _, t := range texts {
		for _, name := range refs(t) {
			w.uses[name] = true
		}
	}
	return w
}

// allow returns the $allow of the private file of c, whose values are
// private, by environment: each secret that its requests send, bound to
// the one origin they send it to, as their URLs give it with the public
// values of the environment, in $shared if that origin is the same in
// every environment. A secret whose requests go to more than one origin,
// or to one not known here, is bound to none, and the report says, at
// where, to declare it: vegtam sends a secret only where it is bound. A
// secret without a value in an environment is not bound there, since
// vegtam binds only the variables of the file; the report asks for its
// value already.
func (imp *importer) allow(c *converter, public, private envMap, where string) map[string]map[string][]string {
	allow := map[string]map[string][]string{}
	bind := func(env, name, origin string) {
		if allow[env] == nil {
			allow[env] = map[string][]string{}
		}
		allow[env][name] = []string{origin}
	}
	type outcome struct{ env, origin, why string }
	for _, name := range imp.sentSecrets(c) {
		_, everywhere := private[shared][name]
		var out []outcome
		for _, e := range imp.envs {
			if _, ok := private[e.name][name]; !ok && !everywhere {
				continue
			}
			vars := maps.Clone(public[shared])
			if vars == nil {
				vars = map[string]string{}
			}
			maps.Copy(vars, public[e.name])
			o, why := sentTo(c.written, name, vars)
			out = append(out, outcome{e.name, o, why})
		}
		same := !slices.ContainsFunc(out, func(o outcome) bool { return o.origin != out[0].origin || o.why != out[0].why })
		switch {
		case len(out) == 0:
		case len(out) == len(imp.envs) && same && out[0].why == "":
			bind(shared, name, out[0].origin)
		case len(out) == len(imp.envs) && same:
			imp.skip("variable", fmt.Sprintf("declare $allow for {{%s}}: %s", name, out[0].why), where)
		default:
			for _, o := range out {
				if o.why == "" {
					bind(o.env, name, o.origin)
				} else {
					imp.skip("variable", fmt.Sprintf("declare $allow for {{%s}} in %s: %s", name, o.env, o.why), where)
				}
			}
		}
	}
	return allow
}

// sentSecrets returns the secrets that the requests of c written as
// requests send, sorted.
func (imp *importer) sentSecrets(c *converter) []string {
	set := map[string]bool{}
	for _, w := range c.written {
		for name := range w.uses {
			if imp.secret[name] {
				set[name] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// sentTo returns the origin that the requests ws send the variable name
// to, with the public values vars, or why there is not one.
func sentTo(ws []written, name string, vars map[string]string) (origin, why string) {
	set := map[string]bool{}
	for _, w := range ws {
		if !w.uses[name] {
			continue
		}
		o, ok := urlOrigin(w.url, vars)
		if !ok {
			return "", "the origin of its requests is not known"
		}
		set[o] = true
	}
	switch origins := slices.Sorted(maps.Keys(set)); len(origins) {
	case 0:
		return "", "no request sends it"
	case 1:
		return origins[0], ""
	default:
		return "", "its requests go to more than one origin (" + strings.Join(origins, ", ") + ")"
	}
}

// urlOrigin returns the origin of raw, a URL as the importer writes it,
// once the placeholders of vars are replaced by their values, as vegtam
// inserts them; and whether it is known. A placeholder of any other
// variable, such as a secret or one without a value, leaves it unknown
// unless the host has ended before it. The origin is as core.ParseOrigin
// writes it: what vegtam reads in $allow.
func urlOrigin(raw string, vars map[string]string) (string, bool) {
	var b strings.Builder
	last := 0
	for _, m := range placeholder.FindAllStringSubmatchIndex(raw, -1) {
		b.WriteString(raw[last:m[0]])
		last = m[1]
		v, ok := vars[strings.TrimSpace(raw[m[2]:m[3]])]
		if !ok {
			// Known if the host has ended before it: what follows is no
			// part of the origin.
			if _, rest, ok := strings.Cut(b.String(), "://"); !ok || !strings.ContainsAny(rest, "/?#") {
				return "", false
			}
			last = len(raw)
			break
		}
		b.WriteString(v)
	}
	b.WriteString(raw[last:])
	u, err := url.Parse(b.String())
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return "", false
	}
	o, err := core.ParseOrigin(core.Origin(u))
	return o, err == nil
}
