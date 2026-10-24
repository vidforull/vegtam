package env

import (
	"slices"
	"strings"

	"github.com/vidforull/vegtam/internal/core"
)

// SecretOrigins returns the origins the secret s may go to: for a value
// an @capture took, the origin of the response it came from, and in a dry
// run that of the request whose @capture would take it (see Bind); for a
// value of the private environment file, the origins the file binds it to
// ($allow); for {{$env NAME}} and {{$cmd NAME}}, those of the operator's
// policy alone. A file binds only the values it holds: the private file
// is found from the directory of the .http file up, so a repository can
// bring one, which may bind its own values anywhere but must not bind the
// machine's. Neither the public environment file nor a .http file binds
// a secret anywhere.
func (v *Vars) SecretOrigins(s core.Secret) []string {
	l := v.loader
	if s.Capture {
		if c, ok := l.captured[s.Name]; ok {
			return slices.Clone(c.origins)
		}
		if l.opts.DryRun {
			return slices.Clone(l.bound[s.Name])
		}
		return nil
	}
	var origins []string
	if n, ok := strings.CutPrefix(s.Name, "$env "); ok {
		origins = l.opts.Secrets.Env[n]
	} else if n, ok := strings.CutPrefix(s.Name, "$cmd "); ok {
		origins = l.opts.Secrets.Cmd[n]
	} else {
		origins = v.allow[s.Name]
	}
	origins = slices.Clone(origins)
	slices.Sort(origins)
	return slices.Compact(origins)
}

// Bind says, in a dry run, that the @capture of a request that goes to
// origins takes the variable name: the requests after it may send what it
// would take there. Outside a dry run, the response a value comes from
// says where it may go.
func (l *Loader) Bind(name string, origins ...string) {
	origins = known(origins)
	if len(origins) == 0 {
		delete(l.bound, name)
		return
	}
	l.bound[name] = origins
}

// known returns origins without "", for none known; nil if that leaves
// none.
func known(origins []string) []string {
	origins = slices.DeleteFunc(slices.Clone(origins), func(o string) bool { return o == "" })
	if len(origins) == 0 {
		return nil
	}
	return origins
}

// Bound returns, of a dry run, the origins each variable is bound to by
// Bind; of a run, the origins of the response each secret value captured
// so far came from.
func (l *Loader) Bound() map[string][]string {
	out := map[string][]string{}
	if l.opts.DryRun {
		for name, origins := range l.bound {
			out[name] = slices.Clone(origins)
		}
		return out
	}
	for name, c := range l.captured {
		if c.secret {
			out[name] = slices.Clone(c.origins)
		}
	}
	return out
}
