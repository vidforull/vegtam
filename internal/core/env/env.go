// Package env resolves the {{...}} placeholders of requests: variables
// from environment files in the JetBrains format, and {{$env NAME}} from
// the process environment. Values from the private environment file and
// from the process environment are secrets: prepared requests refer to
// them by name only.
package env

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/vidforull/vegtam/internal/core"
)

// The environment files, looked up from a .http file's directory upwards.
const (
	PublicFile  = "http-client.env.json"
	PrivateFile = "http-client.private.env.json"
)

// shared is the environment whose variables every environment inherits.
const shared = "$shared"

var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Loader finds environment files and hands out the variables for each
// .http file. One Loader serves one command.
type Loader struct {
	env     string            // selected environment; "" for none
	dirs    map[string]*Vars  // by .http file directory
	errs    map[string]error  // by .http file directory
	files   map[string]envMap // parsed environment files by path
	process map[string]string // process environment values handed out
}

// envMap is a parsed environment file: environment -> name -> value.
type envMap map[string]map[string]string

// NewLoader returns a Loader for the environment named env, or for no
// environment if env is empty: then only {{$env NAME}} resolves.
func NewLoader(env string) *Loader {
	return &Loader{env: env, dirs: map[string]*Vars{}, errs: map[string]error{},
		files: map[string]envMap{}, process: map[string]string{}}
}

// Masker returns a Masker for every secret the loader has handed out or
// read: all private values of the selected environment and the process
// environment values that placeholders referred to.
func (l *Loader) Masker() *core.Masker {
	var values []string
	for _, v := range l.dirs {
		values = slices.AppendSeq(values, maps.Values(v.private))
	}
	return core.NewMasker(slices.AppendSeq(values, maps.Values(l.process)))
}

func (l *Loader) getenv(name string) (string, bool) {
	v, ok := os.LookupEnv(name)
	if ok {
		l.process[name] = v
	}
	return v, ok
}

// Vars are the variables visible to the requests of one directory.
type Vars struct {
	loader  *Loader
	public  map[string]string
	private map[string]string
}

// For returns the variables for the requests of the .http file at path.
func (l *Loader) For(path string) (*Vars, error) {
	dir := filepath.Dir(path)
	if v, ok := l.dirs[dir]; ok {
		return v, nil
	}
	if err, ok := l.errs[dir]; ok {
		return nil, err
	}
	v, err := l.load(dir)
	if err != nil {
		l.errs[dir] = err
		return nil, err
	}
	l.dirs[dir] = v
	return v, nil
}

func (l *Loader) load(dir string) (*Vars, error) {
	v := &Vars{loader: l, public: map[string]string{}, private: map[string]string{}}
	if l.env == "" {
		return v, nil
	}
	if strings.HasPrefix(l.env, "$") {
		return nil, core.Errorf(core.KindUsage, core.Source{}, "invalid environment name %q", l.env)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	var found, defined []string
	selected := false
	for _, f := range []struct {
		name string
		dst  map[string]string
	}{{PublicFile, v.public}, {PrivateFile, v.private}} {
		path := nearest(abs, f.name)
		if path == "" {
			continue
		}
		m, err := l.read(path)
		if err != nil {
			return nil, err
		}
		found = append(found, path)
		defined = append(defined, slices.Collect(maps.Keys(m))...)
		maps.Copy(f.dst, m[shared])
		vars, ok := m[l.env]
		maps.Copy(f.dst, vars)
		selected = selected || ok
	}
	switch {
	case len(found) == 0:
		return nil, core.Errorf(core.KindUsage, core.Source{},
			"environment %q: no %s or %s in %s or above", l.env, PublicFile, PrivateFile, abs)
	case !selected:
		defined = slices.DeleteFunc(defined, func(s string) bool { return s == shared })
		slices.Sort(defined)
		return nil, core.Errorf(core.KindUsage, core.Source{}, "environment %q is not defined in %s (defined: %s)",
			l.env, strings.Join(found, ", "), strings.Join(slices.Compact(defined), ", "))
	}
	return v, nil
}

// nearest returns the path of the file named name in dir or the closest
// directory above it, or "" if there is none.
func nearest(dir, name string) string {
	for {
		path := filepath.Join(dir, name)
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			return path
		}
		up := filepath.Dir(dir)
		if up == dir {
			return ""
		}
		dir = up
	}
}

// read parses the environment file at path: {"<env>": {"<name>": value}}
// with string, number or boolean values.
func (l *Loader) read(path string) (envMap, error) {
	if m, ok := l.files[path]; ok {
		return m, nil
	}
	fail := func(format string, args ...any) error {
		return core.Errorf(core.KindParse, core.Source{File: path}, format, args...)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fail("%v", err)
	}
	var raw map[string]map[string]any
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fail("%v", err)
	}
	m := envMap{}
	for env, vars := range raw {
		m[env] = map[string]string{}
		for name, val := range vars {
			switch val := val.(type) {
			case string:
				m[env][name] = val
			case json.Number:
				m[env][name] = val.String()
			case bool:
				m[env][name] = strconv.FormatBool(val)
			default:
				return nil, fail("%s.%s: value must be a string, number or boolean", env, name)
			}
		}
	}
	l.files[path] = m
	return m, nil
}

// SecretValue returns the value of a secret named in a prepared request.
func (v *Vars) SecretValue(name string) (string, error) {
	if n, ok := strings.CutPrefix(name, "$env "); ok {
		if val, ok := v.loader.getenv(n); ok {
			return val, nil
		}
		return "", fmt.Errorf("environment variable %s is not set", n)
	}
	if val, ok := v.private[name]; ok {
		return val, nil
	}
	return "", fmt.Errorf("no secret named %q", name)
}

// Prepare resolves the placeholders of r and reads its body file. All
// unresolved variables are reported in one error.
func (v *Vars) Prepare(r *core.Request) (*core.Prepared, error) {
	res := resolver{vars: v}
	p := &core.Prepared{Request: r, Method: r.Method, URL: res.text(r.URL), Body: res.text(r.Body)}
	for _, h := range r.Headers {
		p.Headers = append(p.Headers, core.PreparedHeader{Name: h.Name, Value: res.text(h.Value)})
	}
	if r.BodyFile != "" {
		path := r.BodyFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(r.Source.File), path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, core.Errorf(core.KindRequest, r.Source, "body file: %v", err)
		}
		p.Body = core.Text{{Text: string(b)}}
	}
	if res.fail != nil {
		return nil, core.Errorf(core.KindVariable, r.Source, "%v", res.fail)
	}
	if len(res.missing) > 0 {
		msg := "unresolved variables: " + strings.Join(res.missing, ", ")
		if v.loader.env == "" && slices.ContainsFunc(res.missing, func(s string) bool { return !strings.HasPrefix(s, "$") }) {
			msg += " (no environment selected; use -e <name>)"
		}
		e := core.Errorf(core.KindVariable, r.Source, "%s", msg)
		e.Variables = res.missing
		return nil, e
	}
	return p, nil
}

type resolver struct {
	vars    *Vars
	missing []string
	fail    error // the first placeholder that cannot be resolved at all
}

func (rs *resolver) text(s string) core.Text {
	pieces, err := core.ParseTemplate(s)
	if err != nil && rs.fail == nil {
		rs.fail = err
	}
	var t core.Text
	for _, p := range pieces {
		if p.Ref == nil {
			t = append(t, core.Segment{Text: p.Text})
		} else {
			t = append(t, rs.ref(*p.Ref))
		}
	}
	return t
}

func (rs *resolver) ref(r core.Ref) core.Segment {
	secret := func(name string) core.Segment { return core.Segment{Secret: &core.Secret{Name: name}} }
	var err error
	switch r.Func {
	case "":
		if _, ok := rs.vars.private[r.Name]; ok {
			return secret(r.Name)
		}
		if val, ok := rs.vars.public[r.Name]; ok {
			return core.Segment{Text: val}
		}
		rs.miss(r.Name)
	case "$env":
		if !envVarName.MatchString(r.Name) {
			err = fmt.Errorf("%s: want {{$env NAME}}", r)
		} else if _, ok := rs.vars.loader.getenv(r.Name); ok {
			return secret("$env " + r.Name)
		} else {
			rs.miss("$env " + r.Name)
		}
	case "$cmd":
		err = fmt.Errorf("%s: $cmd is not supported yet", r)
	default:
		err = fmt.Errorf("%s: unknown dynamic variable %s (supported: $env)", r, r.Func)
	}
	if err != nil && rs.fail == nil {
		rs.fail = err
	}
	return core.Segment{}
}

func (rs *resolver) miss(name string) {
	if !slices.Contains(rs.missing, name) {
		rs.missing = append(rs.missing, name)
	}
}
