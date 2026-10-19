// Package env resolves the {{...}} placeholders of requests: variables
// from environment files in the JetBrains format, {{$env NAME}} from the
// process environment, {{$cmd NAME}} from the output of a command in a
// trusted command file, and variables that @capture directives take from
// the responses of a run. Values from the private environment file, the
// process environment and commands, and captured values not marked plain,
// are secrets: prepared requests refer to them by name only.
package env

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/policy"
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
	opts    Options
	dirs    map[string]*Vars  // by .http file directory
	errs    map[string]error  // by .http file directory
	files   map[string]envMap // parsed environment files by path
	process map[string]string // process environment values handed out

	declared map[string]bool     // variables an @capture of a request prepared so far takes
	captured map[string]captured // the values taken so far
	lost     map[string]string   // variables whose latest capture took nothing: the request
	taken    []string            // every secret value ever captured, for the masker

	cmdFiles map[string]*commands // command files read, by path
	ran      map[string]ran       // what each command gave, by command file path and name
}

// Options configure a Loader.
type Options struct {
	Env string // the environment to select; "" for none
	// DryRun is set when no request is sent: commands are checked but not
	// run, and their values, like captured ones, are core.ErrLate.
	DryRun bool
	Trust  *policy.Store // the command files allowed to run; nil allows none
}

// captured is a value an @capture took.
type captured struct {
	value  string
	secret bool
}

// envMap is a parsed environment file: environment -> name -> value.
type envMap map[string]map[string]string

// NewLoader returns a Loader. Without an environment, only {{$env NAME}}
// and captured variables resolve.
func NewLoader(opts Options) *Loader {
	return &Loader{opts: opts, dirs: map[string]*Vars{}, errs: map[string]error{},
		files: map[string]envMap{}, process: map[string]string{},
		declared: map[string]bool{}, captured: map[string]captured{}, lost: map[string]string{},
		cmdFiles: map[string]*commands{}, ran: map[string]ran{}}
}

// Masker returns a Masker for every secret the loader has handed out or
// read: all private values of the selected environment, the process
// environment values that placeholders referred to, the output of the
// commands run, and the secret values captured so far.
func (l *Loader) Masker() *core.Masker {
	values := slices.Clone(l.taken)
	for _, v := range l.dirs {
		values = slices.AppendSeq(values, maps.Values(v.private))
	}
	for _, r := range l.ran {
		values = append(values, r.value)
	}
	return core.NewMasker(slices.AppendSeq(values, maps.Values(l.process)))
}

// Declare makes name a variable that an @capture takes from a response.
// In every request prepared after the call, {{name}} refers to the value
// captured last, never to the environment.
func (l *Loader) Declare(name string) { l.declared[name] = true }

// Capture sets the value of the declared variable name for the requests
// sent from now on. A secret value is also masked from now on.
func (l *Loader) Capture(name, value string, secret bool) {
	l.captured[name] = captured{value, secret}
	delete(l.lost, name)
	if secret {
		l.taken = append(l.taken, value)
	}
}

// Forget drops the value of name: the latest @capture of it, in the
// request ref, took none, and the requests after it must not use an
// older one.
func (l *Loader) Forget(name, ref string) {
	delete(l.captured, name)
	l.lost[name] = ref
}

// Fill returns p with the plain values captured so far in place of their
// placeholders; secret ones stay placeholders, as other secrets do. A
// captured variable without a value is an error of kind variable that
// names them all.
func (l *Loader) Fill(p *core.Prepared) (*core.Prepared, error) {
	var missing, why []string
	fill := func(t core.Text) core.Text {
		var out core.Text
		for _, seg := range t {
			if s := seg.Secret; s != nil && s.Capture {
				c, ok := l.captured[s.Name]
				switch {
				case !ok && !slices.Contains(missing, s.Name):
					missing = append(missing, s.Name)
					why = append(why, fmt.Sprintf("%s (%s took no value)", s.Name, cmp.Or(l.lost[s.Name], "an earlier request")))
				case ok && !c.secret:
					seg = core.Segment{Text: c.value}
				}
			}
			out = append(out, seg)
		}
		return out
	}
	q := *p
	q.URL, q.Body, q.Headers = fill(p.URL), fill(p.Body), nil
	for _, h := range p.Headers {
		q.Headers = append(q.Headers, core.PreparedHeader{Name: h.Name, Value: fill(h.Value)})
	}
	if len(missing) > 0 {
		e := core.Errorf(core.KindVariable, p.Request.Source, "not captured: %s", strings.Join(why, ", "))
		e.Variables = missing
		return nil, e
	}
	return &q, nil
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
	dir     string
	public  map[string]string
	private map[string]string
	cmd     *commands // the command file, once a request needs it
	cmdErr  error
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
	v := &Vars{loader: l, dir: dir, public: map[string]string{}, private: map[string]string{}}
	env := l.opts.Env
	if env == "" {
		return v, nil
	}
	if strings.HasPrefix(env, "$") {
		return nil, core.Errorf(core.KindUsage, core.Source{}, "invalid environment name %q", env)
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
		vars, ok := m[env]
		maps.Copy(f.dst, vars)
		selected = selected || ok
	}
	switch {
	case len(found) == 0:
		return nil, core.Errorf(core.KindUsage, core.Source{},
			"environment %q: no %s or %s in %s or above", env, PublicFile, PrivateFile, abs)
	case !selected:
		defined = slices.DeleteFunc(defined, func(s string) bool { return s == shared })
		slices.Sort(defined)
		return nil, core.Errorf(core.KindUsage, core.Source{}, "environment %q is not defined in %s (defined: %s)",
			env, strings.Join(found, ", "), strings.Join(slices.Compact(defined), ", "))
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
func (v *Vars) SecretValue(s core.Secret) (string, error) {
	l := v.loader
	if s.Capture {
		if c, ok := l.captured[s.Name]; ok {
			return c.value, nil
		}
		if l.opts.DryRun {
			return "", core.ErrLate
		}
		return "", fmt.Errorf("%s was not captured: the @capture of an earlier request took no value", s.Name)
	}
	if n, ok := strings.CutPrefix(s.Name, "$cmd "); ok {
		return v.commandValue(n)
	}
	if n, ok := strings.CutPrefix(s.Name, "$env "); ok {
		if val, ok := l.getenv(n); ok {
			return val, nil
		}
		return "", fmt.Errorf("environment variable %s is not set", n)
	}
	if val, ok := v.private[s.Name]; ok {
		return val, nil
	}
	return "", fmt.Errorf("no secret named %q", s.Name)
}

// Prepare resolves the placeholders of r and reads its body file. All
// unresolved variables are reported in one error.
func (v *Vars) Prepare(r *core.Request) (*core.Prepared, error) {
	res := resolver{vars: v, src: r.Source}
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
	if e, ok := errors.AsType[*core.Error](res.fail); ok {
		return nil, e
	} else if res.fail != nil {
		return nil, core.Errorf(core.KindVariable, r.Source, "%v", res.fail)
	}
	if len(res.missing) > 0 {
		msg := "unresolved variables: " + strings.Join(res.missing, ", ")
		if v.loader.opts.Env == "" && slices.ContainsFunc(res.missing, func(s string) bool { return !strings.HasPrefix(s, "$") }) {
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
	src     core.Source // the request
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
		if rs.vars.loader.declared[r.Name] {
			return core.Segment{Secret: &core.Secret{Name: r.Name, Capture: true}}
		}
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
		if !core.IsVarName(r.Name) {
			err = fmt.Errorf("%s: want {{$cmd NAME}}", r)
		} else if err = rs.vars.command(r, rs.src); err == nil {
			return secret("$cmd " + r.Name)
		}
	default:
		err = fmt.Errorf("%s: unknown dynamic variable %s (supported: $env, $cmd)", r, r.Func)
	}
	// The first error wins, but policy over any other: a request that a
	// person must allow says so whatever else is wrong with it.
	if err != nil && (rs.fail == nil || isPolicy(err) && !isPolicy(rs.fail)) {
		rs.fail = err
	}
	return core.Segment{}
}

func isPolicy(err error) bool {
	e, ok := errors.AsType[*core.Error](err)
	return ok && e.Kind == core.KindPolicy
}

func (rs *resolver) miss(name string) {
	if !slices.Contains(rs.missing, name) {
		rs.missing = append(rs.missing, name)
	}
}
