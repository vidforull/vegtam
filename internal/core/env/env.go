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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	bound    map[string][]string // in a dry run, the origins of the request whose @capture would take each variable
	taken    []string            // every secret value ever captured, for the masker
	old      []string            // the secrets read before the last Reload, for the masker

	cmdFiles map[string]*commands // command files read, by path
	ran      map[string]ran       // what each command gave, by command file path and name

	ssl   map[string]envMap   // the SSLConfiguration of each environment, by environment file path
	allow map[string]allowMap // the $allow of each environment, by environment file path

	stored    map[string]string   // the values the store handed out, for the masker
	inStoreOf map[string][]string // the secrets the store holds, with their origins; nil until asked
}

// Options configure a Loader.
type Options struct {
	Env string // the environment to select; "" for none
	// DryRun is set when no request is sent: commands are checked but not
	// run, and their values, like captured ones, are core.ErrLate.
	DryRun bool
	Trust  *policy.Store // the command files allowed to run; nil allows none
	// EnvHint says how to select an environment, in the error of a
	// variable that none is selected for: "use -e <name>" if empty.
	EnvHint string
	// Hidden are environment variables that no {{$env NAME}} may read:
	// those that hold the proxy's credentials, which go to the proxy alone.
	Hidden []string
	// Secrets are the origins the operator's policy binds the values of
	// {{$env NAME}} and {{$cmd NAME}} to: nothing else binds them.
	Secrets policy.Secrets
	// Store is the person's store of secrets: a {{name}} that the
	// private environment file does not give is taken from it. A run
	// without a person knows its names alone.
	Store Store
	// NoPrivate is set in a keeper, which reads no private environment
	// file: a run without a person may have put one where it looks. Its
	// secrets come from the store alone.
	NoPrivate bool
	// Held is set for a run without a person, which holds no secret
	// value. Of the private environment file the loader keeps the names
	// and $allow, never the values; it reads no {{$env NAME}}, and runs no
	// {{$cmd NAME}}, though it checks that its command file is trusted, as
	// a dry run does: each is a secret by its name alone. SecretValue gives
	// core.ErrHeld for every secret, captured ones too.
	Held bool
}

// Store is the person's encrypted store of secrets (see package store),
// as the loader reads it: the secrets it holds, by name, each with the
// origins it may go to, which need no password; and the value of one,
// which may ask for the password, once.
type Store interface {
	Origins() map[string][]string
	Value(name string) (string, error)
}

// captured is a value an @capture took.
type captured struct {
	value   string
	secret  bool
	origins []string // of the response it came from
	held    bool     // a keeper took it, and the run has no value: see Hold
}

// envMap is a parsed environment file: environment -> name -> value.
type envMap map[string]map[string]string

// allowMap is the $allow of each environment of a file: environment ->
// secret -> the origins it may go to, sorted, as core.Origin writes them.
// Of the public environment file, it has the environments that give one,
// and none of what they give.
type allowMap map[string]map[string][]string

// NewLoader returns a Loader. Without an environment, only {{$env NAME}}
// and captured variables resolve.
func NewLoader(opts Options) *Loader {
	return &Loader{
		opts: opts, dirs: map[string]*Vars{}, errs: map[string]error{},
		files: map[string]envMap{}, process: map[string]string{},
		declared: map[string]bool{}, captured: map[string]captured{}, lost: map[string]string{}, bound: map[string][]string{},
		cmdFiles: map[string]*commands{}, ran: map[string]ran{}, ssl: map[string]envMap{}, allow: map[string]allowMap{},
		stored: map[string]string{},
	}
}

// inStore reports whether the person's store holds a secret named name,
// and the origins it may go to.
func (l *Loader) inStore(name string) ([]string, bool) {
	if l.opts.Store == nil {
		return nil, false
	}
	if l.inStoreOf == nil {
		l.inStoreOf = maps.Clone(l.opts.Store.Origins())
		if l.inStoreOf == nil {
			l.inStoreOf = map[string][]string{}
		}
	}
	origins, ok := l.inStoreOf[name]
	return origins, ok
}

// Masker returns a Masker for every secret the loader has handed out or
// read: all private values of the selected environment, the process
// environment values that placeholders referred to, the output of the
// commands run, and the secret values captured so far.
func (l *Loader) Masker() *core.Masker {
	values := slices.Concat(l.taken, l.old)
	for _, v := range l.dirs {
		values = slices.AppendSeq(values, maps.Values(v.private))
	}
	values = slices.AppendSeq(values, maps.Values(l.stored))
	for _, r := range l.ran {
		values = append(values, r.value)
	}
	return core.NewMasker(slices.AppendSeq(values, maps.Values(l.process)))
}

// Reload drops the environment files and command files read so far, and
// what the commands gave, so that the requests prepared from now on see
// the files as they are then and run their commands again. Captured
// values stay, and the masker keeps every secret it knew.
func (l *Loader) Reload() {
	for _, v := range l.dirs {
		l.old = slices.AppendSeq(l.old, maps.Values(v.private))
	}
	for _, r := range l.ran {
		l.old = append(l.old, r.value)
	}
	slices.Sort(l.old)
	l.old = slices.Compact(l.old)
	l.dirs, l.errs, l.files = map[string]*Vars{}, map[string]error{}, map[string]envMap{}
	l.cmdFiles, l.ran = map[string]*commands{}, map[string]ran{}
}

// Declare makes name a variable that an @capture takes from a response.
// In every request prepared after the call, {{name}} refers to the value
// captured last, never to the environment.
func (l *Loader) Declare(name string) { l.declared[name] = true }

// Capture sets the value of the declared variable name, which a response
// from origins gave, for the requests sent from now on. A secret value is
// also masked from now on, and goes to those origins alone.
func (l *Loader) Capture(name, value string, secret bool, origins ...string) {
	l.captured[name] = captured{value: value, secret: secret, origins: known(origins)}
	delete(l.lost, name)
	if secret {
		l.taken = append(l.taken, value)
	}
}

// Hold makes the declared variable name one whose secret value a keeper
// took, from a response of origins, and keeps: the run knows its name and
// where it may go, and never its value.
func (l *Loader) Hold(name string, origins ...string) {
	l.captured[name] = captured{secret: true, origins: known(origins), held: true}
	delete(l.lost, name)
}

// Captured returns the value that the latest @capture of name took, if it
// took one, whether it is a secret, and the origins of the response it
// came from. A value a keeper holds (see Hold) is "".
func (l *Loader) Captured(name string) (value string, secret bool, origins []string, ok bool) {
	c, ok := l.captured[name]
	return c.value, c.secret, slices.Clone(c.origins), ok
}

// Forget drops the value of name: the latest @capture of it, in the
// request ref, took none, and the requests after it must not use an
// older one.
func (l *Loader) Forget(name, ref string) {
	delete(l.captured, name)
	l.lost[name] = ref
}

// Lost returns the variables whose latest @capture took no value, each
// with the request it was in.
func (l *Loader) Lost() map[string]string { return maps.Clone(l.lost) }

// Fill returns p with the plain values captured so far in place of their
// placeholders; secret ones stay placeholders, as other secrets do. A
// captured variable without a value is an error of kind variable that
// names them all. In a dry run, nothing has been captured: a variable
// stays a placeholder unless Forget has dropped it.
func (l *Loader) Fill(p *core.Prepared) (*core.Prepared, error) {
	var missing, why []string
	fill := func(t core.Text) core.Text {
		var out core.Text
		for _, seg := range t {
			if s := seg.Secret; s != nil && s.Capture {
				c, ok := l.captured[s.Name]
				_, lost := l.lost[s.Name]
				switch {
				case ok && !c.secret:
					seg = core.Segment{Text: c.value}
				case ok, l.opts.DryRun && !lost, slices.Contains(missing, s.Name):
				default:
					missing = append(missing, s.Name)
					why = append(why, fmt.Sprintf("%s (%s took no value)", s.Name, cmp.Or(l.lost[s.Name], "an earlier request")))
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

// Lookup returns the value of the environment variable name of the
// process, as {{$env NAME}} reads it: the operator's policy names the
// credentials of its proxy so.
func Lookup(name string) (string, bool) { return os.LookupEnv(name) }

// Has reports whether the environment variable name of the process holds
// a value, one that is not empty, without handing the value out: vegtam
// doctor says which secrets the environment holds, never what they are.
func Has(name string) bool {
	v, ok := os.LookupEnv(name)
	return ok && v != ""
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
	// allow are the origins the private environment file binds its
	// values to ($allow), by variable.
	allow    map[string][]string
	cmd      *commands // the command file, once a request needs it
	cmdErr   error
	warnings []core.Warning
}

// stored reports whether the person's store holds the secret name.
func (v *Vars) stored(name string) bool {
	_, ok := v.loader.inStore(name)
	return ok
}

// Warnings returns what the environment files of v say that vegtam does
// not apply.
func (v *Vars) Warnings() []core.Warning { return v.warnings }

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
	v := &Vars{loader: l, dir: dir, public: map[string]string{}, private: map[string]string{}, allow: map[string][]string{}}
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
	selected, private := false, ""
	for _, f := range []struct {
		name string
		dst  map[string]string
	}{{PublicFile, v.public}, {PrivateFile, v.private}} {
		path := Nearest(abs, f.name)
		if path == "" || f.name == PrivateFile && l.opts.NoPrivate {
			continue
		}
		m, err := l.read(path)
		if err != nil {
			return nil, err
		}
		found = append(found, path)
		v.warnings = append(v.warnings, sslWarnings(path, l.ssl[path], env)...)
		if f.name == PublicFile {
			v.warnings = append(v.warnings, publicAllowWarnings(path, l.allow[path], env)...)
		} else {
			private = path
		}
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
	if private != "" {
		v.warnings = append(v.warnings, v.bind(private, l.allow[private], env)...)
		for _, name := range slices.Sorted(maps.Keys(v.private)) {
			if _, ok := l.inStore(name); ok {
				v.warnings = append(v.warnings, core.Warning{Source: core.Source{File: private}, Msg: fmt.Sprintf(
					"{{%s}} is in this file and in the store of secrets: the file's value is used, and its $allow", name)})
			}
		}
	}
	return v, nil
}

// bind sets the origins that the private environment file at path binds
// the secrets of env to: those of the $allow of $shared, and then those of
// env's, which replace them name by name, as its values do. It says which
// plain name is no variable of the file, and leaves it out.
func (v *Vars) bind(path string, allow allowMap, env string) []core.Warning {
	from := map[string]string{} // the environment that binds each name
	for _, e := range []string{shared, env} {
		for name, origins := range allow[e] {
			v.allow[name], from[name] = origins, e
		}
	}
	var ws []core.Warning
	for _, name := range slices.Sorted(maps.Keys(v.allow)) {
		var msg string
		if fn, n, ok := strings.Cut(name, " "); ok {
			msg = fmt.Sprintf("%s.%s.%s is ignored: {{%s}} is a value of the machine, not of the file, which may have come with the requests; "+
				"bind it in the policy (secrets.%s.%s)", from[name], allowKey, name, name, strings.TrimPrefix(fn, "$"), n)
		} else if _, ok := v.private[name]; !ok {
			msg = fmt.Sprintf("%s.%s.%s: %s is not a variable of the private environment file: ignored", from[name], allowKey, name, name)
		} else {
			continue
		}
		delete(v.allow, name)
		ws = append(ws, core.Warning{Source: core.Source{File: path}, Msg: msg})
	}
	return ws
}

// Private is what a private environment file gives one environment: the
// values of $shared and of the environment, which replace them name by
// name, and the origins its $allow binds each to, as Loader reads them.
type Private struct {
	Values   map[string]string
	Allow    map[string][]string
	Warnings []core.Warning
}

// ReadPrivate reads the private environment file at path for the
// environment env, or for $shared alone if env is "". It returns the
// environments the file defines too, without $shared, sorted, for a caller
// that must choose one.
func ReadPrivate(path, env string) (*Private, []string, error) {
	l := NewLoader(Options{})
	m, err := l.read(path)
	if err != nil {
		return nil, nil, err
	}
	envs := slices.Sorted(maps.Keys(m))
	envs = slices.DeleteFunc(envs, func(s string) bool { return strings.HasPrefix(s, "$") })
	if _, ok := m[env]; env != "" && !ok {
		return nil, envs, core.Errorf(core.KindUsage, core.Source{File: path}, "environment %q is not defined (defined: %s)", env, strings.Join(envs, ", "))
	}
	v := &Vars{loader: l, private: map[string]string{}, allow: map[string][]string{}}
	maps.Copy(v.private, m[shared])
	maps.Copy(v.private, m[env])
	ws := v.bind(path, l.allow[path], cmp.Or(env, shared))
	return &Private{Values: v.private, Allow: v.allow, Warnings: ws}, envs, nil
}

// Names returns the environments that the environment files for the
// .http file at path define, sorted, without $shared and other names
// that start with "$": what Options.Env can select for its requests.
func Names(path string) ([]string, error) {
	abs, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	l := NewLoader(Options{})
	var names []string
	for _, name := range []string{PublicFile, PrivateFile} {
		if p := Nearest(abs, name); p != "" {
			m, err := l.read(p)
			if err != nil {
				return nil, err
			}
			names = slices.AppendSeq(names, maps.Keys(m))
		}
	}
	names = slices.DeleteFunc(names, func(s string) bool { return strings.HasPrefix(s, "$") })
	slices.Sort(names)
	return slices.Compact(names), nil
}

// Nearest returns the path of the file named name in dir, an absolute
// path, or in the closest directory above it; "" if there is none. The
// requests of the .http files in dir find their environment files and
// their command file so.
func Nearest(dir, name string) string {
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
// with string, number or boolean values. Neither SSLConfiguration nor
// $allow is a variable; the $allow of the private environment file must
// be as parseAllow wants it, and that of the public one is not read.
func (l *Loader) read(path string) (envMap, error) {
	if m, ok := l.files[path]; ok {
		return m, nil
	}
	fail := func(format string, args ...any) error {
		return core.Errorf(core.KindParse, core.Source{File: path}, format, args...)
	}
	src, err := os.ReadFile(path) //nolint:forbidigo,gosec // G304: an environment file, found by its name from the .http file's directory up
	if err != nil {
		return nil, fail("%v", err)
	}
	if l.opts.Held && filepath.Base(path) == PrivateFile {
		return l.readNames(path, src, fail)
	}
	var raw map[string]map[string]any
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fail("%v", err)
	}
	m, ssl, allow := envMap{}, envMap{}, allowMap{}
	private := filepath.Base(path) == PrivateFile
	for env, vars := range raw {
		m[env] = map[string]string{}
		for name, val := range vars {
			if name == allowKey {
				a, aerr := parseAllow(env, val, private)
				if aerr != nil {
					return nil, fail("%v", aerr)
				}
				allow[env] = a
				continue
			}
			if cfg, ok := val.(map[string]any); ok && name == sslConfiguration {
				ssl[env] = map[string]string{}
				for k, v := range cfg {
					ssl[env][k] = fmt.Sprint(v)
				}
				continue
			}
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
	l.files[path], l.ssl[path], l.allow[path] = m, ssl, allow
	return m, nil
}

// readNames parses src, the private environment file at path, as read
// does, for a run that holds no secret value: each variable gets the
// value "", and no string is made of a value. The values are decoded as
// raw bytes, checked to be strings, numbers or booleans, and zeroed with
// the file's bytes; what is left of them is what Go's reading of the file
// left in memory, which nothing refers to.
func (l *Loader) readNames(path string, src []byte, fail func(string, ...any) error) (envMap, error) {
	defer clear(src)
	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal(src, &raw); err != nil {
		return nil, fail("%v", err)
	}
	m, ssl, allow := envMap{}, envMap{}, allowMap{}
	defer func() {
		for _, vars := range raw {
			for _, v := range vars {
				clear(v)
			}
		}
	}()
	for env, vars := range raw {
		m[env] = map[string]string{}
		for name, val := range vars {
			switch first := firstByte(val); {
			case name == allowKey, name == sslConfiguration && first == '{':
				if err := setting(env, name, val, ssl, allow); err != nil {
					return nil, fail("%v", err)
				}
			case first == '"', first == '-', '0' <= first && first <= '9', first == 't', first == 'f':
				m[env][name] = ""
			default:
				return nil, fail("%s.%s: value must be a string, number or boolean", env, name)
			}
		}
	}
	l.files[path], l.ssl[path], l.allow[path] = m, ssl, allow
	return m, nil
}

// setting decodes val, the $allow or the SSLConfiguration of env in the
// private environment file, which hold no secret, into allow or ssl, as
// read does.
func setting(env, name string, val json.RawMessage, ssl envMap, allow allowMap) error {
	var v any
	dec := json.NewDecoder(bytes.NewReader(val))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	if cfg, ok := v.(map[string]any); ok && name == sslConfiguration {
		ssl[env] = map[string]string{}
		for k, x := range cfg {
			ssl[env][k] = fmt.Sprint(x)
		}
		return nil
	}
	a, err := parseAllow(env, v, true)
	if err != nil {
		return err
	}
	allow[env] = a
	return nil
}

// firstByte returns the first byte of the JSON value v, or 0 for none.
func firstByte(v json.RawMessage) byte {
	if v = bytes.TrimLeft(v, " \t\r\n"); len(v) == 0 {
		return 0
	}
	return v[0]
}

// allowKey is the entry of an environment, in the private environment
// file, that binds its values to the origins they may go to:
//
//	"$allow": {"token": ["https://api.example.com"], "password": []}
//
// A value it binds to none, or leaves out, goes nowhere. It may name
// "$env NAME" and "$cmd NAME" too, which are ignored with a warning: they
// are the machine's values, which the policy binds, and the file may have
// come with the requests.
const allowKey = "$allow"

// parseAllow returns the $allow of env, val as the file gives it, with
// each origin as core.Origin writes it, sorted and each once. That of the
// public environment file, which binds nothing, is not read.
func parseAllow(env string, val any, private bool) (map[string][]string, error) {
	if !private {
		return nil, nil
	}
	entries, ok := val.(map[string]any)
	if !ok {
		return nil, fmt.Errorf(`%s.%s: want an object of secrets, each with the origins it may go to, such as {"token": ["https://api.example.com"]}`, env, allowKey)
	}
	allow := map[string][]string{}
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		if !allowable(name) {
			return nil, fmt.Errorf(`%s.%s: %q: want a variable name, "$env NAME" or "$cmd NAME"`, env, allowKey, name)
		}
		origins, err := parseOrigins(entries[name])
		if err != nil {
			return nil, fmt.Errorf("%s.%s.%s: %w", env, allowKey, name, err)
		}
		allow[name] = origins
	}
	return allow, nil
}

// parseOrigins returns val, an array of origins as a person writes them,
// as core.Origin writes them, sorted and each once.
func parseOrigins(val any) ([]string, error) {
	const want = `want an array of origins, such as ["https://api.example.com"]`
	list, ok := val.([]any)
	if !ok {
		return nil, errors.New(want)
	}
	origins := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, errors.New(want)
		}
		o, err := core.ParseOrigin(s)
		if err != nil {
			return nil, err
		}
		origins = append(origins, o)
	}
	slices.Sort(origins)
	return slices.Compact(origins), nil
}

// allowable reports whether name may be written in $allow: a variable,
// as in {{name}}, or "$env NAME" or "$cmd NAME", as their placeholders
// name them, which bind is left to say.
func allowable(name string) bool {
	if n, ok := strings.CutPrefix(name, "$env "); ok {
		return envVarName.MatchString(n)
	}
	if n, ok := strings.CutPrefix(name, "$cmd "); ok {
		return core.IsVarName(n)
	}
	return core.IsVarName(name)
}

// publicAllowWarnings says that the $allow the public environment file at
// path gives $shared and env is not applied: the file comes with the
// requests, and whoever wrote it may not be the person whose secrets they
// are.
func publicAllowWarnings(path string, allow allowMap, env string) []core.Warning {
	var ws []core.Warning
	for _, e := range []string{shared, env} {
		if _, ok := allow[e]; ok {
			ws = append(ws, core.Warning{Source: core.Source{File: path}, Msg: fmt.Sprintf(
				"%s.%s is ignored: the public environment file comes with the requests and binds no secret; write it in %s", e, allowKey, PrivateFile)})
		}
	}
	return ws
}

// sslConfiguration is the setting of JetBrains' environment files for
// TLS: whether to check the server's certificate, and the client's.
const sslConfiguration = "SSLConfiguration"

// sslWarnings says what is not applied of the SSLConfiguration that the
// environment file at path gives $shared and env: none of it. The file
// comes with the requests, and what weakens a check or belongs to the
// machine comes from flags.
func sslWarnings(path string, ssl envMap, env string) []core.Warning {
	var ws []core.Warning
	for _, e := range []string{shared, env} {
		for _, key := range slices.Sorted(maps.Keys(ssl[e])) {
			msg := "is not supported: ignored"
			switch key {
			case "verifyHostCertificate":
				if ssl[e][key] != "false" {
					continue
				}
				msg = "is ignored: an environment file may not turn off the check of server certificates; " +
					"trust the server's CA with --cacert, or use --insecure at a terminal"
			case "clientCertificate", "clientCertificateKey", "hasCertificatePassphrase":
				msg = "is not used: an environment file comes with the requests and does not choose a client certificate; pass --cert and --key"
			}
			ws = append(ws, core.Warning{Source: core.Source{File: path}, Msg: fmt.Sprintf("%s.%s.%s %s", e, sslConfiguration, key, msg)})
		}
	}
	return ws
}

// SecretValue returns the value of a secret named in a prepared request.
func (v *Vars) SecretValue(s core.Secret) (string, error) {
	l := v.loader
	if l.opts.Held {
		return "", core.ErrHeld
	}
	if s.Capture {
		if c, ok := l.captured[s.Name]; ok && c.held {
			return "", core.ErrHeld
		} else if ok {
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
		if slices.Contains(l.opts.Hidden, n) {
			// A keeper is handed the request as resolved: the check of
			// Prepare is made again here.
			return "", core.Errorf(core.KindPolicy, core.Source{}, "{{$env %s}} holds the credentials of the proxy, which go to the proxy alone: no request may send them", n)
		}
		if val, ok := l.getenv(n); ok {
			return val, nil
		}
		return "", fmt.Errorf("environment variable %s is not set", n)
	}
	if val, ok := v.private[s.Name]; ok {
		return val, nil
	}
	if _, ok := l.inStore(s.Name); ok {
		val, err := l.opts.Store.Value(s.Name)
		if err != nil {
			return "", err
		}
		l.stored[s.Name] = val
		return val, nil
	}
	return "", fmt.Errorf("no secret named %q", s.Name)
}

// Prepare resolves the placeholders of r and reads its body file. All
// unresolved variables are reported in one error. Outside a dry run, the
// commands of {{$cmd NAME}} placeholders run, until ctx is done.
func (v *Vars) Prepare(ctx context.Context, r *core.Request) (*core.Prepared, error) {
	res := resolver{vars: v, src: r.Source}
	p := &core.Prepared{Request: r, Method: r.Method, URL: res.text(ctx, r.URL), Body: res.text(ctx, r.Body)}
	for _, h := range r.Headers {
		p.Headers = append(p.Headers, core.PreparedHeader{Name: h.Name, Value: res.text(ctx, h.Value)})
	}
	if r.BodyFile != "" {
		b, err := readBodyFile(r)
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
			msg += " (no environment selected; " + cmp.Or(v.loader.opts.EnvHint, "use -e <name>") + ")"
		}
		e := core.Errorf(core.KindVariable, r.Source, "%s", msg)
		e.Variables = res.missing
		return nil, e
	}
	return p, nil
}

// MaxBodyFile is the largest body file a request may send.
const MaxBodyFile = 16 << 20

// readBodyFile reads the body file of r. Its path is relative to the
// directory of the .http file, and the file is opened through an os.Root
// of that directory: neither "..", an absolute path nor a symbolic link
// leads outside it, so that a .http file from someone else cannot send a
// file from elsewhere on the machine. It must be a regular file of at
// most MaxBodyFile bytes: opening a FIFO would wait for a writer, and a
// device could be read without end.
func readBodyFile(r *core.Request) ([]byte, error) {
	name := filepath.FromSlash(r.BodyFile)
	if !filepath.IsLocal(name) {
		return nil, fmt.Errorf("%s is outside the directory of the .http file", r.BodyFile)
	}
	root, err := os.OpenRoot(filepath.Dir(r.Source.File))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	// The kind and the size are known before the file is opened.
	fi, err := root.Stat(name)
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		return nil, fmt.Errorf("%s: %w", r.BodyFile, pe.Err) // not "statat"
	} else if err != nil {
		return nil, err
	}
	if err := bodyFileOK(r.BodyFile, fi); err != nil {
		return nil, err
	}
	return readOpened(root, name, r.BodyFile, fi)
}

// readOpened reads the file name in root, of which Stat gave fi, and
// which is shown as shown.
func readOpened(root *os.Root, name, shown string, fi fs.FileInfo) (b []byte, err error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	// Once open, it must still be the file Stat saw.
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(fi, opened) {
		return nil, fmt.Errorf("%s changed while it was opened", shown)
	}
	if b, err = io.ReadAll(io.LimitReader(f, MaxBodyFile+1)); err != nil {
		return nil, err
	}
	if len(b) > MaxBodyFile {
		return nil, fmt.Errorf("%s has grown past %d MiB, the most a body file may be", shown, MaxBodyFile>>20)
	}
	return b, nil
}

// bodyFileOK says what is wrong with a body file named name, if anything.
func bodyFileOK(name string, fi fs.FileInfo) error {
	what := ""
	switch t := fi.Mode().Type(); {
	case t.IsRegular():
		if fi.Size() > MaxBodyFile {
			return fmt.Errorf("%s is %d bytes, more than the %d MiB a body file may be", name, fi.Size(), MaxBodyFile>>20)
		}
		return nil
	case t.IsDir():
		what = "a directory"
	case t&fs.ModeNamedPipe != 0:
		what = "a named pipe"
	case t&fs.ModeSocket != 0:
		what = "a socket"
	case t&fs.ModeDevice != 0:
		what = "a device"
	default:
		what = "not a regular file"
	}
	return fmt.Errorf("%s is %s: a body file must be a regular file", name, what)
}

// Class is what a placeholder stands for.
type Class int

const (
	Unresolved Class = iota // nothing: preparing the request fails
	Plain                   // a value of the public environment file
	Secret                  // a private value, a process environment variable or the output of a command
	Captured                // the value that an @capture of an earlier request takes
)

// Classes returns what each placeholder of r stands for, by its
// canonical form, such as "{{token}}" or "{{$env NAME}}", as Prepare
// resolves it now. A {{$cmd NAME}} is a secret whatever its command file
// says: what is wrong with it is an error of Prepare. A text with a
// malformed placeholder gives none.
func (v *Vars) Classes(r *core.Request) map[string]Class {
	classes := map[string]Class{}
	texts := []string{r.URL, r.Body}
	for _, h := range r.Headers {
		texts = append(texts, h.Value)
	}
	for _, s := range texts {
		pieces, _ := core.ParseTemplate(s)
		for _, p := range pieces {
			if p.Ref != nil {
				classes[p.Ref.String()] = v.class(*p.Ref)
			}
		}
	}
	return classes
}

func (v *Vars) class(r core.Ref) Class {
	switch r.Func {
	case "":
		_, private := v.private[r.Name]
		_, public := v.public[r.Name]
		switch {
		case v.loader.declared[r.Name]:
			return Captured
		case private, v.stored(r.Name):
			return Secret
		case public:
			return Plain
		}
	case "$env":
		if !envVarName.MatchString(r.Name) {
			break
		}
		if v.loader.opts.Held {
			return Secret // whether it is set or not is the keeper's to know
		}
		if _, ok := v.loader.getenv(r.Name); ok {
			return Secret
		}
	case "$cmd":
		if core.IsVarName(r.Name) {
			return Secret
		}
	}
	return Unresolved
}

type resolver struct {
	vars    *Vars
	src     core.Source // the request
	missing []string
	fail    error // the first placeholder that cannot be resolved at all
}

func (rs *resolver) text(ctx context.Context, s string) core.Text {
	pieces, err := core.ParseTemplate(s)
	if err != nil && rs.fail == nil {
		rs.fail = err
	}
	var t core.Text
	for _, p := range pieces {
		if p.Ref == nil {
			t = append(t, core.Segment{Text: p.Text})
		} else {
			t = append(t, rs.ref(ctx, *p.Ref))
		}
	}
	return t
}

func (rs *resolver) ref(ctx context.Context, r core.Ref) core.Segment {
	secret := func(name string) core.Segment { return core.Segment{Secret: &core.Secret{Name: name}} }
	var err error
	switch r.Func {
	case "":
		switch rs.vars.class(r) {
		case Captured:
			return core.Segment{Secret: &core.Secret{Name: r.Name, Capture: true}}
		case Secret:
			return secret(r.Name)
		case Plain:
			return core.Segment{Text: rs.vars.public[r.Name]}
		case Unresolved:
			rs.miss(r.Name)
		}
	case "$env":
		if !envVarName.MatchString(r.Name) {
			err = fmt.Errorf("%s: want {{$env NAME}}", r)
		} else if slices.Contains(rs.vars.loader.opts.Hidden, r.Name) {
			err = core.Errorf(core.KindPolicy, rs.src, "%s holds the credentials of the proxy, which go to the proxy alone: no request may send them", r)
		} else if rs.vars.loader.opts.Held {
			return secret("$env " + r.Name)
		} else if _, ok := rs.vars.loader.getenv(r.Name); ok {
			return secret("$env " + r.Name)
		} else {
			rs.miss("$env " + r.Name)
		}
	case "$cmd":
		if !core.IsVarName(r.Name) {
			err = fmt.Errorf("%s: want {{$cmd NAME}}", r)
		} else if err = rs.vars.command(ctx, r, rs.src); err == nil {
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
