// Package session resolves and sends requests with one environment. The
// CLI and the terminal interface send requests through it and nothing
// else, so that a request goes out the same way from both.
package session

import (
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/assert"
	"github.com/vidforull/vegtam/internal/core/curl"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/exec"
	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// Options configure a Session.
type Options struct {
	Env string // the environment to use; "" for none
	// DryRun resolves and checks requests without sending them; commands
	// are checked against the trust store but do not run.
	DryRun    bool
	Trust     *policy.Store  // the command files allowed to run; nil allows none
	Transport exec.Transport // from the flags
	MaxBody   int64          // response body bytes kept
	UserAgent string
	Fail      bool   // a response status of 400 or above is an error of kind status
	EnvHint   string // see env.Options
	// Secrets are the origins the operator's policy lets the values of
	// {{$env NAME}} and {{$cmd NAME}} go to.
	Secrets policy.Secrets
	// History keeps each request sent, outside a dry run, unless it has
	// an @no-log directive; nil keeps none.
	History *history.Log
	// Confirm says which requests that need a confirmation are sent; its
	// zero value sends none of them. A dry run sends nothing, and says in
	// each result what sending it would need.
	Confirm Confirm
	// Store is the person's store of secrets: a {{name}} that the private
	// environment file does not give comes from it (see env.Options).
	Store env.Store
	// NoPrivate is set in a keeper, which reads no private environment
	// file: its secrets come from the store alone.
	NoPrivate bool
	// Keeper sends, for a run without a person (Confirm.Person unset), the
	// requests of a run in which one needs a secret value: such a run
	// holds none (see env.Options.Held). Nil, as the policy's
	// secrets.unattended "deny" has it, sends none of those: each is an
	// error of kind policy that names the command a person would run.
	Keeper Keeper
	// Serve is set in a keeper: the session sends what runs without a
	// person relay to it (see Relay), with the values it holds.
	Serve *Serve
}

// Session is one run: the environment loader that hands out variables and
// secrets, and the client that sends. A value an @capture takes is a
// variable for the requests prepared after the one it came from. A
// Session is not safe for concurrent use.
type Session struct {
	opts       Options
	loader     *env.Loader
	client     *exec.Client
	declared   []string        // the variables @capture directives take, in order
	historyErr error           // why the entry of the latest run was not kept
	warned     map[string]bool // the warnings of environment files a job has had
	once       map[string]bool // the requests ConfirmOnce has confirmed, by Key
	plain      map[string]bool // the variables whose latest @capture says plain
	// Secret values that no file holds: the latest values of cookies that
	// responses set, and the credentials of Basic written as user and
	// password.
	cookies, credentials []string
	// relay is set once a request prepared in a run without a person
	// needs a secret value and a keeper sends it: every request of the run
	// then goes through the keeper.
	relay bool
	// peek, if set, stands between the session and the secrets of its
	// requests: tests count what is asked of them.
	peek func(core.Secrets) core.Secrets
}

// src returns the secrets of the request of j. A run without a person
// asks them for no value: it says where each may go, and nothing more.
func (s *Session) src(j *Job) core.Secrets {
	var src core.Secrets = j.vars
	if s.peek != nil {
		src = s.peek(src)
	}
	if s.held() {
		src = withheld{src}
	}
	return src
}

// withheld are the secrets of a run without a person, which gives no
// value: each is core.ErrHeld.
type withheld struct{ core.Secrets }

func (withheld) SecretValue(core.Secret) (string, error) { return "", core.ErrHeld }

// The values of cookies that the masker hides wherever they are: from
// minCookieSecret bytes to maxCookieSecret, the most a cookie may be. A
// shorter one, such as lang=en or seen=1, is no credential, and hiding it
// would hide every "en" and "1"; a longer one is refused; either is still
// hidden where it shows as a cookie's (see output.Cookies). Those of the
// jar are hidden as long as it keeps them, and of the others the latest
// maxCookieSecrets: a server that set more would make the masker, which
// is made anew for each request, as large and slow as it liked.
const (
	minCookieSecret  = 8
	maxCookieSecret  = 4096
	maxCookieSecrets = 256
)

// New returns a Session.
func New(opts Options) *Session {
	return &Session{
		opts:   opts,
		warned: map[string]bool{},
		once:   map[string]bool{},
		plain:  map[string]bool{},
		loader: env.NewLoader(env.Options{
			Env: opts.Env, DryRun: opts.DryRun, Trust: opts.Trust, EnvHint: opts.EnvHint, Hidden: opts.Transport.HiddenEnv, Secrets: opts.Secrets,
			Held: !opts.Confirm.Person && opts.Serve == nil, Store: opts.Store, NoPrivate: opts.NoPrivate,
		}),
		client: exec.New(exec.Options{MaxBody: opts.MaxBody, UserAgent: opts.UserAgent, Transport: opts.Transport}),
	}
}

// Masker returns a Masker for every secret the session has read or
// captured so far, for the values of the cookies responses have set, for
// the credentials of Basic, which go in base64, and for the secrets of the
// transport, such as the password of the proxy.
func (s *Session) Masker() *core.Masker {
	values := slices.Concat(s.cookies, s.credentials, s.opts.Transport.Secrets)
	for _, v := range s.client.CookieValues() {
		if len(v) >= minCookieSecret {
			values = append(values, v)
		}
	}
	return s.loader.Masker().Join(core.NewMasker(values))
}

// Declared returns the variables that the @capture directives of the
// requests prepared so far take.
func (s *Session) Declared() []string { return slices.Clone(s.declared) }

// Declare makes names variables that an @capture takes, as if a request
// that captures them had been prepared: a preview declares what the
// session it previews has. Each is a secret, unless DeclarePlain says
// otherwise after it.
func (s *Session) Declare(names ...string) {
	for _, name := range names {
		s.loader.Declare(name)
		delete(s.plain, name)
		if !slices.Contains(s.declared, name) {
			s.declared = append(s.declared, name)
		}
	}
}

// Plain returns the declared variables whose latest @capture says plain.
func (s *Session) Plain() []string { return slices.Sorted(maps.Keys(s.plain)) }

// DeclarePlain declares names as Declare does, as variables that a plain
// @capture takes: in a dry run, which captures nothing, they are no
// secrets that could go anywhere.
func (s *Session) DeclarePlain(names ...string) {
	s.Declare(names...)
	for _, name := range names {
		s.plain[name] = true
	}
}

// Lost returns the variables whose latest @capture took no value, each
// with the request it was in.
func (s *Session) Lost() map[string]string { return s.loader.Lost() }

// Forget makes name a variable whose latest @capture, in the request ref,
// took no value, as if that request had run: a request prepared after the
// call that uses name is an error of kind variable, in a dry run too. A
// preview forgets what the session it previews has lost.
func (s *Session) Forget(name, ref string) { s.loader.Forget(name, ref) }

// Bound returns the origins each captured secret may go to: in a run,
// those of the response it came from; in a dry run, those of the request
// whose @capture would take it.
func (s *Session) Bound() map[string][]string { return s.loader.Bound() }

// Bind binds the variable name, in a dry run, to origins, as if a request
// that goes there had taken it: a preview binds what the session it
// previews has captured.
func (s *Session) Bind(name string, origins ...string) { s.loader.Bind(name, origins...) }

// Reload makes the requests prepared from now on read the environment and
// command files again and run their commands again, as a new run would,
// with the values captured so far. Secrets read before stay masked.
func (s *Session) Reload() { s.loader.Reload() }

// Job is a request to send, or the error that stops it beforehand.
type Job struct {
	Ref      string
	Request  *core.Request  // nil for a file that does not parse
	Prepared *core.Prepared // nil if Err is set
	Err      error
	Warnings []core.Warning
	settings exec.Settings
	vars     *env.Vars
	captures []string             // the variables its @capture directives take
	classes  map[string]env.Class // of its placeholders, as it was prepared
	ask      *core.Confirmation   // what it needs before it is sent; nil for nothing
	// named is set when a confirmation names the request (see confirmed):
	// with a person at a terminal, its secrets may then go where it goes.
	named bool
	// withheld is, in a run without a person, the first secret the request
	// needs the value of; nil for none.
	withheld *core.Bound
}

// Class returns what the placeholder r of the request stands for, as the
// request was prepared: see env.Vars.Classes.
func (j *Job) Class(r core.Ref) env.Class { return j.classes[r.String()] }

// Prepare resolves the i-th request of f, then declares the variables its
// captures take for the requests prepared after it. A request that needs
// a confirmation it does not have is refused here, outside a dry run,
// before it is resolved: nothing of it is sent, and none of its
// {{$cmd NAME}} runs. A run without a person, whose resolving reads no
// secret and runs no command, resolves it first: one that needs a secret
// value is refused for that, without a keeper, whatever confirms it.
func (s *Session) Prepare(ctx context.Context, f *core.File, i int) *Job {
	j := &Job{Ref: output.Ref(f, i), Request: f.Requests[i]}
	var warnings []core.Warning
	j.settings, warnings = s.client.Settings(j.Request)
	j.vars, j.Err = s.loader.For(f.Path)
	// Those of the environment files once, with the first of their
	// requests, whichever directory it is in, and however often the files
	// are read again.
	if j.vars != nil {
		for _, w := range j.vars.Warnings() {
			if !s.warned[w.String()] {
				s.warned[w.String()] = true
				j.Warnings = append(j.Warnings, w)
			}
		}
	}
	j.Warnings = slices.Concat(j.Warnings, j.Request.Warnings, warnings)
	confirmed, named := s.confirmed(f, i)
	j.named = named
	j.ask = s.ask(f, i, j.Ref, confirmed)
	switch {
	case j.Err != nil:
	case j.ask != nil && !s.opts.DryRun && !s.held():
		j.Err = refused(j.Request, j.ask)
	default:
		j.classes = j.vars.Classes(j.Request)
		j.Prepared, j.Err = j.vars.Prepare(ctx, j.Request)
		if !s.held() {
			break
		}
		if j.Err == nil {
			j.withheld = s.heldSecret(j, j.Prepared)
		}
		switch {
		case j.withheld != nil && s.opts.Keeper == nil && !s.opts.DryRun:
			j.Prepared, j.Err = nil, s.denied(j, j.withheld)
		case j.ask != nil && !s.opts.DryRun:
			j.Prepared, j.Err = nil, refused(j.Request, j.ask)
		case j.withheld != nil && s.opts.Keeper != nil:
			s.relay = true
		}
	}
	_, captures, _ := assert.Directives(j.Request) // the file parsed, so they do
	for _, c := range captures {
		if c.Secret {
			s.Declare(c.Name)
		} else {
			s.DeclarePlain(c.Name)
		}
		j.captures = append(j.captures, c.Name)
	}
	return j
}

// Jobs prepares every request of the .http files at root, in order: root
// itself if it is a file, or the files below it. A file that does not
// parse is one job with its error. The error returned is for root itself.
func (s *Session) Jobs(ctx context.Context, root string) ([]*Job, error) {
	paths, err := httpfile.Files(root)
	if err != nil {
		return nil, err
	}
	var jobs []*Job
	for _, path := range paths {
		src, err := httpfile.ReadFile(path)
		var f *core.File
		if err == nil {
			f, err = httpfile.Parse(path, src)
		}
		if err != nil {
			// The variables its @capture lines name, found line by line, are
			// still declared: the requests after it must not take them from
			// the environment.
			j := &Job{Ref: path, Err: err, captures: httpfile.CaptureNames(src)}
			s.Declare(j.captures...)
			jobs = append(jobs, j)
			continue
		}
		for i := range f.Requests {
			jobs = append(jobs, s.Prepare(ctx, f, i))
		}
	}
	return jobs, nil
}

// Run sends the request of j with the values captured so far, or checks
// it in a dry run, and returns its result with every secret masked. The
// requests prepared after j get what its captures took, and no older
// value of a variable that one of them did not take. In a dry run they
// took nothing, and lost nothing either.
func (s *Session) Run(ctx context.Context, j *Job) *output.Result {
	start := time.Now()
	res := &output.Result{Ref: j.Ref, Warnings: output.Warnings(j.Warnings, s.Masker())}
	if j.Request != nil {
		res.Transport = output.NewTransport(j.settings)
	}
	if s.opts.DryRun && j.ask != nil {
		res.Confirm = output.NewConfirm(j.ask, s.Masker())
	}
	err := j.Err
	switch {
	case err != nil:
	case j.ask != nil && !s.opts.DryRun: // as Prepare refused it
		err = refused(j.Request, j.ask)
	case s.opts.DryRun:
		var p *core.Prepared
		if p, err = s.loader.Fill(j.Prepared); err == nil {
			res.Request = output.Sent(p, s.Masker())
			err = s.client.Check(ctx, p, s.src(j))
		}
		if err == nil {
			err = s.dryOrigins(j, p, res)
		}
		if j.withheld != nil && s.opts.Keeper == nil {
			err = s.denied(j, j.withheld)
		}
	case s.relay:
		err = s.relayed(ctx, j, res)
	default:
		err = s.send(ctx, j, res)
	}
	for _, name := range j.captures {
		if !s.opts.DryRun && !slices.ContainsFunc(res.Captures, func(c output.Capture) bool { return c.Name == name }) {
			s.loader.Forget(name, j.Ref)
		}
	}
	if err != nil {
		res.Error = output.NewError(err, s.Masker())
	}
	// What a run without a person sees is sterile: a person's is not.
	if !s.opts.Confirm.Person {
		res.Redact()
	}
	s.record(j, res, start)
	return res
}

// HistoryError returns why the history could not keep the latest run,
// or nil.
func (s *Session) HistoryError() error { return s.historyErr }

// record adds the run of j that started at start and gave res to the
// history: what its file says of it, and how it ended. Its URL is kept
// as written, with any secret value in it masked all the same; nothing
// it resolved to is kept. A dry run is no run, a file that does not parse
// has no request, and a request with @no-log is not kept.
func (s *Session) record(j *Job, res *output.Result, start time.Time) {
	s.historyErr = nil
	if s.opts.History == nil || s.opts.DryRun || j.Request == nil || j.Request.NoLog() {
		return
	}
	e := history.Entry{
		Time: start, Ref: j.Ref, Env: s.opts.Env, Method: j.Request.Method, URL: s.Masker().Mask(j.Request.URL),
		DurationMS: float64(time.Since(start).Microseconds()) / 1000, Result: "ok",
	}
	// The ref names the file as given; the history names it wherever the
	// next run starts from.
	file := j.Request.Source.File
	if abs, err := filepath.Abs(file); err == nil && strings.HasPrefix(j.Ref, file+"#") {
		e.Ref = abs + strings.TrimPrefix(j.Ref, file)
	}
	if r := res.Response; r != nil {
		e.Status, e.Truncated = r.Status, r.Truncated
		e.DurationMS = res.Timing.TotalMS
	}
	if res.Error != nil {
		e.Result = string(res.Error.Kind)
	}
	e.Redacted = len(res.Redacted) > 0
	s.historyErr = s.opts.History.Add(e)
}

// Curl returns the request of j as a curl command line, as Run would send
// it now: see package curl. Every secret in it is a shell variable, and
// so is every captured value in a dry run; m, or the session's masker if
// m is nil, finds any other secret value, which stops the command. The
// error is otherwise the one Run would give before sending.
func (s *Session) Curl(ctx context.Context, j *Job, m *core.Masker) (string, error) {
	if j.Err != nil {
		return "", j.Err
	}
	p, err := s.loader.Fill(j.Prepared)
	if err == nil {
		err = s.client.Check(ctx, p, s.src(j))
	}
	if err != nil {
		return "", err
	}
	if m == nil {
		m = s.Masker()
	}
	return curl.Command(p, m)
}

// basic makes the masker hide the credentials of an Authorization header
// of p written as Basic, user and password, which go in base64, if they
// hold a secret that vars reveal.
func (s *Session) basic(p *core.Prepared, vars core.Secrets) {
	for _, h := range p.Headers {
		user, password, ok := core.BasicAuth(h)
		if !ok || !user.HasSecret() && !password.HasSecret() {
			continue
		}
		u, uerr := user.Reveal(vars)
		pw, perr := password.Reveal(vars)
		if uerr == nil && perr == nil {
			if !slices.Contains(s.credentials, u+":"+pw) {
				s.credentials = append(s.credentials, u+":"+pw)
			}
		}
	}
}

// cookie makes the masker hide v, the value of a cookie a response set,
// if it is a secret: see maxCookieSecrets. Each response sets its cookies
// again: a value is kept once, however often it comes.
func (s *Session) cookie(v string) {
	switch {
	case len(v) < minCookieSecret, len(v) > maxCookieSecret, slices.Contains(s.cookies, v):
		return
	case len(s.cookies) == maxCookieSecrets:
		s.cookies = slices.Delete(s.cookies, 0, 1)
	}
	s.cookies = append(s.cookies, v)
}

// send sends the request of j, evaluates its directives, and sets the
// request, the response, the outcomes and the captures of res. The error
// is for a status of 400 or above with Fail, or else for failed captures
// or assertions.
func (s *Session) send(ctx context.Context, j *Job, res *output.Result) error {
	p, err := s.loader.Fill(j.Prepared)
	if err != nil {
		return err
	}
	if s.held() {
		// A plain value a capture took may have turned out to be a secret.
		if b := s.heldSecret(j, p); b != nil && s.opts.Keeper != nil {
			s.relay = true
			return s.relayed(ctx, j, res)
		} else if b != nil {
			return s.denied(j, b)
		}
	}
	vars := s.src(j)
	res.Request = output.Sent(p, s.Masker())
	// Refused here, where a person may confirm it; the client refuses it
	// too, as every hop of a redirect.
	origins, known, oerr := p.Origins(vars)
	var refused []core.Bound
	if oerr == nil && known {
		for _, o := range origins {
			refused = append(refused, core.Unbound(p, vars, o)...)
		}
	}
	switch {
	case s.opts.Serve != nil:
		if vars, err = s.askKeeper(ctx, j, p, vars, origins, refused); err != nil {
			return err
		}
		// Its commands run once its person has said yes, or need not.
		if cerr := j.vars.Commands(ctx, p, true); cerr != nil {
			return cerr
		}
	case len(refused) == 0:
	case !s.opts.Confirm.Person || !j.named:
		return s.unbound(j, refused)
	default:
		for _, o := range origins {
			vars = core.Grant(vars, o)
		}
	}
	s.basic(p, vars)
	resp, trace, err := s.client.Do(ctx, p, vars)
	if trace != nil {
		for _, h := range trace.Hops {
			for _, c := range h.Set {
				s.cookie(c.Value)
			}
		}
	}
	if err != nil {
		output.Diagnose(res, trace, s.Masker())
		return err
	}
	return s.received(ctx, j, resp, trace, res)
}

// received evaluates the directives of the request of j on resp, its
// response, which trace says how it came, and sets the response, the
// outcomes and the captures of res, as send says.
func (s *Session) received(ctx context.Context, j *Job, resp *exec.Response, trace *exec.Trace, res *output.Result) error {
	ev := assert.Evaluate(ctx, j.Request, resp)
	m := s.Masker()
	for i, v := range ev.Captured {
		// A plain value that holds a secret, as a response that echoes the
		// request holds it, is that secret still; and for a run without a
		// person, so is a credential the response hands out, which it is
		// not shown.
		if !v.Secret && (m.Mask(v.Value) != v.Value || !s.opts.Confirm.Person && output.Credential(v.Source, v.Value)) {
			c := *v.Capture
			c.Secret = true
			ev.Captured[i].Capture, v.Capture = &c, &c
		}
		s.loader.Capture(v.Name, v.Value, v.Secret, resp.Origins...)
	}
	// A secret is masked in the very response it was captured from.
	m = s.Masker()
	res.Response = output.NewResponse(resp, m)
	if !s.opts.Confirm.Person {
		// A run without a person checks its assertions on what it is
		// shown; what its captures take comes from the response as it came.
		var err error
		ev.Outcomes, err = assert.Check(ctx, j.Request, sterile(resp, res.Response))
		if e, ok := errors.AsType[*core.Error](ev.Err); !ok || e.Kind != core.KindCapture {
			ev.Err = err
		}
	}
	output.Diagnose(res, trace, m)
	res.Asserts = output.Checked(ev.Outcomes, m)
	res.Captures = output.Captures(ev.Captured)
	if s.opts.Fail && resp.Status >= 400 {
		return core.Errorf(core.KindStatus, j.Request.Source, "HTTP %d %s", resp.Status, resp.Reason)
	}
	return ev.Err
}

// sterile returns resp as a run without a person is shown it, from out,
// the response it prints: every secret value masked, and what a response
// hands out redacted (see output.Result.Redact).
func sterile(resp *exec.Response, out *output.Response) *exec.Response {
	shown := &output.Result{Response: &output.Response{
		Proto: out.Proto, Status: out.Status, Reason: out.Reason, Headers: slices.Clone(out.Headers),
		Body: out.Body, Encoding: out.Encoding, Truncated: out.Truncated,
	}}
	shown.Redact()
	r := *resp
	r.Header = http.Header{}
	for _, h := range shown.Response.Headers {
		r.Header.Add(h.Name, h.Value)
	}
	r.Body = []byte(shown.Response.Body)
	if shown.Response.Encoding == "base64" {
		if b, err := base64.StdEncoding.DecodeString(shown.Response.Body); err == nil {
			r.Body = b
		}
	}
	return &r
}

// Bindings returns the secrets of the request of j, by name, with the
// origins each may go to and the origin the request goes to, as far as
// they are known now; nil for a request that was not resolved.
func (s *Session) Bindings(j *Job) []core.Bound {
	if j.Prepared == nil {
		return nil
	}
	p, err := s.loader.Fill(j.Prepared)
	if err != nil {
		p = j.Prepared
	}
	origins, _, _ := p.Origins(s.src(j))
	return core.Bindings(s.src(j), first(origins), s.secretTexts(p)...)
}

// first returns the first of origins, that of the URL, or "" for none.
func first(origins []string) string {
	if len(origins) == 0 {
		return ""
	}
	return origins[0]
}

// secretTexts returns the texts of p, as core.Bindings takes them, with
// each variable that a plain @capture takes as literal text: in a dry run,
// which captures nothing, it stands in for a value that is no secret; in
// a run, Fill has put the value there already.
func (s *Session) secretTexts(p *core.Prepared) []core.Text {
	if !s.opts.DryRun {
		return p.Texts()
	}
	var texts []core.Text
	for _, t := range p.Texts() {
		t = slices.Clone(t)
		for i, seg := range t {
			if seg.Secret != nil && seg.Secret.Capture && s.plain[seg.Secret.Name] {
				t[i] = core.Segment{Text: "{{" + seg.Secret.Name + "}}"}
			}
		}
		texts = append(texts, t)
	}
	return texts
}

// dryOrigins says in res what sending p, the request of j, would do with
// its secrets: where each may go, and, for one that may not go where p
// goes, the confirmation that a person would give, or the error of kind
// policy that a run without one gets. The captures of j are bound to
// where p goes, as a run binds them to where the response comes from.
func (s *Session) dryOrigins(j *Job, p *core.Prepared, res *output.Result) error {
	origins, _, err := p.Origins(s.src(j))
	if err != nil {
		return core.Errorf(core.KindVariable, j.Request.Source, "%v", err)
	}
	for _, name := range j.captures {
		s.loader.Bind(name, origins...)
	}
	texts := s.secretTexts(p)
	bs := core.Bindings(s.src(j), first(origins), texts...)
	m := s.Masker()
	res.SecretOrigins = output.Bindings(bs, m)
	refused := core.Refused(bs)
	for _, o := range origins[min(1, len(origins)):] {
		refused = append(refused, core.Refused(core.Bindings(s.src(j), o, texts...))...)
	}
	switch {
	case len(refused) == 0, s.opts.Confirm.Person && j.named:
		return nil
	case !s.opts.Confirm.Person:
		return s.unbound(j, refused)
	case res.Confirm != nil:
		res.Confirm.Secret = output.NewSecret(&refused[0], m)
	default:
		res.Confirm = output.NewConfirm(s.unbound(j, refused).Confirm, m)
	}
	return nil
}
