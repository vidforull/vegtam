// Package session resolves and sends requests with one environment. The
// CLI and the terminal interface send requests through it and nothing
// else, so that a request goes out the same way from both.
package session

import (
	"context"
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
	// History keeps each request sent, outside a dry run, unless it has
	// an @no-log directive; nil keeps none.
	History *history.Log
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
	// Secret values that no file holds: the latest values of cookies that
	// responses set, and the credentials of Basic written as user and
	// password.
	cookies, credentials []string
}

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
		loader: env.NewLoader(env.Options{Env: opts.Env, DryRun: opts.DryRun, Trust: opts.Trust, EnvHint: opts.EnvHint}),
		client: exec.New(exec.Options{MaxBody: opts.MaxBody, UserAgent: opts.UserAgent, Transport: opts.Transport}),
	}
}

// Masker returns a Masker for every secret the session has read or
// captured so far, for the values of the cookies responses have set, and
// for the credentials of Basic, which go in base64.
func (s *Session) Masker() *core.Masker {
	values := slices.Concat(s.cookies, s.credentials)
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
// session it previews has.
func (s *Session) Declare(names ...string) {
	for _, name := range names {
		s.loader.Declare(name)
		if !slices.Contains(s.declared, name) {
			s.declared = append(s.declared, name)
		}
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
}

// Class returns what the placeholder r of the request stands for, as the
// request was prepared: see env.Vars.Classes.
func (j *Job) Class(r core.Ref) env.Class { return j.classes[r.String()] }

// Prepare resolves the i-th request of f, then declares the variables its
// captures take for the requests prepared after it.
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
	if j.Err == nil {
		j.classes = j.vars.Classes(j.Request)
		j.Prepared, j.Err = j.vars.Prepare(ctx, j.Request)
	}
	_, captures, _ := assert.Directives(j.Request) // the file parsed, so they do
	for _, c := range captures {
		s.Declare(c.Name)
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
	err := j.Err
	switch {
	case err != nil:
	case s.opts.DryRun:
		var p *core.Prepared
		if p, err = s.loader.Fill(j.Prepared); err == nil {
			res.Request = output.Sent(p, s.Masker())
			err = s.client.Check(ctx, p, j.vars)
		}
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
		err = s.client.Check(ctx, p, j.vars)
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
	s.basic(p, j.vars)
	res.Request = output.Sent(p, s.Masker())
	resp, trace, err := s.client.Do(ctx, p, j.vars)
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
	ev := assert.Evaluate(ctx, j.Request, resp)
	for _, v := range ev.Captured {
		s.loader.Capture(v.Name, v.Value, v.Secret)
	}
	// A secret is masked in the very response it was captured from.
	m := s.Masker()
	res.Response = output.NewResponse(resp, m)
	output.Diagnose(res, trace, m)
	res.Asserts = output.Checked(ev.Outcomes, m)
	res.Captures = output.Captures(ev.Captured)
	if s.opts.Fail && resp.Status >= 400 {
		return core.Errorf(core.KindStatus, j.Request.Source, "HTTP %d %s", resp.Status, resp.Reason)
	}
	return ev.Err
}
