// Package session resolves and sends requests with one environment. The
// CLI and the terminal interface send requests through it and nothing
// else, so that a request goes out the same way from both.
package session

import (
	"context"
	"slices"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/assert"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/exec"
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
	Trust     *policy.Store // the command files allowed to run; nil allows none
	Timeout   time.Duration // for each request, body included; 0 means none
	MaxBody   int64         // response body bytes kept
	UserAgent string
	Fail      bool // a response status of 400 or above is an error of kind status
}

// Session is one run: the environment loader that hands out variables and
// secrets, and the client that sends. A value an @capture takes is a
// variable for the requests prepared after the one it came from. A
// Session is not safe for concurrent use.
type Session struct {
	opts     Options
	loader   *env.Loader
	client   *exec.Client
	declared []string // the variables @capture directives take, in order
}

// New returns a Session.
func New(opts Options) *Session {
	return &Session{
		opts:   opts,
		loader: env.NewLoader(env.Options{Env: opts.Env, DryRun: opts.DryRun, Trust: opts.Trust}),
		client: exec.New(exec.Options{Timeout: opts.Timeout, MaxBody: opts.MaxBody, UserAgent: opts.UserAgent}),
	}
}

// Masker returns a Masker for every secret the session has read or
// captured so far.
func (s *Session) Masker() *core.Masker { return s.loader.Masker() }

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
	vars     *env.Vars
	captures []string // the variables its @capture directives take
}

// Prepare resolves the i-th request of f, then declares the variables its
// captures take for the requests prepared after it.
func (s *Session) Prepare(ctx context.Context, f *core.File, i int) *Job {
	j := &Job{Ref: output.Ref(f, i), Request: f.Requests[i]}
	j.vars, j.Err = s.loader.For(f.Path)
	if j.Err == nil {
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
// value of a variable that one of them did not take.
func (s *Session) Run(ctx context.Context, j *Job) *output.Result {
	res := &output.Result{Ref: j.Ref}
	err := j.Err
	switch {
	case err != nil:
	case s.opts.DryRun:
		res.Request = output.Sent(j.Prepared, s.Masker())
		err = s.client.Check(ctx, j.Prepared, j.vars)
	default:
		err = s.send(ctx, j, res)
	}
	for _, name := range j.captures {
		if !slices.ContainsFunc(res.Captures, func(c output.Capture) bool { return c.Name == name }) {
			s.loader.Forget(name, j.Ref)
		}
	}
	if err != nil {
		res.Error = output.NewError(err, s.Masker())
	}
	return res
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
	res.Request = output.Sent(p, s.Masker())
	resp, err := s.client.Do(ctx, p, j.vars)
	if err != nil {
		return err
	}
	ev := assert.Evaluate(ctx, j.Request, resp)
	for _, v := range ev.Captured {
		s.loader.Capture(v.Name, v.Value, v.Secret)
	}
	// A secret is masked in the very response it was captured from.
	m := s.Masker()
	res.Response, res.Timing = output.NewResponse(resp, m)
	res.Asserts = output.Checked(ev.Outcomes, m)
	res.Captures = output.Captures(ev.Captured)
	if s.opts.Fail && resp.Status >= 400 {
		return core.Errorf(core.KindStatus, j.Request.Source, "HTTP %d %s", resp.Status, resp.Reason)
	}
	return ev.Err
}
