package cli

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/assert"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/exec"
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
)

type runFlags struct {
	env     string
	dryRun  bool
	fail    bool
	timeout time.Duration
	maxBody byteSize
	verbose bool
}

func newRunCmd(cfg *Config) *cobra.Command {
	f := runFlags{maxBody: 1 << 20}
	cmd := &cobra.Command{
		Use:   "run <file>[#<name>|#<N>] | <dir>",
		Short: "Send requests",
		Long: `Send one request, every request of a .http file, or every request of the
.http files in a directory and below it, in order.

file.http#name sends the request named with "# @name name", file.http#2 the
second request of the file. -e selects the environment from
http-client.env.json and http-client.private.env.json.

On a terminal the response is printed as text: the status and the time,
the headers with --verbose, the body, JSON indented, the outcome of each
"# @assert" and the variables "# @capture" took. Otherwise, or with
--json, the output is one JSON document: a result for file#ref, a list of
results for a file or a directory. An error stops only its own request.

A captured value is a variable for the requests after it in the same
run, over the environment; it is a secret unless the directive says
plain. {{$cmd NAME}} runs a command of http-client.cmd.json once per run,
if the file is trusted (see vegtam trust --help); --dry-run checks the
trust but runs nothing.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), cfg, f, args[0])
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.env, "env", "e", "", "the environment to use")
	fl.BoolVar(&f.dryRun, "dry-run", false, "resolve the requests and print them without sending")
	fl.BoolVar(&f.fail, "fail", false, "exit with 4 if a response status is 400 or above")
	fl.DurationVar(&f.timeout, "timeout", 30*time.Second, "time limit for each request, body included; 0 for none")
	fl.Var(&f.maxBody, "max-body", "response body bytes to keep, such as 64KiB or 10MB; the rest is not read")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "print the request and the response headers too")
	return cmd
}

// job is a request to send, or the error that stops it beforehand.
type job struct {
	ref      string
	req      *core.Request
	p        *core.Prepared
	vars     *env.Vars
	captures []string // the variables its @capture directives take
	err      error
}

func run(ctx context.Context, cfg *Config, f runFlags, arg string) error {
	if f.timeout < 0 {
		return core.Errorf(core.KindUsage, core.Source{}, "--timeout must not be negative")
	}
	t := parseTarget(arg)
	loader := env.NewLoader(env.Options{Env: f.env, DryRun: f.dryRun, Trust: policy.DefaultStore()})
	jobs, err := t.jobs(loader)
	// Every request is resolved before the first is sent, so the masker
	// knows every secret before anything is printed; captured ones join
	// it as they are taken, before their response is printed.
	cfg.masker = loader.Masker()
	if err != nil {
		return err
	}
	client := exec.New(exec.Options{Timeout: f.timeout, MaxBody: int64(f.maxBody), UserAgent: "vegtam/" + cfg.Version})
	code := exitOK
	results := []*output.Result{}
	for i, j := range jobs {
		res := &output.Result{Ref: j.ref}
		err := j.err
		switch {
		case err != nil:
		case f.dryRun:
			res.Request = output.Sent(j.p, cfg.masker)
			err = client.Check(j.p, j.vars)
		default:
			err = send(ctx, cfg, client, loader, j, f.fail, res)
		}
		// The requests after this one get what its captures took, and no
		// older value of a variable that one of them did not take.
		for _, name := range j.captures {
			if !slices.ContainsFunc(res.Captures, func(c output.Capture) bool { return c.Name == name }) {
				loader.Forget(name, j.ref)
			}
		}
		if err != nil {
			res.Error = output.NewError(err, cfg.masker)
			code = max(code, exitCode(res.Error.Kind))
		}
		if !cfg.asJSON() {
			cfg.printResult(res, i, !t.one, f.verbose)
		} else if res.Error != nil {
			cfg.printError(res.Error)
		}
		results = append(results, res)
	}
	if cfg.asJSON() {
		doc := output.Document{SchemaVersion: output.SchemaVersion, Results: results}
		if t.one {
			doc.Result, doc.Results = results[0], nil
		}
		cfg.writeJSON(doc)
	}
	if code != exitOK {
		return &exitError{code}
	}
	return nil
}

// send sends the request of j with the values captured so far, evaluates
// its directives, and sets the request, the response, the outcomes and
// the captures of res. The error is for a status of 400 or above with
// fail, or else for failed captures or assertions.
func send(ctx context.Context, cfg *Config, c *exec.Client, loader *env.Loader, j job, fail bool, res *output.Result) error {
	p, err := loader.Fill(j.p)
	if err != nil {
		return err
	}
	res.Request = output.Sent(p, cfg.masker)
	resp, err := c.Do(ctx, p, j.vars)
	if err != nil {
		return err
	}
	ev := assert.Evaluate(ctx, j.req, resp)
	for _, v := range ev.Captured {
		loader.Capture(v.Name, v.Value, v.Secret)
	}
	// A secret is masked in the very response it was captured from.
	cfg.masker = loader.Masker()
	res.Response, res.Timing = output.NewResponse(resp, cfg.masker)
	res.Asserts = output.Checked(ev.Outcomes, cfg.masker)
	res.Captures = output.Captures(ev.Captured)
	if fail && resp.Status >= 400 {
		return core.Errorf(core.KindStatus, j.req.Source, "HTTP %d %s", resp.Status, resp.Reason)
	}
	return ev.Err
}

// target is a command-line argument: a .http file or a directory, and a
// request of the file if the argument ends in #ref.
type target struct {
	path string
	ref  string
	one  bool // a request was named with #ref
}

// parseTarget splits arg into a path and a #ref. An existing path is
// taken whole, even if it contains '#'.
func parseTarget(arg string) target {
	if _, err := os.Stat(arg); err != nil {
		if i := strings.LastIndex(arg, "#"); i >= 0 {
			return target{path: arg[:i], ref: arg[i+1:], one: true}
		}
	}
	return target{path: arg}
}

// request returns the file and the index of the request t names.
func (t target) request() (*core.File, int, error) {
	usage := func(format string, args ...any) error {
		return core.Errorf(core.KindUsage, core.Source{File: t.path}, format, args...)
	}
	if t.ref == "" {
		return nil, 0, usage("name a request: %s#<name> or %s#<N>", t.path, t.path)
	}
	if fi, err := os.Stat(t.path); err == nil && fi.IsDir() {
		return nil, 0, usage("is a directory; #%s needs a .http file", t.ref)
	}
	f, err := httpfile.ParseFile(t.path)
	if err != nil {
		return nil, 0, err
	}
	if r, ok := f.Find(t.ref); ok {
		return f, slices.Index(f.Requests, r), nil
	}
	if len(f.Requests) == 0 {
		return nil, 0, usage("no request %q: the file has no requests", t.ref)
	}
	var refs []string
	for i := range f.Requests {
		refs = append(refs, strings.TrimPrefix(output.Ref(f, i), f.Path+"#"))
	}
	return nil, 0, usage("no request %q (requests: %s)", t.ref, strings.Join(refs, ", "))
}

// jobs resolves the requests t names. A file that does not parse and a
// request that cannot be resolved become jobs with an error; the error
// returned is for t itself.
func (t target) jobs(loader *env.Loader) ([]job, error) {
	if t.one {
		f, i, err := t.request()
		if err != nil {
			return nil, err
		}
		return []job{prepare(loader, f, i)}, nil
	}
	paths, err := httpfile.Files(t.path)
	if err != nil {
		return nil, err
	}
	var jobs []job
	for _, path := range paths {
		f, err := httpfile.ParseFile(path)
		if err != nil {
			j := job{ref: path, err: err}
			if src, err := os.ReadFile(path); err == nil {
				j.captures = httpfile.CaptureNames(src)
			}
			for _, name := range j.captures {
				loader.Declare(name)
			}
			jobs = append(jobs, j)
			continue
		}
		for i := range f.Requests {
			jobs = append(jobs, prepare(loader, f, i))
		}
	}
	return jobs, nil
}

// prepare resolves the i-th request of f, then declares the variables
// its captures take for the requests prepared after it.
func prepare(loader *env.Loader, f *core.File, i int) job {
	j := job{ref: output.Ref(f, i), req: f.Requests[i]}
	j.vars, j.err = loader.For(f.Path)
	if j.err == nil {
		j.p, j.err = j.vars.Prepare(j.req)
	}
	_, captures, _ := assert.Directives(j.req) // the file parsed, so they do
	for _, c := range captures {
		loader.Declare(c.Name)
		j.captures = append(j.captures, c.Name)
	}
	return j
}

// byteSize is a size flag: a number of bytes, optionally with a unit.
type byteSize int64

var (
	sizeRE    = regexp.MustCompile(`^([0-9]+) *([A-Za-z]*)$`)
	sizeUnits = map[string]int64{"": 1, "B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "KIB": 1 << 10, "MIB": 1 << 20, "GIB": 1 << 30}
)

func (s *byteSize) Set(v string) error {
	m := sizeRE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return errors.New("want bytes or a size such as 512KiB or 10MB")
	}
	unit, ok := sizeUnits[strings.ToUpper(m[2])]
	if !ok {
		return fmt.Errorf("unknown unit %q (use B, KB, MB, GB, KiB, MiB or GiB)", m[2])
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || n > math.MaxInt64/unit {
		return errors.New("size too large")
	}
	*s = byteSize(n * unit)
	return nil
}

func (s *byteSize) String() string {
	for _, u := range []struct {
		name string
		n    byteSize
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if *s >= u.n && *s%u.n == 0 {
			return strconv.FormatInt(int64(*s/u.n), 10) + u.name
		}
	}
	return strconv.FormatInt(int64(*s), 10)
}

func (s *byteSize) Type() string { return "size" }
