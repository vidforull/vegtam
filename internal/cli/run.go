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
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
	"github.com/vidforull/vegtam/internal/core/session"
)

type runFlags struct {
	env       string
	dryRun    bool
	fail      bool
	timeout   time.Duration
	maxBody   byteSize
	verbose   bool
	noHistory bool
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
trust but runs nothing.

Each request sent goes into the history of runs, which keeps where it is
written, its method and URL as written, and how it ended, and never a
secret: $XDG_DATA_HOME/vegtam/history.jsonl, or
~/.local/share/vegtam/history.jsonl. --no-history keeps this run out of
it, VEGTAM_NO_HISTORY=1 every run, and "# @no-log" one request.`,
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
	fl.BoolVar(&f.noHistory, "no-history", false, "keep this run out of the history of runs")
	return cmd
}

func run(ctx context.Context, cfg *Config, f runFlags, arg string) error {
	if f.timeout < 0 {
		return core.Errorf(core.KindUsage, core.Source{}, "--timeout must not be negative")
	}
	t := parseTarget(arg)
	s := session.New(session.Options{
		Env: f.env, DryRun: f.dryRun, Trust: policy.DefaultStore(),
		Timeout: f.timeout, MaxBody: int64(f.maxBody), UserAgent: "vegtam/" + cfg.Version, Fail: f.fail,
		History: cfg.history(f.noHistory || f.dryRun),
	})
	cfg.secrets = s.Masker
	jobs, err := t.jobs(ctx, s)
	// Every request is resolved before the first is sent, so the masker
	// knows every secret before anything is printed; captured ones join
	// it as they are taken, before their response is printed.
	cfg.masker = s.Masker()
	if err != nil {
		return err
	}
	code := exitOK
	results := []*output.Result{}
	warned := false
	for i, j := range jobs {
		res := s.Run(ctx, j)
		cfg.masker = s.Masker()
		if err := s.HistoryError(); err != nil && !warned {
			fmt.Fprintf(cfg.errOut, "vegtam: history: %s; --no-history or VEGTAM_NO_HISTORY=1 turns it off\n", cfg.text(err.Error()))
			warned = true
		}
		if res.Error != nil {
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
		if path, ref, ok := strings.CutLast(arg, "#"); ok {
			return target{path: path, ref: ref, one: true}
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
func (t target) jobs(ctx context.Context, s *session.Session) ([]*session.Job, error) {
	if !t.one {
		return s.Jobs(ctx, t.path)
	}
	f, i, err := t.request()
	if err != nil {
		return nil, err
	}
	return []*session.Job{s.Prepare(ctx, f, i)}, nil
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
