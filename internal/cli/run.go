package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

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
	maxBody   byteSize
	verbose   bool
	noHistory bool
	confirm   confirmFlag
	net       netFlags
}

func newRunCmd(cfg *Config) *cobra.Command {
	f := runFlags{maxBody: 1 << 20, net: newNetFlags()}
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
plain. So is a cookie a response sets: a jar in memory keeps it for the
requests after it, and sends it where it goes, without ever writing it
to disk or showing its value. --no-cookies turns the jar off, and
"# @no-cookie-jar" for one request. {{$cmd NAME}} runs a command of http-client.cmd.json once per run,
if the file is trusted (see vegtam trust --help); --dry-run checks the
trust but runs nothing.

Each request sent goes into the history of runs, which keeps where it is
written, its method and URL as written, and how it ended, and never a
secret: $XDG_DATA_HOME/vegtam/history.jsonl, or
~/.local/share/vegtam/history.jsonl. --no-history keeps this run out of
it, VEGTAM_NO_HISTORY=1 every run, and "# @no-log" one request.

Without a person at a terminal (stdin or stdout is not one, or --json
is given), a request whose method is not GET, HEAD or OPTIONS is not
sent without --confirm: it is an error of kind confirm, exit code 5,
that names the flag to give, and the other requests run. --confirm
alone confirms every request of the run; --confirm=file#name,file#N
only those, which must be requests of the run. The value needs the =:
"--confirm file#name" is --confirm and an argument. The operator's
policy may let such a run send any method (network.confirm, see vegtam
policy --help). A request with "# @note" needs --confirm in every mode,
with a person at a terminal too, whatever the policy says: its file
asks for a person, and the error shows the note. A dry run needs no
confirmation: each result says, in confirm, what sending it would need.

A secret goes only to the origins it is bound to: a value of
http-client.private.env.json to those the file binds it to ($allow);
{{$env NAME}} and {{$cmd NAME}} to those of the operator's policy
alone (secrets, see vegtam policy --help), whatever a file says; a
captured value back to the origin of the response it came from. A
request that would send one elsewhere is not sent: without a person at a terminal, it is an error of kind policy,
exit code 6, which --confirm does not lift; with one, an error of kind
confirm, exit code 5, and --confirm=file#name sends it this once. A
redirect that would carry a secret of the URL to an origin it is not
bound to is refused, exit code 6, with a person at a terminal too. A dry
run says where each secret may go, in secret_origins.

Without a person at a terminal, a run gets no secret value at all: it
reads the names of http-client.private.env.json and not its values,
reads no {{$env NAME}} and runs no {{$cmd NAME}}. A request that needs a
secret value is an error of kind policy, exit code 6, whatever confirms
it, and error.person_command is the command a person runs to send it.
The operator's policy may send such a run's requests through the keeper
instead, a process in the person's terminal that holds the values and
asks before it uses them (secrets.unattended "keeper", see vegtam policy
--help). Such a run is shown no Set-Cookie, Authorization,
Proxy-Authorization or WWW-Authenticate header of a response, no field
named as a token, a password or a session is, and no JWT: each is ***,
and result.redacted says where.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), cfg, f, args[0])
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.env, "env", "e", "", "the environment to use")
	fl.BoolVar(&f.dryRun, "dry-run", false, "resolve the requests and print them without sending")
	fl.BoolVar(&f.fail, "fail", false, "exit with 4 if a response status is 400 or above")
	fl.Var(&f.maxBody, "max-body", "response body bytes to keep, such as 64KiB or 10MB; the rest is not read")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "print the request and the response headers too")
	fl.BoolVar(&f.noHistory, "no-history", false, "keep this run out of the history of runs")
	fl.Var(&f.confirm, "confirm", "send the requests that need a confirmation: all of them, or --confirm=file#name,file#N those (with =)")
	fl.Lookup("confirm").NoOptDefVal = confirmAll
	f.net.add(fl)
	return cmd
}

func run(ctx context.Context, cfg *Config, f runFlags, arg string) error {
	pol, err := cfg.loadPolicy()
	if err != nil {
		return err
	}
	tr, err := f.net.transport(cfg, pol)
	if err != nil {
		return err
	}
	t := parseTarget(arg)
	// A person at a terminal runs what they typed; a script or an agent,
	// which a file or a response may lead, sends what may change something
	// only with --confirm, unless the operator's policy trusts it.
	// A person may also send a secret where it is not bound, by confirming
	// it; nothing confirms that for a program.
	confirm := session.Confirm{Mutations: !cfg.unattended() || !pol.Network.ConfirmMutations(), Person: !cfg.unattended(), All: f.confirm.all}
	if confirm.Requests, err = t.confirmed(f.confirm.refs); err != nil {
		return err
	}
	opts := session.Options{
		Env: f.env, DryRun: f.dryRun, Trust: policy.DefaultStore(), Transport: tr,
		MaxBody: int64(f.maxBody), UserAgent: "vegtam/" + cfg.Version, Fail: f.fail,
		History: cfg.history(f.noHistory || f.dryRun), Confirm: confirm, Secrets: pol.Secrets,
	}
	// Without a person, the run holds no secret value: the requests that
	// need one go through the keeper, if the operator's policy says so,
	// and are refused otherwise. A dry run asks for no password.
	var none error
	switch {
	case cfg.unattended():
		none = core.ErrHeld
	case f.dryRun:
		none = core.ErrLate
	}
	opts.Store = cfg.personStore(none)
	defer closeStore(opts.Store)
	if cfg.unattended() && pol.Secrets.Keeper() {
		opts.Keeper = cfg.keeper(opts)
		if c, ok := opts.Keeper.(io.Closer); ok {
			defer func() {
				if cerr := c.Close(); cerr != nil {
					fmt.Fprintf(cfg.errOut, "vegtam: the keeper: %s\n", cfg.text(cerr.Error()))
				}
			}()
		}
	}
	s := session.New(opts)
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
		cfg.printWarnings(res.Warnings)
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
	fail := func(format string, args ...any) error {
		return core.Errorf(core.KindUsage, core.Source{File: t.path}, format, args...)
	}
	if t.ref == "" {
		return nil, 0, fail("name a request: %s#<name> or %s#<N>", t.path, t.path)
	}
	if fi, err := os.Stat(t.path); err == nil && fi.IsDir() {
		return nil, 0, fail("is a directory; #%s needs a .http file", t.ref)
	}
	f, err := httpfile.ParseFile(t.path)
	if err != nil {
		return nil, 0, err
	}
	if r, ok := f.Find(t.ref); ok {
		return f, slices.Index(f.Requests, r), nil
	}
	if len(f.Requests) == 0 {
		return nil, 0, fail("no request %q: the file has no requests", t.ref)
	}
	var refs []string
	for i := range f.Requests {
		refs = append(refs, strings.TrimPrefix(output.Ref(f, i), f.Path+"#"))
	}
	return nil, 0, fail("no request %q (requests: %s)", t.ref, strings.Join(refs, ", "))
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

// confirmed returns the keys (see session.Key) of the requests that refs
// name, as --confirm= gives them. Each must be a request of the run t,
// or the run is a usage error before anything is sent: a ref that names
// nothing must not let the run go on as if it had confirmed something.
// Files are compared as absolute paths, not as typed.
func (t target) confirmed(refs []string) ([]string, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	var in func(key string) bool
	if t.one {
		f, i, err := t.request()
		if err != nil {
			return nil, err
		}
		k, err := session.Key(f.Path, i)
		if err != nil {
			return nil, usage("%v", err)
		}
		in = func(key string) bool { return key == k }
	} else {
		paths, err := httpfile.Files(t.path)
		if err != nil {
			return nil, err
		}
		var files []string
		for _, p := range paths {
			abs, err := filepath.Abs(p)
			if err != nil {
				return nil, usage("%v", err)
			}
			files = append(files, abs)
		}
		in = func(key string) bool {
			file, _, _ := strings.CutLast(key, "#")
			return slices.Contains(files, file)
		}
	}
	var keys []string
	for _, ref := range refs {
		c := parseTarget(ref)
		if !c.one {
			return nil, usage("--confirm=%s: name a request, file#name or file#N", ref)
		}
		f, i, err := c.request()
		if err != nil {
			return nil, usage("--confirm=%s: %v", ref, err)
		}
		k, err := session.Key(f.Path, i)
		if err != nil {
			return nil, usage("%v", err)
		}
		if !in(k) {
			return nil, usage("--confirm=%s is not a request of this run, %s", ref, t.arg())
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// arg returns t as the argument of run wrote it.
func (t target) arg() string {
	if t.one {
		return t.path + "#" + t.ref
	}
	return t.path
}

// confirmFlag is --confirm: alone, it confirms every request of the run,
// and --confirm=<ref>[,<ref>...] the requests named.
type confirmFlag struct {
	all  bool
	refs []string
}

// confirmAll is what --confirm alone sets. A ref has a "#", so no ref is
// taken for it. A value needs the "=": "--confirm api.http#a" is
// --confirm and an argument, which run, of one argument, refuses.
const confirmAll = "all"

func (c *confirmFlag) Set(v string) error {
	if v == confirmAll {
		c.all = true
		return nil
	}
	for ref := range strings.SplitSeq(v, ",") {
		if !strings.Contains(ref, "#") {
			return fmt.Errorf("%q: want file#name or file#N, the requests to confirm, or --confirm alone for all", ref)
		}
		c.refs = append(c.refs, ref)
	}
	return nil
}

func (c *confirmFlag) String() string {
	if c.all {
		return confirmAll
	}
	return strings.Join(c.refs, ",")
}

// Type is empty, so that the help writes --confirm[=all], without a
// value after the flag that would read as one to give there.
func (c *confirmFlag) Type() string { return "" }

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
