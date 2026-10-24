package env

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// CommandFileName is the file that maps {{$cmd NAME}} to commands, looked
// up from a .http file's directory upwards, as the environment files are.
const CommandFileName = "http-client.cmd.json"

const (
	defaultTimeout = 30 * time.Second // for a command without a timeout
	maxStdout      = 1 << 20          // bytes a command may print as its value
	maxStderr      = 1 << 10          // bytes of stderr an error keeps
)

// CommandFile is a parsed command file:
//
//	{"TOKEN": {"argv": ["op", "read", "op://vault/item/field"], "timeout": "10s"}}
type CommandFile struct {
	Path     string // absolute, symbolic links resolved
	Contents []byte // as read and parsed
	Commands map[string]Command
}

// Command is how {{$cmd NAME}} gets its value: a program run with its
// arguments, without a shell, in the directory of the command file, with
// the environment of vegtam, no input and, on Unix, no terminal. Its
// output, less one final line break, is the value; it is a secret.
type Command struct {
	Argv    []string
	Timeout time.Duration
}

// ReadCommandFile reads and parses the command file at path.
func ReadCommandFile(path string) (*CommandFile, error) {
	canonical, err := policy.Canonical(path)
	if err != nil {
		return nil, core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	fail := func(format string, args ...any) error {
		return core.Errorf(core.KindParse, core.Source{File: canonical}, format, args...)
	}
	src, err := os.ReadFile(canonical) //nolint:forbidigo,gosec // G304: the command file, found by its name from the .http file's directory up
	if err != nil {
		return nil, fail("%v", err)
	}
	var raw map[string]*struct {
		Argv    []string `json:"argv"`
		Timeout string   `json:"timeout"`
	}
	// What runs must be what a person reads: no key twice, of which the
	// last would win, and nothing after the object.
	if key, ok := duplicateKey(src); ok {
		return nil, fail("%q is there twice", key)
	}
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&raw); err != nil {
		return nil, fail("%v", err)
	}
	if _, err = dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fail("data after the object")
	}
	f := &CommandFile{Path: canonical, Contents: src, Commands: map[string]Command{}}
	for _, name := range slices.Sorted(maps.Keys(raw)) {
		c := raw[name]
		switch {
		case !core.IsVarName(name):
			return nil, fail("invalid command name %q: start with a letter or _, then letters, digits, _, . and -", name)
		case c == nil || len(c.Argv) == 0 || c.Argv[0] == "":
			return nil, fail("%s: argv needs at least the program", name)
		}
		timeout := defaultTimeout
		if c.Timeout != "" {
			if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
				return nil, fail("%s: invalid timeout %q: want a duration such as 10s", name, c.Timeout)
			}
		}
		f.Commands[name] = Command{Argv: c.Argv, Timeout: timeout}
	}
	return f, nil
}

// duplicateKey returns a key that an object in the JSON document src has
// twice, if there is one.
func duplicateKey(src []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(src))
	// value reads one value; an error ends the walk, and the parse
	// reports it.
	var value func() (string, error)
	value = func() (dup string, err error) {
		tok, err := dec.Token()
		if err != nil || tok != json.Delim('{') && tok != json.Delim('[') {
			return "", err
		}
		keys := map[string]bool{}
		for dec.More() {
			if tok == json.Delim('{') {
				var k json.Token
				if k, err = dec.Token(); err != nil {
					return "", err
				}
				key, ok := k.(string)
				if !ok { // json.Decoder gives every object key as a string
					return "", nil
				}
				if keys[key] {
					return key, nil
				}
				keys[key] = true
			}
			if dup, err = value(); dup != "" || err != nil {
				return dup, err
			}
		}
		_, err = dec.Token() // the closing delimiter
		return "", err
	}
	dup, _ := value()
	return dup, dup != ""
}

// Sum returns the SHA-256 of what the commands of f run: f itself, and
// every file that an argv names by a path relative to f's directory, such
// as ./bin/token or token.py. Programs from PATH and absolute paths are
// not covered.
func (f *CommandFile) Sum() (string, error) {
	dir := filepath.Dir(f.Path)
	var b bytes.Buffer
	b.Write(f.Contents)
	var seen []string
	for _, name := range slices.Sorted(maps.Keys(f.Commands)) {
		for _, arg := range f.Commands[name].Argv {
			path := filepath.Join(dir, arg)
			if arg == "" || filepath.IsAbs(arg) || slices.Contains(seen, path) {
				continue
			}
			if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			contents, err := os.ReadFile(path) //nolint:forbidigo,gosec // G304: a script the command file names, hashed for the trust store, never sent or printed
			if err != nil {
				return "", err
			}
			seen = append(seen, path)
			fmt.Fprintf(&b, "\x00%s\x00%d\x00", arg, len(contents))
			b.Write(contents)
		}
	}
	return policy.Sum(b.Bytes()), nil
}

// commands is a command file as a run sees it.
type commands struct {
	*CommandFile
	status policy.Status
}

// commandFile returns the command file for the requests of v, checked
// against the trust store, or the error of finding or reading it.
func (v *Vars) commandFile() (*commands, error) {
	if v.cmd == nil && v.cmdErr == nil {
		v.cmd, v.cmdErr = v.loader.findCommands(v.dir)
	}
	return v.cmd, v.cmdErr
}

func (l *Loader) findCommands(dir string) (*commands, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	path := Nearest(abs, CommandFileName)
	if path == "" {
		return nil, fmt.Errorf("no %s in %s or above", CommandFileName, abs)
	}
	f, err := ReadCommandFile(path)
	if err != nil {
		return nil, err
	}
	if c, ok := l.cmdFiles[f.Path]; ok && bytes.Equal(c.Contents, f.Contents) {
		return c, nil
	}
	c := &commands{CommandFile: f, status: policy.Untrusted}
	if l.opts.Trust != nil {
		sum, err := f.Sum()
		if err != nil {
			return nil, core.Errorf(core.KindPolicy, core.Source{File: f.Path}, "%v", err)
		}
		if c.status, err = l.opts.Trust.Check(f.Path, sum); err != nil {
			return nil, err
		}
	}
	l.cmdFiles[f.Path] = c
	return c, nil
}

// command checks that the command of r may run: its command file is
// trusted and has it. Outside a dry run, and but for a run without a
// person, it also runs it, once for the whole run, so that the masker
// knows the value before anything is printed.
func (v *Vars) command(ctx context.Context, r core.Ref, src core.Source) error {
	return v.commandRun(ctx, r, src, !v.loader.opts.DryRun && !v.loader.opts.Held)
}

// commandRun is command, which runs the command only with run.
func (v *Vars) commandRun(ctx context.Context, r core.Ref, src core.Source, run bool) error {
	cf, err := v.commandFile()
	if _, ok := errors.AsType[*core.Error](err); ok {
		return err
	} else if err != nil {
		return fmt.Errorf("%s: %w", r, err)
	}
	if cf.status != policy.Trusted {
		why := "is not trusted to run commands; read it, then trust it with"
		if cf.status == policy.Changed {
			why = "has changed since it was trusted; read it again, then trust it with"
		}
		return core.Errorf(core.KindPolicy, src, "%s: %s %s: vegtam trust %s", r, cf.Path, why, core.ShellQuote(filepath.Dir(cf.Path)))
	}
	if _, ok := cf.Commands[r.Name]; !ok {
		return fmt.Errorf("%s: no command %s in %s (commands: %s)", r, r.Name, cf.Path, strings.Join(slices.Sorted(maps.Keys(cf.Commands)), ", "))
	}
	if !run {
		return nil
	}
	if _, err = v.loader.run(ctx, cf, r.Name); errors.Is(err, context.Canceled) {
		return core.Errorf(core.KindCanceled, src, "%v", err)
	}
	return err
}

// Commands checks the commands of the {{$cmd NAME}} secrets of p, which a
// run without a person resolved and a keeper sends, as Prepare checks them
// for a request of its own: their command file, found from the directory
// of the request's file up, must be trusted and have them. With run, it
// runs them too, once: a keeper runs them once its person says yes.
func (v *Vars) Commands(ctx context.Context, p *core.Prepared, run bool) error {
	for _, t := range p.Texts() {
		for _, seg := range t {
			if seg.Secret == nil || seg.Secret.Capture {
				continue
			}
			if name, ok := strings.CutPrefix(seg.Secret.Name, "$cmd "); ok {
				if err := v.commandRun(ctx, core.Ref{Func: "$cmd", Name: name}, p.Request.Source, run); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// commandValue returns the value of {{$cmd name}} for the requests of v:
// what its command printed when the request was prepared.
func (v *Vars) commandValue(name string) (string, error) {
	if v.loader.opts.DryRun {
		return "", core.ErrLate
	}
	cf, err := v.commandFile()
	if err != nil {
		return "", err
	}
	r, ok := v.loader.ran[ranKey(cf.Path, name)]
	if !ok || cf.status != policy.Trusted {
		return "", fmt.Errorf("no trusted command %s has run", name)
	}
	return r.value, r.err
}

// ran is the outcome of running a command.
type ran struct {
	value string
	err   error
}

// ranKey is the key of a command in Loader.ran.
func ranKey(path, name string) string { return path + "\x00" + name }

// run runs the command name of cf, or returns what running it gave
// before.
func (l *Loader) run(ctx context.Context, cf *commands, name string) (string, error) {
	key := ranKey(cf.Path, name)
	if r, ok := l.ran[key]; ok {
		return r.value, r.err
	}
	v, err := runCommand(ctx, filepath.Dir(cf.Path), cf.Commands[name])
	if err != nil {
		err = fmt.Errorf("{{$cmd %s}}: %w", name, err)
	}
	l.ran[key] = ran{v, err}
	return v, err
}

// noTerminal ends the error of a command that may have waited for input
// that never came.
const noTerminal = " (commands run with no input and no terminal: a command that asks for a password " +
	"must get it from an agent, a cache or a window of its own)"

func runCommand(ctx context.Context, dir string, c Command) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...) //nolint:gosec // G204: the argv of a trusted command file, without a shell
	cmd.Dir = dir
	// No input: Stdin stays nil, the null device. And no terminal: a
	// session of its own has none, so a command that opens /dev/tty to
	// ask for a password fails at once, rather than wait for an answer
	// that the terminal interface, which reads every key, would take.
	cmd.SysProcAttr = detached()
	// Run out of time or canceled, it goes with what it started.
	cmd.Cancel = func() error { return kill(cmd.Process) }
	stdout, stderr := &capped{max: maxStdout}, &capped{max: maxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// A child left behind with the output open does not hold the run.
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	// A command may leave a process behind that keeps its output open,
	// such as an agent it starts; its own exit is what counts.
	if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState.Success() {
		err = nil
	}
	prog := c.Argv[0]
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "", fmt.Errorf("%s did not finish within %s%s", prog, c.Timeout, noTerminal)
	case ctx.Err() != nil:
		return "", fmt.Errorf("%s: %w", prog, ctx.Err())
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("%s: %w", prog, err)
	case err != nil:
		if msg := strings.TrimSpace(strings.ToValidUTF8(stderr.String(), "")); msg != "" {
			if stderr.over {
				msg += "..."
			}
			return "", fmt.Errorf("%s: %w: %s%s", prog, err, msg, noTerminal)
		}
		return "", fmt.Errorf("%s: %w%s", prog, err, noTerminal)
	case stdout.over:
		return "", fmt.Errorf("%s printed more than %d bytes", prog, maxStdout)
	}
	out := stdout.String()
	if s, ok := strings.CutSuffix(out, "\n"); ok {
		out = strings.TrimSuffix(s, "\r")
	}
	if out == "" {
		return "", fmt.Errorf("%s printed nothing%s", prog, noTerminal)
	}
	return out, nil
}

// capped keeps the first max bytes written to it and drops the rest, so
// that a command that prints too much neither blocks nor fills memory.
// The buffer is not embedded: io.Copy would use its ReadFrom and bypass
// Write.
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); len(p) > room {
		c.over = true
		c.buf.Write(p[:max(room, 0)])
	} else {
		c.buf.Write(p)
	}
	return len(p), nil
}

func (c *capped) String() string { return c.buf.String() }
