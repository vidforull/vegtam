package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
	"github.com/vidforull/vegtam/internal/tui"
)

// Exit codes. The root command's help and docs/AUTOMATION.md list them.
const (
	exitOK       = 0
	exitAssert   = 1   // an @assert failed
	exitUsage    = 2   // bad arguments, a file that does not parse, an unresolved variable, an invalid request, a capture without a value, an export that cannot be read
	exitNetwork  = 3   // network or TLS error, timeout
	exitStatus   = 4   // HTTP status 400 or above, with run --fail
	exitPolicy   = 6   // not allowed by policy: a command file that is not trusted
	exitCanceled = 130 // interrupted by Ctrl-C or SIGTERM: 128 + SIGINT, as a shell reports it
	exitPanic    = 2   // a bug in vegtam: the code Go exits with on a panic
)

// exitCode returns the exit code for an error of kind k.
func exitCode(k core.Kind) int {
	switch k {
	case core.KindAssert:
		return exitAssert
	case core.KindNetwork, core.KindTimeout:
		return exitNetwork
	case core.KindStatus:
		return exitStatus
	case core.KindPolicy:
		return exitPolicy
	case core.KindCanceled:
		return exitCanceled
	case core.KindUsage, core.KindParse, core.KindVariable, core.KindRequest, core.KindImport, core.KindCapture:
		return exitUsage
	}
	return exitUsage
}

const rootHelp = `vegtam is a local-first API client for .http files.

On a terminal vegtam prints text. Otherwise, or with --json, it prints JSON
documents; "vegtam schema" prints their JSON Schema. Secret values never
appear in the output. With no command, when stdin and stdout are
terminals, vegtam opens the terminal interface on the current directory,
as "vegtam tui" does.

Exit codes:
  0  success
  1  an assertion (# @assert) failed
  2  bad arguments, a .http or environment file that does not parse, an
     unresolved variable, an invalid request, a capture (# @capture)
     that finds no value, or an export that cannot be imported
  3  network or TLS error, or timeout
  4  HTTP status 400 or above, with run --fail
  5  reserved for requests that need confirmation
  6  blocked by policy: a {{$cmd NAME}} whose command file is not
     trusted (see vegtam trust --help)
  130  interrupted by Ctrl-C (SIGINT) or SIGTERM
With several requests, the exit code is the highest of theirs.`

// Config is what the commands need from the process.
type Config struct {
	Stdin  io.Reader // read by the terminal interface only
	Stdout io.Writer
	Stderr io.Writer
	TTY    bool // stdout is a terminal: print text rather than JSON
	// Interactive is set when stdin and stdout are both terminals: vegtam
	// alone then opens the terminal interface.
	Interactive bool
	Version     string

	json   bool         // --json
	masker *core.Masker // the secrets the command has read
	// secrets returns a masker for every secret read so far, from the
	// moment the command has an environment loader: masker is set only
	// once the requests are resolved, and a panic may come before.
	secrets func() *core.Masker
	// Commands write to out and errOut, never to Stdout and Stderr, so
	// that everything they print goes through masker.
	out, errOut io.Writer
}

// asJSON reports whether output should be JSON.
func (c *Config) asJSON() bool { return c.json || !c.TTY }

// writeJSON prints v as one JSON document, indented on a terminal, with
// secret values masked in its strings.
func (c *Config) writeJSON(v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if c.TTY {
		enc.SetIndent("", "  ")
	}
	// Encoding our own types cannot fail, and if stdout is gone there is
	// nowhere left to report it.
	_ = enc.Encode(v)
	_, _ = c.Stdout.Write(c.masker.MaskJSON(b.Bytes()))
}

// history returns the history of runs that the requests a command sends
// go into, or nil for none: with off, with VEGTAM_NO_HISTORY set, and
// with no place for it, which a warning says.
func (c *Config) history(off bool) *history.Log {
	if off {
		return nil
	}
	dir, err := policy.HistoryDir()
	if err != nil {
		fmt.Fprintf(c.errOut, "vegtam: no history: %s\n", c.text(err.Error()))
		return nil
	}
	if dir == "" {
		return nil
	}
	return history.New(dir)
}

// printError prints e on stderr.
func (c *Config) printError(e *output.Error) {
	loc := e.File
	if loc != "" && e.Line > 0 {
		loc += ":" + strconv.Itoa(e.Line)
	}
	if loc != "" {
		loc += ": "
	}
	// A message may quote the server: a certificate name, a status line.
	fmt.Fprintf(c.errOut, "vegtam: %s%s\n", c.text(loc), c.text(e.Message))
}

// printWarnings prints ws on stderr.
func (c *Config) printWarnings(ws []output.Warning) {
	for _, w := range ws {
		loc := w.File
		if loc != "" && w.Line > 0 {
			loc += ":" + strconv.Itoa(w.Line)
		}
		if loc != "" {
			loc += ": "
		}
		fmt.Fprintf(c.errOut, "vegtam: %swarning: %s\n", c.text(loc), c.text(w.Message))
	}
}

// internalError prints v, the value of a panic, and stack on stderr. A
// panic is a bug in vegtam, and its value may hold a secret or a control
// character that Go would print as is: it is masked with every secret
// read so far, and shown as text for a terminal.
func (c *Config) internalError(v any, stack []byte) {
	// The terminal interface catches a panic to restore the terminal, and
	// panics again with it; its own stack is the one that tells.
	if p, ok := v.(*tui.Panic); ok {
		v, stack = p.Value, p.Stack
	}
	if c.secrets != nil {
		c.masker = c.secrets()
	}
	fmt.Fprint(c.errOut, c.text(fmt.Sprintf("vegtam: internal error: %v\n%s", v, stack)))
}

// masked is stdout or stderr with secret values masked. A value split
// across two writes would escape, so callers write whole lines or blocks.
type masked struct {
	w   io.Writer
	cfg *Config
}

func (m masked) Write(p []byte) (int, error) {
	if _, err := io.WriteString(m.w, m.cfg.masker.Mask(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// exitError ends a command with an exit code once it has printed its
// output.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// Run runs the command line args and returns the exit code. The commands
// stop when ctx is done.
func Run(ctx context.Context, args []string, cfg Config) (code int) {
	cfg.out, cfg.errOut = masked{cfg.Stdout, &cfg}, masked{cfg.Stderr, &cfg}
	defer func() {
		if v := recover(); v != nil {
			cfg.internalError(v, debug.Stack())
			code = exitPanic
		}
	}()
	root := &cobra.Command{
		Use:           "vegtam",
		Short:         "A local-first API client for .http files",
		Long:          rootHelp,
		SilenceErrors: true,
		SilenceUsage:  true,
		// A person at a terminal gets the terminal interface; a program,
		// which needs none, gets the help and a usage error.
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.Interactive && !cfg.json {
				return runTUI(cmd.Context(), &cfg, newTUIFlags(), ".")
			}
			cmd.SetOut(cfg.errOut)
			if err := cmd.Help(); err != nil {
				return err
			}
			return core.Errorf(core.KindUsage, core.Source{}, "no command given")
		},
	}
	root.SetArgs(args)
	root.SetOut(cfg.out)
	root.SetErr(cfg.errOut)
	root.PersistentFlags().BoolVar(&cfg.json, "json", false, "print JSON even on a terminal")
	root.AddCommand(newRunCmd(&cfg), newShowCmd(&cfg), newListCmd(&cfg), newTUICmd(&cfg), newImportCmd(&cfg),
		newTrustCmd(&cfg), newSchemaCmd(&cfg), newVersionCmd(&cfg))

	cmd, err := root.ExecuteContextC(ctx)
	if err == nil {
		return exitOK
	}
	if xe, ok := errors.AsType[*exitError](err); ok {
		return xe.code
	}
	// An error that ends the command: text on stderr and, for JSON
	// output, a document on stdout too.
	e := output.NewError(err, cfg.masker)
	cfg.printError(e)
	if _, ok := errors.AsType[*core.Error](err); !ok {
		fmt.Fprintf(cfg.errOut, "Run \"%s --help\" for usage.\n", cmd.CommandPath())
	}
	if cfg.asJSON() {
		cfg.writeJSON(output.Document{SchemaVersion: output.SchemaVersion, Result: &output.Result{Error: e}})
	}
	return exitCode(e.Kind)
}
