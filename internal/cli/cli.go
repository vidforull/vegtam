package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
)

// Exit codes. The root command's help and docs/AUTOMATION.md list them.
const (
	exitOK      = 0
	exitAssert  = 1 // an @assert failed
	exitUsage   = 2 // bad arguments, a file that does not parse, an unresolved variable, an invalid request, a capture without a value, an export that cannot be read
	exitNetwork = 3 // network or TLS error, timeout
	exitStatus  = 4 // HTTP status 400 or above, with run --fail
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
	}
	return exitUsage
}

const rootHelp = `vegtam is a local-first API client for .http files.

On a terminal vegtam prints text. Otherwise, or with --json, it prints JSON
documents; "vegtam schema" prints their JSON Schema. Secret values never
appear in the output.

Exit codes:
  0  success
  1  an assertion (# @assert) failed
  2  bad arguments, a .http or environment file that does not parse, an
     unresolved variable, an invalid request, a capture (# @capture)
     that finds no value, or an export that cannot be imported
  3  network or TLS error, or timeout
  4  HTTP status 400 or above, with run --fail
  5 and 6 are reserved for requests that need confirmation and requests
  blocked by policy.
With several requests, the exit code is the highest of theirs.`

// Config is what the commands need from the process.
type Config struct {
	Stdout  io.Writer
	Stderr  io.Writer
	TTY     bool // stdout is a terminal: print text rather than JSON
	Version string

	json   bool         // --json
	masker *core.Masker // the secrets the command has read
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
	fmt.Fprintf(c.errOut, "vegtam: %s%s\n", printable(loc), printable(e.Message))
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

// Run runs the command line args and returns the exit code.
func Run(args []string, cfg Config) int {
	cfg.out, cfg.errOut = masked{cfg.Stdout, &cfg}, masked{cfg.Stderr, &cfg}
	root := &cobra.Command{
		Use:           "vegtam",
		Short:         "A local-first API client for .http files",
		Long:          rootHelp,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetArgs(args)
	root.SetOut(cfg.out)
	root.SetErr(cfg.errOut)
	root.PersistentFlags().BoolVar(&cfg.json, "json", false, "print JSON even on a terminal")
	root.AddCommand(newRunCmd(&cfg), newShowCmd(&cfg), newListCmd(&cfg), newImportCmd(&cfg), newSchemaCmd(&cfg),
		newVersionCmd(&cfg))

	cmd, err := root.ExecuteC()
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
