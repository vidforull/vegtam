package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// Exit codes. docs/AUTOMATION.md documents them.
const (
	exitOK    = 0
	exitUsage = 2 // bad arguments
)

// Config is what the commands need from the process.
type Config struct {
	Stdout  io.Writer
	Stderr  io.Writer
	TTY     bool // stdout is a terminal: print text rather than JSON
	Version string

	json bool // --json
}

// asJSON reports whether output should be JSON.
func (c *Config) asJSON() bool { return c.json || !c.TTY }

// writeJSON prints v as one JSON document, indented on a terminal.
func (c *Config) writeJSON(v any) {
	enc := json.NewEncoder(c.Stdout)
	enc.SetEscapeHTML(false)
	if c.TTY {
		enc.SetIndent("", "  ")
	}
	// Encoding our own types fails only if stdout is gone, and then there
	// is nowhere left to report it.
	_ = enc.Encode(v)
}

// exitError ends a command with an exit code once it has printed its
// output.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// Run runs the command line args and returns the exit code.
func Run(args []string, cfg Config) int {
	root := &cobra.Command{
		Use:           "vegtam",
		Short:         "A local-first API client for .http files",
		Long:          "vegtam is a local-first API client for .http files.",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetArgs(args)
	root.SetOut(cfg.Stdout)
	root.SetErr(cfg.Stderr)
	root.PersistentFlags().BoolVar(&cfg.json, "json", false, "print JSON even on a terminal")
	root.AddCommand(newVersionCmd(&cfg))

	cmd, err := root.ExecuteC()
	if err == nil {
		return exitOK
	}
	if xe, ok := errors.AsType[*exitError](err); ok {
		return xe.code
	}
	fmt.Fprintf(cfg.Stderr, "vegtam: %v\nRun \"%s --help\" for usage.\n", err, cmd.CommandPath())
	return exitUsage
}
