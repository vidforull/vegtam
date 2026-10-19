package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/policy"
	"github.com/vidforull/vegtam/internal/tui"
)

type tuiFlags struct {
	env     string
	timeout time.Duration
	maxBody byteSize
}

// newTUIFlags returns the flags of tui as they are when not given, which
// are also what vegtam alone uses.
func newTUIFlags() tuiFlags { return tuiFlags{timeout: 30 * time.Second, maxBody: 1 << 20} }

func newTUICmd(cfg *Config) *cobra.Command {
	f := newTUIFlags()
	cmd := &cobra.Command{
		Use:   "tui [<file>|<dir>]",
		Short: "Browse and send requests in the terminal",
		Long: `Open the terminal interface on a .http file, or on the .http files in a
directory and below it: "." if none is named. On a terminal, vegtam with
no command does the same.

One pane lists the files and their requests, the next shows the selected
request as written or, with an environment, as it would be sent, and the
last the latest response. enter sends the request as
vegtam run does, after asking unless its method is GET, HEAD or OPTIONS,
and esc cancels it; e chooses the environment, tab moves between panes,
? lists the keys and q quits.

A value that "# @capture" takes is a variable for the requests sent after
it, until another environment is chosen. The interface writes no files.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			return runTUI(cmd.Context(), cfg, f, path)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.env, "env", "e", "", "the environment to start with")
	fl.DurationVar(&f.timeout, "timeout", f.timeout, "time limit for each request, body included; 0 for none")
	fl.Var(&f.maxBody, "max-body", "response body bytes to keep, such as 64KiB or 10MB; the rest is not read")
	return cmd
}

func runTUI(ctx context.Context, cfg *Config, f tuiFlags, path string) error {
	switch {
	case cfg.json:
		return core.Errorf(core.KindUsage, core.Source{}, "the terminal interface prints no JSON: use run, show or list")
	case !cfg.Interactive:
		return core.Errorf(core.KindUsage, core.Source{}, "the terminal interface needs a terminal for its input and output")
	case f.timeout < 0:
		return core.Errorf(core.KindUsage, core.Source{}, "--timeout must not be negative")
	}
	// Bubble Tea writes to the terminal itself, not through the masked
	// writer: it draws the screen in pieces, which masking each write could
	// not follow. The interface masks everything it shows before drawing.
	m, err := tui.New(tui.Options{
		Path: path, Env: f.env, Trust: policy.DefaultStore(), Timeout: f.timeout, MaxBody: int64(f.maxBody),
		UserAgent: "vegtam/" + cfg.Version, Input: cfg.Stdin, Output: cfg.Stdout,
	})
	if err != nil {
		return err
	}
	cfg.secrets = m.Masker
	return m.Run(ctx)
}
