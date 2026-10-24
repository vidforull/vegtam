package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/policy"
	"github.com/vidforull/vegtam/internal/tui"
)

type tuiFlags struct {
	env       string
	maxBody   byteSize
	noHistory bool
	net       netFlags
}

// newTUIFlags returns the flags of tui as they are when not given, which
// are also what vegtam alone uses.
func newTUIFlags() tuiFlags { return tuiFlags{maxBody: 1 << 20, net: newNetFlags()} }

func newTUICmd(cfg *Config) *cobra.Command {
	f := newTUIFlags()
	cmd := &cobra.Command{
		Use:   "tui [<file>|<dir>]",
		Short: "Browse and send requests in the terminal",
		Long: `Open the terminal interface on a .http file, or on the .http files in a
directory and below it: "." if none is named. On a terminal, vegtam with
no command does the same.

One pane lists the files and their requests, the next shows the selected
request as it would be sent, its variables coloured, and where each of
its secrets may go, and the last the latest response. enter sends the request as vegtam run does, and esc
cancels it; for a method other than GET, HEAD or OPTIONS, and for a
request with "# @note", it asks first, showing the note, and only a
second enter sends. So it does for a request that would send a secret to
an origin the secret is not bound to (see vegtam run --help): nothing is
sent, the question names the secret and where it may go, and a second
enter sends it there this once. / searches the list, y copies the request
as a curl command, z folds the JSON of the response, e chooses the
environment, h lists the latest runs, tab moves between panes, ? lists
the keys and q quits.

A value that "# @capture" takes is a variable for the requests sent after
it, until another environment is chosen. The requests sent go into the
history of runs, as with vegtam run (see vegtam run --help), unless
--no-history is given; the interface writes no other file.`,
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
	fl.Var(&f.maxBody, "max-body", "response body bytes to keep, such as 64KiB or 10MB; the rest is not read")
	fl.BoolVar(&f.noHistory, "no-history", false, "keep the requests sent out of the history of runs")
	f.net.add(fl)
	return cmd
}

func runTUI(ctx context.Context, cfg *Config, f tuiFlags, path string) error {
	switch {
	case cfg.json:
		return core.Errorf(core.KindUsage, core.Source{}, "the terminal interface prints no JSON: use run, show or list")
	case !cfg.Interactive:
		return core.Errorf(core.KindUsage, core.Source{}, "the terminal interface needs a terminal for its input and output")
	}
	pol, err := cfg.loadPolicy()
	if err != nil {
		return err
	}
	// Its warnings, --insecure's among them, are left on the terminal once
	// the interface is gone; the status line says --insecure meanwhile.
	tr, err := f.net.transport(cfg, pol)
	if err != nil {
		return err
	}
	// Bubble Tea writes to the terminal itself, not through the masked
	// writer: it draws the screen in pieces, which masking each write could
	// not follow. The interface masks everything it shows before drawing.
	m, err := tui.New(tui.Options{
		Path: path, Env: f.env, Trust: policy.DefaultStore(), Transport: tr, MaxBody: int64(f.maxBody),
		UserAgent: "vegtam/" + cfg.Version, History: cfg.history(f.noHistory), Secrets: pol.Secrets, Input: cfg.Stdin, Output: cfg.Stdout,
	})
	if err != nil {
		return err
	}
	cfg.secrets = m.Masker
	return m.Run(ctx)
}
