package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/charmbracelet/x/term"

	"github.com/vidforull/vegtam/internal/cli"
)

// The version, the commit and the commit's date (RFC 3339, UTC), set at
// build time, as a release does, with
//
//	-ldflags "-X main.version=... -X main.commit=... -X main.date=..."
//
// Whatever is not set is taken from what the go command recorded in the
// binary; see stamp.
var (
	version = "dev"
	commit  string
	date    string
)

func main() {
	// Ctrl-C and SIGTERM cancel what is running, a request or a
	// {{$cmd NAME}}, and vegtam still prints what it has, masked. A second
	// one ends vegtam at once, should something not stop with ctx.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	context.AfterFunc(ctx, stop)
	bi, _ := debug.ReadBuildInfo()
	v, c, d := stamp(version, commit, date, bi)
	code := cli.Run(ctx, os.Args[1:], cli.Config{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		TTY:         isTerminal(os.Stdout),
		Interactive: term.IsTerminal(os.Stdin.Fd()) && term.IsTerminal(os.Stdout.Fd()),
		Version:     v,
		Commit:      c,
		Date:        d,
	})
	stop()
	os.Exit(code)
}

// stamp returns the version, the commit and its date: those set at build
// time, and for each one that was not, what the go command recorded in
// bi, which may be nil. go install of a tagged version records the
// version; go build in a git checkout records a pseudo-version, the
// commit, its date and whether the files had changes, which "+dirty"
// after the commit then says. An empty value was not set, and neither
// was a version of "dev" nor one of "(devel)" in bi; a version that is
// known from neither is "dev". The date and "+dirty" are taken for the
// commit that bi names only.
func stamp(version, commit, date string, bi *debug.BuildInfo) (v, c, d string) {
	if version == "" {
		version = "dev"
	}
	if bi == nil {
		return version, commit, date
	}
	var revision, vcsTime, modified string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			vcsTime = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
	if commit == "" {
		commit = revision
	}
	if commit != "" && commit == revision {
		if date == "" {
			date = vcsTime
		}
		if modified == "true" {
			commit += "+dirty"
		}
	}
	return version, commit, date
}

// isTerminal reports whether f is a character device. This is the
// standard-library approximation of isatty: /dev/null counts as a terminal
// too, which only matters when the output is thrown away anyway.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
