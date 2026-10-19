package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/x/term"

	"github.com/vidforull/vegtam/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Ctrl-C and SIGTERM cancel what is running, a request or a
	// {{$cmd NAME}}, and vegtam still prints what it has, masked. A second
	// one ends vegtam at once, should something not stop with ctx.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	context.AfterFunc(ctx, stop)
	code := cli.Run(ctx, os.Args[1:], cli.Config{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		TTY:         isTerminal(os.Stdout),
		Interactive: term.IsTerminal(os.Stdin.Fd()) && term.IsTerminal(os.Stdout.Fd()),
		Version:     version,
	})
	stop()
	os.Exit(code)
}

// isTerminal reports whether f is a character device. This is the
// standard-library approximation of isatty: /dev/null counts as a terminal
// too, which only matters when the output is thrown away anyway.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
