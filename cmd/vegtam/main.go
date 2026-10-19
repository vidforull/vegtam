package main

import (
	"context"
	"os"

	"github.com/vidforull/vegtam/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], cli.Config{
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		TTY:     isTerminal(os.Stdout),
		Version: version,
	}))
}

// isTerminal reports whether f is a character device. This is the
// standard-library approximation of isatty: /dev/null counts as a terminal
// too, which only matters when the output is thrown away anyway.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
