package cli

import (
	"fmt"
	"strings"

	"github.com/vidforull/vegtam/internal/core/output"
)

// printResult prints the i-th result of a run as text. With several
// requests each block starts with "### ref". The request is shown with
// --verbose and for a dry run, and so is what it went through, up to an
// error, which goes to stderr. A dry run shows, after the request, where
// each of its secrets may go and what sending it would need.
func (c *Config) printResult(res *output.Result, i int, several, verbose bool) {
	var b strings.Builder
	if several {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "### %s\n", res.Ref)
	}
	dryRun := res.Response == nil && res.Error == nil
	if res.Request != nil && (verbose || dryRun) {
		if res.Transport != nil {
			output.WriteTransport(&b, res.Transport)
		}
		output.WriteRequest(&b, res.Request)
		output.WriteSecrets(&b, res.SecretOrigins)
		output.WriteConfirm(&b, res.Confirm)
		if res.Response != nil || res.Timing != nil {
			b.WriteString("\n")
		}
	}
	switch {
	case res.Response != nil:
		output.WriteResponse(&b, res, verbose, 0)
	case verbose:
		output.WriteTrace(&b, res)
	}
	fmt.Fprint(c.out, c.text(b.String()))
	if res.Error != nil {
		c.printError(res.Error)
	}
}

// printable is output.Printable, kept under this name for FuzzPrintable,
// which make fuzz runs in this package.
func printable(s string) string { return output.Printable(s) }

// text makes s fit for a terminal, as printable does, once every secret
// value in it is masked: printable shows an invisible character as an
// escape, which would hide a value that holds one from the masker of
// the writer, which comes last.
func (c *Config) text(s string) string { return printable(c.masker.Mask(s)) }
