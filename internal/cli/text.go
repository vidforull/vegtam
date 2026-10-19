package cli

import (
	"fmt"
	"strings"

	"github.com/vidforull/vegtam/internal/core/output"
)

// printResult prints the i-th result of a run as text. With several
// requests each block starts with "### ref". The request is shown with
// --verbose and for a dry run; an error goes to stderr.
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
		output.WriteRequest(&b, res.Request)
		if res.Response != nil {
			b.WriteString("\n")
		}
	}
	if res.Response != nil {
		output.WriteResponse(&b, res, verbose, 0)
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
