package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
		writeRequest(&b, res.Request)
		if res.Response != nil {
			b.WriteString("\n")
		}
	}
	if res.Response != nil {
		writeResponse(&b, res, verbose)
	}
	fmt.Fprint(c.out, printable(b.String()))
	if res.Error != nil {
		c.printError(res.Error)
	}
}

// writeResponse writes the response of res: the status and the time, the
// headers with verbose, the body, and the outcomes of its directives.
func writeResponse(b *strings.Builder, res *output.Result, verbose bool) {
	r := res.Response
	status := strings.TrimSpace(fmt.Sprintf("%s %d %s", r.Proto, r.Status, r.Reason))
	fmt.Fprintf(b, "%s (%s)\n", status, duration(res.Timing))
	if verbose {
		writeHeaders(b, r.Headers)
	}
	if r.Body != "" {
		b.WriteString("\n")
		writeBody(b, r.Body, r.Encoding, true)
	}
	if r.Truncated {
		b.WriteString("[truncated: the body is longer than --max-body]\n")
	}
	if len(res.Asserts) > 0 || len(res.Captures) > 0 {
		b.WriteString("\n")
	}
	for _, a := range res.Asserts {
		if a.Passed {
			fmt.Fprintf(b, "✓ %s\n", a.Expression)
		} else {
			fmt.Fprintf(b, "✗ %s (actual: %s)\n", a.Expression, strings.ReplaceAll(a.Actual, "\n", `\n`))
		}
	}
	if len(res.Captures) > 0 {
		var names []string
		for _, c := range res.Captures {
			if c.Secret {
				names = append(names, c.Name)
			} else {
				names = append(names, c.Name+" (plain)")
			}
		}
		fmt.Fprintf(b, "captured: %s\n", strings.Join(names, ", "))
	}
}

// writeRequest writes r in .http form.
func writeRequest(b *strings.Builder, r *output.Request) {
	fmt.Fprintf(b, "%s %s\n", r.Method, r.URL)
	writeHeaders(b, r.Headers)
	switch {
	case r.BodyFile != "":
		fmt.Fprintf(b, "\n< %s\n", r.BodyFile)
	case r.Body != "":
		b.WriteString("\n")
		writeBody(b, r.Body, r.Encoding, false)
	}
}

func writeHeaders(b *strings.Builder, headers []output.Header) {
	for _, h := range headers {
		fmt.Fprintf(b, "%s: %s\n", h.Name, h.Value)
	}
}

// writeBody writes a body, indented if it is JSON and indent is set. A
// body that is not text is only described.
func writeBody(b *strings.Builder, body, encoding string, indent bool) {
	if encoding == "base64" {
		raw, _ := base64.StdEncoding.DecodeString(body)
		fmt.Fprintf(b, "[binary body, %d bytes; --json shows it base64-encoded]\n", len(raw))
		return
	}
	var out bytes.Buffer
	if indent && json.Indent(&out, []byte(body), "", "  ") == nil {
		body = out.String()
	}
	b.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\n")
	}
}

// printable returns s with control characters other than tab and line
// feed, and bytes that are not UTF-8, shown as \xNN: a response must not
// be able to drive the terminal, and a lone byte such as 0x9b starts an
// escape sequence on a terminal that does not read UTF-8.
func printable(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	isControl := func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }
	if utf8.ValidString(s) && !strings.ContainsFunc(s, isControl) {
		return s
	}
	var b strings.Builder
	for s != "" {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		case isControl(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteString(s[:size])
		}
		s = s[size:]
	}
	return b.String()
}

// duration formats the total time of t.
func duration(t *output.Timing) string {
	if t == nil {
		return "?"
	}
	d := time.Duration(t.TotalMS * float64(time.Millisecond))
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}
