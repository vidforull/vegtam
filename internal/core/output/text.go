package output

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The text form of results, for terminals: the CLI prints it and the
// terminal interface shows it. Whoever puts it on a terminal passes it
// through Printable.

// WriteResponse writes the response of res: the status and the time, the
// headers if headers is set, the body, and the outcomes of its directives.
func WriteResponse(b *strings.Builder, res *Result, headers bool) {
	r := res.Response
	status := strings.TrimSpace(fmt.Sprintf("%s %d %s", r.Proto, r.Status, r.Reason))
	fmt.Fprintf(b, "%s (%s)\n", status, duration(res.Timing))
	if headers {
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

// WriteRequest writes r in .http form.
func WriteRequest(b *strings.Builder, r *Request) {
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

func writeHeaders(b *strings.Builder, headers []Header) {
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

// Printable returns s with control characters other than tab and line
// feed, and bytes that are not UTF-8, shown as \xNN: a response must not
// be able to drive the terminal, and a lone byte such as 0x9b starts an
// escape sequence on a terminal that does not read UTF-8.
func Printable(s string) string {
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
func duration(t *Timing) string {
	if t == nil {
		return "?"
	}
	d := time.Duration(t.TotalMS * float64(time.Millisecond))
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}
