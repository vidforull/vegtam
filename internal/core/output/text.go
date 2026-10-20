package output

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vidforull/vegtam/internal/core"
)

// The text form of results, for terminals: the CLI prints it and the
// terminal interface shows it. Whoever puts it on a terminal passes it
// through Printable.

// WriteResponse writes the response of res: the status and the time, the
// headers and what the request went through (WriteTrace) if headers is
// set, the body, JSON formatted by FormatJSON with fold, and the outcomes
// of its directives.
func WriteResponse(b *strings.Builder, res *Result, headers bool, fold int) {
	r := res.Response
	status := strings.TrimSpace(fmt.Sprintf("%s %d %s", r.Proto, r.Status, r.Reason))
	fmt.Fprintf(b, "%s (%s)\n", status, duration(res.Timing))
	if headers {
		writeHeaders(b, r.Headers)
		WriteTrace(b, res)
	}
	if r.Body != "" {
		body := r.Body
		if r.Encoding == "" {
			body, _ = FormatJSON(body, fold)
		}
		b.WriteString("\n")
		writeBody(b, body, r.Encoding)
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
		writeBody(b, r.Body, r.Encoding)
	}
}

// WriteTransport writes what a request is sent with, as a comment line
// that may go before the request.
func WriteTransport(b *strings.Builder, t *Transport) {
	d := func(ms float64) string { return core.FormatTimeout(time.Duration(ms * float64(time.Millisecond))) }
	b.WriteString("# ")
	if t.Version != "" {
		b.WriteString(t.Version + "; ")
	}
	fmt.Fprintf(b, "timeouts: connect %s, read %s, max time %s\n", d(t.ConnectTimeoutMS), d(t.ReadTimeoutMS), d(t.MaxTimeMS))
}

func writeHeaders(b *strings.Builder, headers []Header) {
	for _, h := range headers {
		fmt.Fprintf(b, "%s: %s\n", h.Name, h.Value)
	}
}

// writeBody writes a body. A body that is not text is only described.
func writeBody(b *strings.Builder, body, encoding string) {
	if encoding == "base64" {
		raw, _ := base64.StdEncoding.DecodeString(body)
		fmt.Fprintf(b, "[binary body, %d bytes; --json shows it base64-encoded]\n", len(raw))
		return
	}
	b.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\n")
	}
}

// FormatJSON returns the JSON text s indented by two spaces, with every
// object and array that is fold levels deep or deeper folded into a
// summary: {… 3 keys}, [… 1 item]. The value s is at level 0, so a fold
// of 1 shows its members and folds theirs; a fold of 0 folds nothing. If
// s is not one JSON value, FormatJSON returns it unchanged, and false.
//
// The CLI prints bodies with a fold of 0. The terminal interface folds a
// body once it has masked it whole, so that no secret value is cut in
// two by a fold.
func FormatJSON(s string, fold int) (string, bool) {
	var out bytes.Buffer
	if json.Indent(&out, []byte(s), "", "  ") != nil {
		return s, false
	}
	if fold <= 0 {
		return out.String(), true
	}
	return foldJSON(out.String(), fold), true
}

// foldJSON folds the objects and arrays of s, a JSON text that
// json.Indent wrote, that are fold levels deep or deeper. Empty ones stay
// as they are: {} says as much as a summary would.
func foldJSON(s string, fold int) string {
	var b strings.Builder
	b.Grow(len(s))
	level := 0
	for i := 0; i < len(s); {
		switch c := s[i]; c {
		case '"':
			end := endOfString(s, i)
			b.WriteString(s[i:end])
			i = end
			continue
		case '{', '[':
			if level >= fold {
				if end, n := endOfValue(s, i); n > 0 {
					b.WriteString(summary(c, n))
					i = end
					continue
				}
			}
			level++
		case '}', ']':
			level--
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// endOfString returns the index just past the JSON string that starts at
// s[i], a quote.
func endOfString(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return len(s)
}

// endOfValue returns the index just past the object or array that starts
// at s[i], and how many members or items it has.
func endOfValue(s string, i int) (end, n int) {
	depth := 0
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '"':
			if depth == 1 && n == 0 {
				n = 1
			}
			j = endOfString(s, j) - 1
		case '{', '[':
			if depth == 1 && n == 0 {
				n = 1
			}
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return j + 1, n
			}
		case ',':
			if depth == 1 {
				n++
			}
		case ' ', '\n':
		default: // a number, true, false or null
			if depth == 1 && n == 0 {
				n = 1
			}
		}
	}
	return len(s), n
}

// summary describes a folded object, open being '{', or array.
func summary(open byte, n int) string {
	what, closing := "item", "]"
	if open == '{' {
		what, closing = "key", "}"
	}
	if n != 1 {
		what += "s"
	}
	return fmt.Sprintf("%c… %d %s%s", open, n, what, closing)
}

// Printable returns s with control characters other than tab and line
// feed, and bytes that are not UTF-8, shown as \xNN, and invisible
// characters (core.Invisible) shown as \uNNNN: a response must not
// be able to drive the terminal, a lone byte such as 0x9b starts an
// escape sequence on a terminal that does not read UTF-8, and a right-to-
// left override or a zero-width space makes text read as other than it
// is.
func Printable(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	isControl := func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }
	escaped := func(r rune) bool { return isControl(r) || core.Invisible(r) }
	if utf8.ValidString(s) && !strings.ContainsFunc(s, escaped) {
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
		case core.Invisible(r) && r > 0xffff:
			fmt.Fprintf(&b, `\U%08x`, r)
		case core.Invisible(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[:size])
		}
		s = s[size:]
	}
	return b.String()
}

// WriteTrace writes what the request of res went through, in lines that
// start with "* ", as curl -v writes its own: each redirect, then the
// connection of the last hop, its TLS, the server's certificate, the time
// each phase of each hop ended, and the cookies of each hop, without their
// values. It writes nothing for a request that was not sent.
func WriteTrace(b *strings.Builder, res *Result) {
	if res.Timing == nil {
		return
	}
	last := max(res.hops-1, 0)
	for i, r := range res.Redirects {
		parts := []string{fmt.Sprintf("%d → %s", r.Status, r.Location)}
		if len(r.Dropped) > 0 {
			parts = append(parts, "dropped "+strings.Join(r.Dropped, ", "))
		}
		writeHop(b, append(parts, hop(r.RemoteAddr, r.ResolvedBy, r.Proxy, nil, r.Timing)...))
		if i < last {
			writeCookies(b, res.Cookies, i)
		}
	}
	writeHop(b, hop(res.RemoteAddr, res.ResolvedBy, res.Proxy, res.TLS, cmp.Or(res.last, res.Timing)))
	if t := res.TLS; t != nil && t.Peer != nil {
		fmt.Fprintf(b, "* certificate %s, issuer %s, expires %s\n", t.Peer.Subject, t.Peer.Issuer, t.Peer.NotAfter)
	}
	writeCookies(b, res.Cookies, last)
}

// writeCookies writes the names of the cookies of the hop-th hop: those
// sent, and those set, with why one was not kept.
func writeCookies(b *strings.Builder, c *Cookies, hop int) {
	if c == nil {
		return
	}
	var sent, set []string
	for _, s := range c.Sent {
		if s.Hop == hop {
			sent = append(sent, s.Name)
		}
	}
	for _, s := range c.Set {
		switch {
		case s.Hop != hop:
		case s.Stored:
			set = append(set, s.Name)
		case s.Reason == "removed":
			set = append(set, s.Name+" (removed)")
		default:
			set = append(set, s.Name+" (not kept: "+s.Reason+")")
		}
	}
	var parts []string
	if sent != nil {
		parts = append(parts, "sent "+strings.Join(sent, ", "))
	}
	if set != nil {
		parts = append(parts, "set "+strings.Join(set, ", "))
	}
	if parts != nil {
		b.WriteString("* cookies: " + strings.Join(parts, " · ") + "\n")
	}
}

// hop describes a hop that went to addr, where the flag by sent it if it
// is not "", through proxy if it is not "", with the TLS of t if it is not
// nil, and took tm.
func hop(addr, by, proxy string, t *TLS, tm *Timing) []string {
	var parts []string
	switch {
	case addr == "":
		parts = append(parts, "no connection")
	case tm.Reused:
		parts = append(parts, "connected to "+addr+" (reused)")
	default:
		parts = append(parts, "connected to "+addr)
	}
	if by != "" {
		parts = append(parts, "resolved by "+by)
	}
	if proxy != "" {
		parts = append(parts, "through "+proxy)
	}
	if t != nil {
		v := cmp.Or(t.Version, "TLS")
		if !t.Verified {
			v += " (not verified)"
		}
		parts = append(parts, v)
		if t.ALPN != "" {
			parts = append(parts, t.ALPN)
		}
	}
	var times []string
	for _, p := range []struct {
		name string
		ms   *float64
	}{{"dns", tm.NameLookupMS}, {"connect", tm.ConnectMS}, {"tls", tm.AppConnectMS}, {"ttfb", tm.StartTransferMS}, {"total", &tm.TotalMS}} {
		if p.ms != nil {
			times = append(times, p.name+" "+formatMS(*p.ms))
		}
	}
	return append(parts, strings.Join(times, " "))
}

func writeHop(b *strings.Builder, parts []string) {
	b.WriteString("* " + strings.Join(parts, " · ") + "\n")
}

// duration formats the total time of t.
func duration(t *Timing) string {
	if t == nil {
		return "?"
	}
	return formatMS(t.TotalMS)
}

// formatMS formats a time in milliseconds.
func formatMS(ms float64) string {
	d := time.Duration(ms * float64(time.Millisecond))
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}
