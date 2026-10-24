//go:build linux || darwin

package keeper

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vidforull/vegtam/internal/core"
)

// maxName is the most bytes of a process's name that are kept: those of
// Linux and macOS hold 15 and 16.
const maxName = 64

// processName returns b, the name a process gave itself, as a Peer holds
// it: printable characters only, the rest as '?', and brackets for
// parentheses, so that a name cannot close the parenthesis that String
// writes around it and pass for more than a name.
func processName(b []byte) string {
	b = b[:min(len(b), maxName)]
	var s strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		switch {
		case r == utf8.RuneError && size == 1, !unicode.IsPrint(r), core.Invisible(r):
			s.WriteByte('?')
		case r == '(':
			s.WriteByte('[')
		case r == ')':
			s.WriteByte(']')
		default:
			s.WriteRune(r)
		}
		b = b[size:]
	}
	return strings.TrimSpace(s.String())
}
