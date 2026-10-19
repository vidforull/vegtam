package core

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

// ShellQuote returns s quoted for a POSIX shell if it needs it, for
// messages that show a command or its arguments. Text with a line break,
// another control character or an invisible one, such as a bidirectional
// override, is shown as a Go string instead, escapes and all, so that it
// cannot pass for something else.
func ShellQuote(s string) string {
	switch {
	case shellSafe.MatchString(s):
		return s
	case strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsPrint(r) && r != ' ' }):
		return strconv.Quote(s)
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
