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

// Invisible reports whether r is a character that a terminal does not
// show, yet that changes how the text around it reads or carries text
// that cannot be seen: a format character (Unicode category Cf: the
// marks and overrides of text direction, zero-width characters, the byte
// order mark, the soft hyphen, the tag characters), a line or paragraph
// separator, another default-ignorable one, such as the Hangul fillers,
// or one of the variation selectors 17 to 256, which no emoji uses. The
// selectors 1 to 16 are left out: emoji use them in ordinary text.
func Invisible(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Other_Default_Ignorable_Code_Point) ||
		0xe0100 <= r && r <= 0xe01ef
}
