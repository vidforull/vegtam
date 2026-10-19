package cli

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/vidforull/vegtam/internal/core"
)

// FuzzPrintable checks that what printable returns can go to a terminal:
// valid UTF-8 without control characters other than tab and line feed,
// so no escape sequence, 7-bit or 8-bit, and without invisible
// characters (core.Invisible), such as those of text direction; that
// text without either comes back as it was, line breaks aside; and that
// it changes nothing more on a second pass.
func FuzzPrintable(f *testing.F) {
	for _, s := range []string{
		"plain text\n", "plain\x1b]0;title\x07 text", "\x1b[2J\x1b[H", "a\r\nb\rc", "\u009b2J", "\x9b2J",
		"\xc2\x9b", "tab\tand\x00nul", "\u202eevil", "caf\xe9", "a\u200bb\ufeff", "\u2066x\u2069", "\U000e0041\U000e007f",
		"soft\u00adhyphen", "\u202a\u202b\u202c\u202d\u202e", `\u202e`, "emoji \U0001f468\u200d\U0001f469", "\u2028\u2029",
		"\u2764\ufe0f", "x\U000e0100\U000e01ef", "\u3164\u115f\u034f",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := printable(s)
		if !utf8.ValidString(got) {
			t.Fatalf("printable(%q) = %q: not UTF-8", s, got)
		}
		for _, r := range got {
			if unicode.IsControl(r) && r != '\n' && r != '\t' || core.Invisible(r) {
				t.Fatalf("printable(%q) = %q: holds %U", s, got, r)
			}
		}
		clean := utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool {
			return unicode.IsControl(r) && r != '\n' && r != '\t' || core.Invisible(r)
		})
		if want := strings.ReplaceAll(s, "\r\n", "\n"); clean && got != want {
			t.Fatalf("printable(%q) = %q: changed text with nothing to escape", s, got)
		}
		if again := printable(got); again != got {
			t.Fatalf("printable(%q) = %q, then %q", s, got, again)
		}
	})
}
