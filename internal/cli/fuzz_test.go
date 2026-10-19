package cli

import (
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzPrintable checks that what printable returns can go to a terminal:
// valid UTF-8 without control characters other than tab and line feed,
// so no escape sequence, 7-bit or 8-bit; and that it changes nothing more
// on a second pass.
func FuzzPrintable(f *testing.F) {
	for _, s := range []string{
		"plain text\n", "plain\x1b]0;title\x07 text", "\x1b[2J\x1b[H", "a\r\nb\rc", "\u009b2J", "\x9b2J",
		"\xc2\x9b", "tab\tand\x00nul", "\u202eevil", "caf\xe9",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := printable(s)
		if !utf8.ValidString(got) {
			t.Fatalf("printable(%q) = %q: not UTF-8", s, got)
		}
		for _, r := range got {
			if unicode.IsControl(r) && r != '\n' && r != '\t' {
				t.Fatalf("printable(%q) = %q: holds %U", s, got, r)
			}
		}
		if again := printable(got); again != got {
			t.Fatalf("printable(%q) = %q, then %q", s, got, again)
		}
	})
}
