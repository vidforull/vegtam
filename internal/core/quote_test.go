package core

import "testing"

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"op://vault/item":   "op://vault/item",
		"-test.run=^Test$":  `'-test.run=^Test$'`,
		"it's":              `'it'\''s'`,
		"two words":         `'two words'`,
		"a\nTOKEN  op read": `"a\nTOKEN  op read"`,
		"tab\there":         `"tab\there"`,
		"evil\u202etxt.sh":  `"evil\u202etxt.sh"`,
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
