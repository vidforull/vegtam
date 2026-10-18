package core

import (
	"errors"
	"testing"
)

type secretMap map[string]string

func (m secretMap) SecretValue(name string) (string, error) {
	if v, ok := m[name]; ok {
		return v, nil
	}
	return "", errors.New("no secret " + name)
}

func TestText(t *testing.T) {
	text := Text{{Text: "Bearer "}, {Secret: &Secret{Name: "token"}}, {Text: "; "}, {Secret: &Secret{Name: "$env KEY"}}}
	if got := text.Masked(); got != "Bearer {{token}}; {{$env KEY}}" {
		t.Errorf("Masked = %q", got)
	}
	got, err := text.Reveal(secretMap{"token": "t0k", "$env KEY": "k3y"})
	if got != "Bearer t0k; k3y" || err != nil {
		t.Errorf("Reveal = %q, %v", got, err)
	}
	if _, err := text.Reveal(secretMap{}); err == nil {
		t.Error("Reveal without the secrets: no error")
	}
	if !text.HasSecret() || text[:1].HasSecret() {
		t.Error("HasSecret is wrong")
	}
}

func TestMasker(t *testing.T) {
	m := NewMasker([]string{"", "a b&c/d", "abc", "abcdef", `q"\`})
	tests := map[string]string{
		"x=a b&c/d":                 "x=***",
		"?x=a+b%26c%2Fd":            "?x=***",
		"/a%20b&c%2Fd":              "/***",
		"abcdef abc":                "*** ***",
		`{"v":"q\"\\"} and q"\ too`: `{"v":"***"} and *** too`,
		"nothing secret":            "nothing secret",
	}
	for in, want := range tests {
		if got := m.Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
	if got := (*Masker)(nil).Mask("abc"); got != "abc" {
		t.Errorf("nil Masker: %q", got)
	}
	if got := NewMasker(nil).Mask("abc"); got != "abc" {
		t.Errorf("empty Masker: %q", got)
	}
}
