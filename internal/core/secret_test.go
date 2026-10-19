package core

import (
	"errors"
	"testing"
)

type secretMap map[string]string

func (m secretMap) SecretValue(s Secret) (string, error) {
	if v, ok := m[s.Name]; ok {
		return v, nil
	}
	return "", errors.New("no secret " + s.Name)
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
	m := NewMasker([]string{"", "a b&c/d", "abc", "abcdef", `q"\`, `<"&>`, "k+1%2F", "https://int.example.test:8443/v1"})
	tests := map[string]string{
		"echo k 1/":                                     "echo ***",
		"https://int.example.test:8443/v1/users":        "***/users",
		"dial tcp int.example.test:8443: refused":       "dial tcp ***: refused",
		"x509: certificate is not for int.example.test": "x509: certificate is not for ***",
		"x=a b&c/d":                 "x=***",
		"?x=a+b%26c%2Fd":            "?x=***",
		"/a%20b&c%2Fd":              "/***",
		`"a b&c\/d"`:                `"***"`,
		"abcdef abc":                "*** ***",
		`{"v":"q\"\\"} and q"\ too`: `{"v":"***"} and *** too`,
		`["\u003c\"\u0026\u003e"]`:  `["***"]`,
		`["<\"&>"]`:                 `["***"]`,
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

func TestMaskCut(t *testing.T) {
	m := NewMasker([]string{"s3cr3t/x", "k3y"})
	tests := map[string]string{
		"id=s3cr3t/x":    "id=***",
		"id=s3cr3t%2":    "id=***", // the URL-escaped form, cut
		"id=s3c":         "id=***",
		"id=k3y; k":      "id=***; ***",
		"id=s3cr3t/x; z": "id=***; z",
		"":               "",
	}
	for in, want := range tests {
		if got := m.MaskCut(in); got != want {
			t.Errorf("MaskCut(%q) = %q, want %q", in, got, want)
		}
	}
	if got := (*Masker)(nil).MaskCut("s3c"); got != "s3c" {
		t.Errorf("nil Masker: %q", got)
	}
}

func TestMaskJSON(t *testing.T) {
	m := NewMasker([]string{"url", `t"0k`, "n"})
	tests := map[string]string{
		// Keys stay; values are masked whole, never inside an escape.
		`{"url": "url", "a": ["x-url"]}`: `{"url": "***", "a": ["x-***"]}`,
		`{"v":"t\"0k\n"}`:                `{"v":"***\n"}`,
		`{"v": "a\nb", "n": 1}`:          `{"v": "a\nb", "n": 1}`,
		"{\n  \"n\" : \"n\"\n}":          "{\n  \"n\" : \"***\"\n}",
		`{"v":"safe"}`:                   `{"v":"safe"}`,
	}
	for in, want := range tests {
		if got := string(m.MaskJSON([]byte(in))); got != want {
			t.Errorf("MaskJSON(%s) = %s, want %s", in, got, want)
		}
	}
}
