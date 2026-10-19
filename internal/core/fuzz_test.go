package core

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseTemplate checks that literal text never holds "{{", and that
// the pieces, written back with placeholders in canonical form, parse to
// the same pieces.
func FuzzParseTemplate(f *testing.F) {
	for _, s := range []string{
		"", "plain", "{{host}}/users/{{ id }}?k={{$env KEY}}", "{{$cmd TOKEN}}}", "a{{b}}{{c}}d",
		"{{", "{{}}", "{{$env}}", "{{a b c}}", "}}{{x}}", "{{x}", "{{{x}}}", "{{ $env\tKEY }}",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		pieces, err := ParseTemplate(s)
		if err != nil {
			return
		}
		var b strings.Builder
		for i, p := range pieces {
			switch {
			case p.Ref != nil:
				b.WriteString(p.Ref.String())
			case p.Text == "" || strings.Contains(p.Text, "{{") || i > 0 && pieces[i-1].Ref == nil:
				t.Fatalf("%q: text piece %d is %q", s, i, p.Text)
			default:
				b.WriteString(p.Text)
			}
		}
		if again, err := ParseTemplate(b.String()); err != nil || !reflect.DeepEqual(again, pieces) {
			t.Fatalf("%q written back as %q parses to %v, %v", s, b.String(), again, err)
		}
	})
}

// maskable reports whether a fuzzed secret can be checked for: a value
// with "*" in it could be made of the "***" that replaces another.
func maskable(secrets ...string) bool {
	for _, s := range secrets {
		if s == "" || strings.Contains(s, "*") {
			return false
		}
	}
	return true
}

// FuzzMasker checks that no secret is left in masked text, cut off or
// not.
func FuzzMasker(f *testing.F) {
	f.Add("s3cret/x+y", "t0ken", "Bearer s3cret/x+y and s3cret%2Fx%2By, t0ken")
	f.Add("https://user:pw@api.example.test:8443/x", "pw", `{"url": "https:\/\/api.example.test:8443"}`)
	f.Add("ab", "bc", "abc aabbcc")
	f.Add("<&>", "é", `<&> é`)
	f.Fuzz(func(t *testing.T, a, b, text string) {
		if !maskable(a, b) {
			return
		}
		m := NewMasker([]string{a, b})
		for _, got := range []string{m.Mask(text), m.MaskCut(text)} {
			if strings.Contains(got, a) || strings.Contains(got, b) {
				t.Fatalf("Mask(%q) with %q, %q = %q", text, a, b, got)
			}
		}
	})
}

// FuzzMaskJSON checks that masking a JSON document leaves it valid, and
// leaves the secret in none of its string values. A JSON string is UTF-8:
// a secret that is not shows up in one only with its bad bytes replaced,
// and the bytes of U+FFFD would match it.
func FuzzMaskJSON(f *testing.F) {
	f.Add("s3cret/x", []byte(`{"token": "s3cret/x", "list": ["a s3cret\/x b"], "s3cret/x": 1}`))
	f.Add("<b>", []byte(`["<b>", "<b>", {"k": "\\<b>"}]`))
	f.Add("x", []byte(`"x"`))
	f.Add("\"q", []byte(`{"a": "\"q\"q"}`))
	f.Fuzz(func(t *testing.T, secret string, doc []byte) {
		if !maskable(secret) || !utf8.ValidString(secret) || !json.Valid(doc) {
			return
		}
		out := NewMasker([]string{secret}).MaskJSON(doc)
		// Numbers stay as written: 1e700 is valid JSON but no float64.
		dec := json.NewDecoder(bytes.NewReader(out))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("MaskJSON(%s) = %s: %v", doc, out, err)
		}
		if s, ok := stringValue(v, secret); ok {
			t.Fatalf("MaskJSON(%s) with %q = %s: value %q", doc, secret, out, s)
		}
	})
}

// stringValue returns a string value in v, object keys aside, that
// contains secret.
func stringValue(v any, secret string) (string, bool) {
	switch v := v.(type) {
	case string:
		return v, strings.Contains(v, secret)
	case []any:
		for _, x := range v {
			if s, ok := stringValue(x, secret); ok {
				return s, true
			}
		}
	case map[string]any:
		for _, x := range v {
			if s, ok := stringValue(x, secret); ok {
				return s, true
			}
		}
	}
	return "", false
}
