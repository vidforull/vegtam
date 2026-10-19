package core

import (
	"bytes"
	"cmp"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
)

// Prepared is a request with its placeholders resolved. Secrets stay
// named segments of Text until the request is sent.
type Prepared struct {
	Request *Request
	Method  string
	URL     Text
	Headers []PreparedHeader
	Body    Text
}

// PreparedHeader is a header with a resolved value.
type PreparedHeader struct {
	Name  string
	Value Text
}

// Secret names a secret value. Prepared requests hold only the name; the
// value is looked up from Secrets when the request is sent.
type Secret struct {
	Name string // as in its placeholder: "token" or "$env TOKEN"
}

// Secrets looks up secret values by name.
type Secrets interface {
	SecretValue(name string) (string, error)
}

// Segment is literal text or a secret.
type Segment struct {
	Text   string
	Secret *Secret
}

// Text is a resolved template: literal text with secrets in between.
type Text []Segment

// Masked renders t with every secret shown as its placeholder.
func (t Text) Masked() string {
	var b strings.Builder
	for _, s := range t {
		if s.Secret != nil {
			b.WriteString("{{" + s.Secret.Name + "}}")
		} else {
			b.WriteString(s.Text)
		}
	}
	return b.String()
}

// Reveal renders t with the secret values from src. The result is for
// the wire only.
func (t Text) Reveal(src Secrets) (string, error) {
	var b strings.Builder
	for _, s := range t {
		if s.Secret == nil {
			b.WriteString(s.Text)
			continue
		}
		v, err := src.SecretValue(s.Secret.Name)
		if err != nil {
			return "", err
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

// HasSecret reports whether t contains a secret.
func (t Text) HasSecret() bool {
	return slices.ContainsFunc(t, func(s Segment) bool { return s.Secret != nil })
}

// Masker hides secret values in free text: error messages, response
// headers and bodies. A nil *Masker hides nothing.
type Masker struct {
	r     *strings.Replacer
	forms []string
}

// NewMasker returns a Masker that replaces each value, and its URL- and
// JSON-escaped forms, with "***". A value that is a URL also hides its
// host, which errors and responses often name alone.
func NewMasker(values []string) *Masker {
	var forms []string
	for _, v := range values {
		if v == "" {
			continue
		}
		forms = append(forms, escapes(v)...)
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			forms = append(forms, escapes(u.Host)...)
			forms = append(forms, escapes(u.Hostname())...)
		}
	}
	// Longest first, so that a value is never half-masked because a
	// shorter one is part of it.
	slices.SortFunc(forms, func(a, b string) int { return cmp.Or(len(b)-len(a), strings.Compare(a, b)) })
	forms = slices.Compact(forms)
	var pairs []string
	for _, f := range forms {
		pairs = append(pairs, f, "***")
	}
	return &Masker{strings.NewReplacer(pairs...), forms}
}

// escapes returns v and the forms it may come back in.
func escapes(v string) []string {
	j := jsonString(v, false)
	forms := []string{v, url.QueryEscape(v), url.PathEscape(v), jsonString(v, true), j,
		strings.ReplaceAll(j, "/", `\/`)} // as PHP escapes JSON
	// A server that decodes a query and echoes it turns "+" into a space.
	if d, err := url.QueryUnescape(v); err == nil {
		forms = append(forms, d)
	}
	return forms
}

// jsonString returns the contents of s encoded as a JSON string, quotes
// excluded, with <, > and & escaped or not.
func jsonString(s string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	_ = enc.Encode(s) // a string always encodes
	return string(b.Bytes()[1 : b.Len()-2])
}

// Mask returns s with every secret value replaced.
func (m *Masker) Mask(s string) string {
	if m == nil {
		return s
	}
	return m.r.Replace(s)
}

// MaskCut is Mask for text cut off at its end, such as a truncated
// response body: it also hides a value that the cut left only the start
// of.
func (m *Masker) MaskCut(s string) string {
	if m == nil {
		return s
	}
	s = m.r.Replace(s)
	cut := 0
	for _, f := range m.forms {
		for n := min(len(f)-1, len(s)); n > cut; n-- {
			if strings.HasSuffix(s, f[:n]) {
				cut = n
				break
			}
		}
	}
	if cut == 0 {
		return s
	}
	return s[:len(s)-cut] + "***"
}

// MaskJSON returns the JSON document doc with secret values masked in its
// string values. Masking works on the decoded strings, so it cannot break
// an escape sequence; object keys are left alone, so the structure stays
// intact.
func (m *Masker) MaskJSON(doc []byte) []byte {
	if m == nil {
		return doc
	}
	var out []byte
	for i := 0; i < len(doc); {
		if doc[i] != '"' {
			out = append(out, doc[i])
			i++
			continue
		}
		j := i + 1
		for j < len(doc) && doc[j] != '"' {
			if doc[j] == '\\' {
				j++
			}
			j++
		}
		j = min(j+1, len(doc)) // just past the closing quote
		tok := doc[i:j]
		rest := bytes.TrimLeft(doc[j:], " \t\r\n")
		var s string
		if (len(rest) == 0 || rest[0] != ':') && json.Unmarshal(tok, &s) == nil {
			if masked := m.r.Replace(s); masked != s {
				tok = []byte(`"` + jsonString(masked, false) + `"`)
			}
		}
		out = append(out, tok...)
		i = j
	}
	return out
}
