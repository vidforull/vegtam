package core

import (
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
type Masker struct{ r *strings.Replacer }

// NewMasker returns a Masker that replaces each value, and its URL- and
// JSON-escaped forms, with "***".
func NewMasker(values []string) *Masker {
	var forms []string
	for _, v := range values {
		if v == "" {
			continue
		}
		j, _ := json.Marshal(v)
		forms = append(forms, v, url.QueryEscape(v), url.PathEscape(v), string(j[1:len(j)-1]))
	}
	// Longest first, so that a value is never half-masked because a
	// shorter one is part of it.
	slices.SortFunc(forms, func(a, b string) int { return cmp.Or(len(b)-len(a), strings.Compare(a, b)) })
	forms = slices.Compact(forms)
	var pairs []string
	for _, f := range forms {
		pairs = append(pairs, f, "***")
	}
	return &Masker{strings.NewReplacer(pairs...)}
}

// Mask returns s with every secret value replaced.
func (m *Masker) Mask(s string) string {
	if m == nil {
		return s
	}
	return m.r.Replace(s)
}
