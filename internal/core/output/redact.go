package output

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/vidforull/vegtam/internal/core/redact"
)

// Redact makes r sterile, for a run without a person at a terminal: what
// commonly carries credentials in a response is replaced with ***, though
// vegtam does not know it as a secret, and Redacted says where, each place
// once. Redacting r again changes nothing. A person's run is not
// redacted.
//
// It replaces, with redact:
//
//   - the values of the response headers that redact.Header names; the
//     query and fragment parameters of a Location (redact.URL); and the
//     JWT-shaped tokens in any header (redact.Text): "header <Name>";
//   - in a text body, by what it is: JSON, as redact.JSON does, by path,
//     such as "$.access_token"; a form (application/x-www-form-urlencoded),
//     as redact.Form does, "form <name>"; other text, as redact.Text does,
//     "body";
//   - the actual value of an assertion that checks a header redact.Header
//     names, or a JSON path through a key redact.Key names, whole; that of
//     any other, as a body of its kind (JSON, the form of a body
//     assertion, or text): "assert <expression>";
//   - the Location of each redirect, as that of a response:
//     "redirect <n> location".
func (r *Result) Redact() {
	if r == nil {
		return
	}
	seen := map[string]bool{}
	for _, e := range r.Redacted {
		seen[e] = true
	}
	add := func(e string) {
		if !seen[e] {
			seen[e] = true
			r.Redacted = append(r.Redacted, e)
		}
	}
	form := false
	if resp := r.Response; resp != nil {
		for i := range resp.Headers {
			h := &resp.Headers[i]
			if v := redactHeader(h.Name, h.Value); v != h.Value {
				h.Value = v
				add("header " + h.Name)
			}
			form = form || isForm(*h)
		}
		redactBody(resp, form, add)
	}
	for i := range r.Asserts {
		a := &r.Asserts[i]
		if v := redactActual(a.Expression, a.Actual, form); v != a.Actual {
			a.Actual = v
			add("assert " + a.Expression)
		}
	}
	for i := range r.Redirects {
		l := &r.Redirects[i].Location
		if v := location(*l); v != *l {
			*l = v
			add("redirect " + strconv.Itoa(i+1) + " location")
		}
	}
}

// redactHeader returns the value v of the response header name, redacted.
func redactHeader(name, v string) string {
	switch {
	case v == "":
		return v
	case redact.Header(name):
		return "***"
	case strings.EqualFold(name, "Location"):
		return location(v)
	}
	v, _ = redact.Text(v)
	return v
}

// location returns the URL of a Location header redacted: its parameters,
// and the JWT-shaped tokens anywhere in it, such as in its path.
func location(v string) string {
	v, _ = redact.URL(v)
	v, _ = redact.Text(v)
	return v
}

// isForm reports whether h says that the body is a form.
func isForm(h Header) bool {
	media, _, _ := strings.Cut(h.Value, ";")
	return strings.EqualFold(h.Name, "Content-Type") && strings.EqualFold(strings.TrimSpace(media), "application/x-www-form-urlencoded")
}

// redactBody redacts the body of resp, if it is text, as JSON, as a form
// if form is set, or as text, and adds where.
func redactBody(resp *Response, form bool, add func(string)) {
	if resp.Encoding != "" || resp.Body == "" {
		return
	}
	switch {
	case looksJSON(resp.Body):
		out, paths := redact.JSON([]byte(resp.Body))
		resp.Body = string(out)
		for _, p := range paths {
			add(p)
		}
	case form:
		var names []string
		resp.Body, names = redact.Form(resp.Body)
		for _, n := range names {
			add("form " + n)
		}
	default:
		var changed bool
		if resp.Body, changed = redact.Text(resp.Body); changed {
			add("body")
		}
	}
}

// redactActual returns the actual value of the assertion expr redacted;
// form says that the body is a form.
func redactActual(expr, actual string, form bool) string {
	subject, rest := splitWord(expr)
	switch {
	case secretPlace(subject, rest):
		if noValue(actual) {
			return actual
		}
		return "***"
	case looksJSON(actual) || strings.HasPrefix(strings.TrimSpace(actual), `"`):
		out, _ := redact.JSON([]byte(actual))
		return string(out)
	case form && subject == "body":
		actual, _ = redact.Form(actual)
		return actual
	}
	actual, _ = redact.Text(actual)
	return actual
}

// secretPlace reports whether an assertion, its subject and the rest,
// checks a value that is never shown: a header that redact.Header names,
// or a JSON path through a key that redact.Key names, as the body hides
// the whole value of such a key. A path that ends in |length checks a
// count, which is shown.
func secretPlace(subject, rest string) bool {
	place, _ := splitWord(rest)
	switch subject {
	case "header":
		return redact.Header(place)
	case "jsonpath":
		return !strings.HasSuffix(place, "|length") && pathThroughKey(place)
	}
	return false
}

// pathThroughKey reports whether the JSON path p, as an assertion writes
// it, such as $.data.access_token, $.data["access-token"] or
// $.data."token", goes through a key that redact.Key names.
func pathThroughKey(p string) bool {
	for i := min(1, len(p)); i < len(p); {
		var key string
		switch {
		case p[i] == '.' && i+1 < len(p) && p[i+1] == '[':
			i++
			continue
		case p[i] == '.' && i+1 < len(p) && p[i+1] == '"', p[i] == '[' && i+1 < len(p) && p[i+1] == '"':
			key, i = quotedKey(p, i+1)
		case p[i] == '.':
			j := i + 1
			for j < len(p) && (p[j] == '_' || 'a' <= p[j] && p[j] <= 'z' || 'A' <= p[j] && p[j] <= 'Z' || '0' <= p[j] && p[j] <= '9') {
				j++
			}
			key, i = p[i+1:j], j
		default: // an index, or the end of a bracket
			i++
		}
		if redact.Key(key) {
			return true
		}
	}
	return false
}

// quotedKey returns the key quoted at p[i], its escapes decoded as gojq
// decodes them, and the index just past it.
func quotedKey(p string, i int) (string, int) {
	j := i + 1
	for j < len(p) && p[j] != '"' {
		if p[j] == '\\' {
			j++
		}
		j++
	}
	j = min(j+1, len(p))
	var key string
	if json.Unmarshal([]byte(p[i:j]), &key) != nil {
		key = strings.Trim(p[i:j], `"`)
	}
	return key, j
}

// noValue reports whether actual holds nothing to hide: an empty value, a
// JSON null or "", or why there is no value, in parentheses.
func noValue(actual string) bool {
	return actual == "" || actual == "null" || actual == `""` ||
		strings.HasPrefix(actual, "(") && strings.HasSuffix(actual, ")")
}

// looksJSON reports whether s starts as a JSON object or array does,
// after spaces and a byte order mark.
func looksJSON(s string) bool {
	s = strings.TrimLeft(strings.TrimPrefix(s, "\uFEFF"), " \t\r\n")
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

// splitWord splits s at its first run of spaces or tabs, as the
// assertions are split.
func splitWord(s string) (word, rest string) {
	s = strings.TrimSpace(s)
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i:])
}

// Credential reports whether value, which the @capture source src takes,
// is a credential that a response hands out: from a header or a JSON
// member that Redact hides, a JSON value that holds one, or a JWT. A run
// without a person takes it as a secret, whatever the directive says, as
// it is not shown it.
func Credential(src, value string) bool {
	subject, rest := splitWord(src)
	switch {
	case subject == "header" && redact.Header(strings.TrimSpace(rest)):
		return true
	case strings.HasPrefix(src, "$") && !strings.HasSuffix(src, "|length") && pathThroughKey(src):
		return true
	}
	if json.Valid([]byte(value)) {
		if _, paths := redact.JSON([]byte(value)); len(paths) > 0 {
			return true
		}
	}
	_, changed := redact.Text(value)
	return changed
}
