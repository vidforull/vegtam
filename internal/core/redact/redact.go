// Package redact hides what commonly carries credentials in a response,
// for a run without a person at a terminal: a script or an agent gets a
// result it may log, store or pass on without passing on a credential
// that vegtam does not know as a secret. Masking (core.Masker) hides the
// values vegtam knows; redaction hides by place and by shape: the headers
// and JSON keys that name credentials, and tokens shaped as JWTs wherever
// they stand.
//
// Redaction replaces a value with ***, and each function says what it
// replaced, so that the output can say so. A value that is *** already is
// left alone: redacting twice gives what redacting once does.
package redact

import (
	"net/url"
	"slices"
	"strings"
	"unicode"
)

// headers are the response headers whose value is never shown.
var headers = []string{"Set-Cookie", "Authorization", "Proxy-Authorization", "WWW-Authenticate"}

// keys are the JSON keys whose value is never shown, as Key normalises
// them: token, access_token, refresh_token, id_token, secret,
// client_secret, password, passwd, api_key, apikey, session, sessionid,
// cookie, authorization and private_key.
var keys = map[string]bool{
	"token": true, "accesstoken": true, "refreshtoken": true, "idtoken": true,
	"secret": true, "clientsecret": true, "password": true, "passwd": true,
	"apikey": true, "session": true, "sessionid": true, "cookie": true,
	"authorization": true, "privatekey": true,
}

// minSegment is the length a segment of a JWT-shaped token has at least.
const minSegment = 10

// Header reports whether the value of the response header name is never
// shown: it sets a cookie, carries credentials or asks for them; or, less
// an X- in front, it is named as Key names a credential, as X-Session or
// X-Api-Key are.
func Header(name string) bool {
	if len(name) > 2 && strings.EqualFold(name[:2], "x-") && Key(name[2:]) {
		return true
	}
	return slices.ContainsFunc(headers, func(h string) bool { return strings.EqualFold(h, name) })
}

// Key reports whether the value of a JSON object member with the key k is
// never shown. Case, '-' and '_' do not matter: access_token,
// Access-Token, accessToken and ACCESS_TOKEN are one key.
func Key(k string) bool {
	return keys[strings.Map(func(r rune) rune {
		if r == '-' || r == '_' {
			return -1
		}
		return unicode.ToLower(r)
	}, k)]
}

// JWT reports whether s is a token shaped as a JWT in compact form: three
// segments of at least ten characters of the base64url alphabet, joined by
// dots. Many tokens that are not JWTs share the shape, and are credentials
// all the same.
func JWT(s string) bool {
	dots, n := 0, 0
	for i := range len(s) {
		switch c := s[i]; {
		case c == '.':
			if n < minSegment {
				return false
			}
			dots, n = dots+1, 0
		case base64url(c):
			n++
		default:
			return false
		}
	}
	return dots == 2 && n >= minSegment
}

// base64url reports whether c is of the base64url alphabet.
func base64url(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// wordByte reports whether c may be part of a word that Text looks at: a
// JWT-shaped token is one only between bytes that may not.
func wordByte(c byte) bool { return base64url(c) || c == '.' }

// Text returns s with each JWT-shaped token that stands as a word replaced
// with ***, and whether there was one. A word runs between the start or
// end of s and bytes that cannot be part of a token: not letters, digits,
// '-', '_' or '.'. Dots at either end of a word are not part of it: a
// sentence may end after a token.
func Text(s string) (string, bool) {
	var b strings.Builder
	done := 0 // s[:done] is in b
	for i := 0; i < len(s); {
		if !wordByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && wordByte(s[j]) {
			j++
		}
		start, end := i, j
		for start < end && s[start] == '.' {
			start++
		}
		for end > start && s[end-1] == '.' {
			end--
		}
		if JWT(s[start:end]) {
			b.WriteString(s[done:start])
			b.WriteString("***")
			done = end
		}
		i = j
	}
	if done == 0 {
		return s, false
	}
	b.WriteString(s[done:])
	return b.String(), true
}

// Form returns the form-encoded text s (application/x-www-form-urlencoded)
// with the value of each field replaced with *** whose name, decoded, is
// one that Key names, or whose value, decoded, holds a JWT-shaped token
// (Text); and the names of the fields replaced, decoded, each once. The
// rest of s is left as it was. A field without a value holds nothing, and
// is left alone.
func Form(s string) (string, []string) {
	fields := strings.Split(s, "&")
	var names []string
	seen := map[string]bool{}
	for i, f := range fields {
		name, value, ok := strings.Cut(f, "=")
		v := strings.TrimRight(value, " \t\r\n") // the line break at the end of a body
		if !ok || v == "" || unescape(v) == "***" {
			continue
		}
		n := unescape(name)
		if _, jwt := Text(unescape(v)); !jwt && !Key(n) {
			continue
		}
		fields[i] = name + "=***" + value[len(v):]
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return strings.Join(fields, "&"), names
}

// unescape returns s decoded as a part of a form or a query, or s itself
// if it does not decode.
func unescape(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

// URL returns the URL s, such as the Location of a redirect, with the
// parameters of its query, and those of its fragment (#name=value&...),
// replaced with *** as Form replaces them, and their names, each once: the
// implicit flow of OAuth 2.0 hands out an access_token in the fragment. A
// URL that does not parse is returned as it is.
func URL(s string) (string, []string) {
	if _, err := url.Parse(s); err != nil {
		return s, nil
	}
	rest, fragment, hasFragment := strings.Cut(s, "#")
	base, query, hasQuery := strings.Cut(rest, "?")
	var names []string
	seen := map[string]bool{}
	add := func(list []string) {
		for _, n := range list {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	var found []string
	if hasQuery {
		query, found = Form(query)
		add(found)
		base += "?" + query
	}
	if hasFragment {
		fragment, found = Form(fragment)
		add(found)
		base += "#" + fragment
	}
	return base, names
}
