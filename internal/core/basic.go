package core

import "strings"

// BasicAuth returns the user and the password of h if it is an
// Authorization header written in the shortcut of JetBrains, REST Client
// and httpyac: Basic, then a user and a password, a word each, such as
// "Basic {{user}} {{password}}". It goes on the wire as Basic and the
// base64 of user:password (RFC 7617). Words are split at the spaces and
// tabs of the literal text: a secret's value may hold one. "Basic" and
// one word, the encoded form, is no shortcut.
func BasicAuth(h PreparedHeader) (user, password Text, ok bool) {
	if !strings.EqualFold(h.Name, "Authorization") {
		return nil, nil, false
	}
	w := words(h.Value)
	if len(w) != 3 || len(w[0]) != 1 || w[0][0].Secret != nil || !strings.EqualFold(w[0][0].Text, "Basic") {
		return nil, nil, false
	}
	return w[1], w[2], true
}

// words splits t at the runs of spaces and tabs of its literal text.
func words(t Text) []Text {
	var out []Text
	var cur Text
	end := func() {
		if cur != nil {
			out, cur = append(out, cur), nil
		}
	}
	for _, seg := range t {
		if seg.Secret != nil {
			cur = append(cur, seg)
			continue
		}
		s := seg.Text
		for s != "" {
			i := strings.IndexAny(s, " \t")
			if i < 0 {
				cur = append(cur, Segment{Text: s})
				break
			}
			if i > 0 {
				cur = append(cur, Segment{Text: s[:i]})
			}
			end()
			s = s[i+1:]
		}
	}
	end()
	return out
}
