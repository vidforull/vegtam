package core

import "strings"

// BasicAuth returns the user and the password of h if it is an
// Authorization header written in the shortcut of JetBrains, REST Client
// and httpyac: Basic, then a user and a password, a word each, such as
// "Basic {{user}} {{password}}", or one word with a colon between them,
// such as "Basic {{user}}:{{password}}". It goes on the wire as Basic and
// the base64 of user:password (RFC 7617). Words are split at the spaces
// and tabs of the literal text, and one word at the first colon of its
// literal text: a secret's value may hold either. "Basic" and one word
// without such a colon is the encoded form, which base64 writes without
// one, and no shortcut.
func BasicAuth(h PreparedHeader) (user, password Text, ok bool) {
	if !strings.EqualFold(h.Name, "Authorization") {
		return nil, nil, false
	}
	w := words(h.Value)
	if len(w) < 2 || len(w[0]) != 1 || w[0][0].Secret != nil || !strings.EqualFold(w[0][0].Text, "Basic") {
		return nil, nil, false
	}
	switch len(w) {
	case 2:
		return cutColon(w[1])
	case 3:
		return w[1], w[2], true
	}
	return nil, nil, false
}

// cutColon splits t at the first colon of its literal text.
func cutColon(t Text) (before, after Text, found bool) {
	for i, seg := range t {
		if seg.Secret != nil {
			continue
		}
		b, a, ok := strings.Cut(seg.Text, ":")
		if !ok {
			continue
		}
		before = append(before, t[:i]...)
		if b != "" {
			before = append(before, Segment{Text: b})
		}
		if a != "" {
			after = append(after, Segment{Text: a})
		}
		return before, append(after, t[i+1:]...), true
	}
	return nil, nil, false
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
