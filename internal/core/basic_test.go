package core

import "testing"

func TestBasicAuth(t *testing.T) {
	sec := func(name string) Segment { return Segment{Secret: &Secret{Name: name}} }
	for _, tt := range []struct {
		name           string
		header         PreparedHeader
		user, password string // masked; both "" if no shortcut
	}{
		{"placeholders", PreparedHeader{"Authorization", Text{{Text: "Basic "}, sec("user"), {Text: " "}, sec("password")}}, "{{user}}", "{{password}}"},
		{"literal user", PreparedHeader{"authorization", Text{{Text: "basic  alice\t"}, sec("password")}}, "alice", "{{password}}"},
		{"words around secrets", PreparedHeader{"Authorization", Text{{Text: "Basic a-"}, sec("u"), {Text: " p-"}, sec("p"), {Text: "!"}}}, "a-{{u}}", "p-{{p}}!"},
		{"literal both", PreparedHeader{"Authorization", Text{{Text: "Basic alice s3cret"}}}, "alice", "s3cret"},
		{"encoded already", PreparedHeader{"Authorization", Text{{Text: "Basic YWxpY2U6czNjcmV0"}}}, "", ""},
		{"a secret, encoded", PreparedHeader{"Authorization", Text{{Text: "Basic "}, sec("creds")}}, "", ""},
		{"three words", PreparedHeader{"Authorization", Text{{Text: "Basic a b c"}}}, "", ""},
		{"Bearer", PreparedHeader{"Authorization", Text{{Text: "Bearer "}, sec("t"), {Text: " x"}}}, "", ""},
		{"another header", PreparedHeader{"X-Auth", Text{{Text: "Basic alice s3cret"}}}, "", ""},
		{"the scheme from a secret", PreparedHeader{"Authorization", Text{sec("scheme"), {Text: " alice s3cret"}}}, "", ""},
		// One word, with a colon outside the placeholders: REST Client's and
		// httpyac's form.
		{"one word", PreparedHeader{"Authorization", Text{{Text: "Basic "}, sec("user"), {Text: ":"}, sec("password")}}, "{{user}}", "{{password}}"},
		{"one word, literal", PreparedHeader{"Authorization", Text{{Text: "Basic alice:s3cret:x"}}}, "alice", "s3cret:x"},
		{"one word around secrets", PreparedHeader{"Authorization", Text{{Text: "Basic a-"}, sec("u"), {Text: "-b:p-"}, sec("p"), {Text: "!"}}}, "a-{{u}}-b", "p-{{p}}!"},
		{"one word, empty password", PreparedHeader{"Authorization", Text{{Text: "Basic "}, sec("user"), {Text: ":"}}}, "{{user}}", ""},
		{"a colon in a secret only", PreparedHeader{"Authorization", Text{{Text: "Basic "}, sec("creds")}}, "", ""},
		{"one word, then another", PreparedHeader{"Authorization", Text{{Text: "Basic a:b c"}}}, "a:b", "c"},
	} {
		user, password, ok := BasicAuth(tt.header)
		if ok != (tt.user != "" || tt.password != "") || ok && (user.Masked() != tt.user || password.Masked() != tt.password) {
			t.Errorf("%s: %q, %q, %v; want %q, %q", tt.name, user.Masked(), password.Masked(), ok, tt.user, tt.password)
		}
	}
}
