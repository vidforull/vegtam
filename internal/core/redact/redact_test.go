package redact

import (
	"slices"
	"strings"
	"testing"
)

// jwt is shaped as a JWT: its header and payload are base64url JSON, its
// signature made up.
const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlLWZha2U"

func TestHeader(t *testing.T) {
	for name, want := range map[string]bool{
		"Set-Cookie": true, "set-cookie": true, "AUTHORIZATION": true, "Proxy-Authorization": true,
		"WWW-Authenticate": true, "www-authenticate": true,
		"X-Session": true, "x-api-key": true, "X-Auth_Token": false, "X-Access-Token": true, "X-Cookie": true, "X-": false, "x-token": true,
		"Cookie": false, "Proxy-Authenticate": false, "X-Set-Cookie": false, "Content-Type": false, "": false, "Session": false,
	} {
		if got := Header(name); got != want {
			t.Errorf("Header(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestKey(t *testing.T) {
	for _, k := range []string{
		"token", "Token", "access_token", "Access-Token", "accessToken", "ACCESS_TOKEN", "access-token",
		"refresh_token", "refreshToken", "id_token", "idToken", "secret", "client_secret", "clientSecret",
		"password", "Password", "passwd", "api_key", "apiKey", "API-KEY", "apikey", "session", "sessionId",
		"session_id", "SESSIONID", "cookie", "Cookie", "authorization", "Authorization", "private_key",
		"privateKey", "_token_", "to-ken", "a_c_c_e_s_s_t_o_k_e_n",
	} {
		if !Key(k) {
			t.Errorf("Key(%q) = false, want true", k)
		}
	}
	for _, k := range []string{
		"", "tokens", "token_type", "expires_in", "auth_token", "csrf", "user", "secrets", "passwords",
		"key", "id", "to ken", "token.", "sessions", "cookies", "x-api-key", "access",
	} {
		if Key(k) {
			t.Errorf("Key(%q) = true, want false", k)
		}
	}
}

func TestJWT(t *testing.T) {
	for s, want := range map[string]bool{
		jwt:                                         true,
		"aaaaaaaaaa.bbbbbbbbbb.cccccccccc":          true,
		"a-_aaaaaaa.b-_bbbbbbb.c-_ccccccc":          true,
		"aaaaaaaaa.bbbbbbbbbb.cccccccccc":           false, // a segment of nine
		"aaaaaaaaaa.bbbbbbbbbb.ccccccccc":           false,
		"aaaaaaaaaa.bbbbbbbbbb":                     false,
		"aaaaaaaaaa.bbbbbbbbbb.cccccccccc.dddddddd": false,
		"aaaaaaaaaa..bbbbbbbbbb.cccccccccc":         false,
		"aaaaaaaaaa.bbbbbbbbbb.cccccccccc.":         false,
		".aaaaaaaaaa.bbbbbbbbbb.cccccccccc":         false,
		"aaaaaaaaaa.bbbbbbbbbb.ccccccccc=":          false,
		"aaaaaaaaaa.bbbb+bbbbb.cccccccccc":          false,
		" " + jwt:                                   false,
		jwt + "\n":                                  false,
		"":                                          false,
	} {
		if got := JWT(s); got != want {
			t.Errorf("JWT(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestText(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{jwt, "***"},
		{"Bearer " + jwt, "Bearer ***"},
		{"token: " + jwt + ".", "token: ***."},
		{"(" + jwt + ")\n" + jwt, "(***)\n***"},
		{"https://app.example/cb#access_token=" + jwt + "&state=x", "https://app.example/cb#access_token=***&state=x"},
		{`{"t":"` + jwt + `"}`, `{"t":"***"}`},
		{"..." + jwt + "...", "...***..."},
		// Not a word of its own.
		{"x." + jwt, "x." + jwt},
		{jwt + ".x", jwt + ".x"},
		{"aaaaaaaaaa.bbbbbbbbbb", "aaaaaaaaaa.bbbbbbbbbb"},
		{"plain text", "plain text"},
		{"", ""},
		{"***", "***"},
	} {
		got, changed := Text(tt.in)
		if got != tt.want || changed != (tt.in != tt.want) {
			t.Errorf("Text(%q) = %q, %v; want %q", tt.in, got, changed, tt.want)
		}
		if again, changed := Text(got); again != got || changed {
			t.Errorf("Text(%q) = %q, %v; want it unchanged", got, again, changed)
		}
	}
}

func TestForm(t *testing.T) {
	for _, tt := range []struct {
		in, want string
		names    []string
	}{
		{"access_token=abc&token_type=bearer&expires_in=3600", "access_token=***&token_type=bearer&expires_in=3600", []string{"access_token"}},
		{"Access-Token=a+b&accessToken=%2F&ACCESS_TOKEN=x", "Access-Token=***&accessToken=***&ACCESS_TOKEN=***", []string{"Access-Token", "accessToken", "ACCESS_TOKEN"}},
		{"%74oken=x&token=y", "%74oken=***&token=***", []string{"token"}},
		{"id=1&jwt=" + jwt, "id=1&jwt=***", []string{"jwt"}},
		{"next=https%3A%2F%2Fx.example%2F%23t%3D" + jwt, "next=***", []string{"next"}},
		{"token=&password&secret=***", "token=&password&secret=***", nil},
		{"password=hunter2\n", "password=***\n", []string{"password"}},
		{"a=1&b=%zz&password=%zz", "a=1&b=%zz&password=***", []string{"password"}},
		{"", "", nil},
		{"plain", "plain", nil},
	} {
		got, names := Form(tt.in)
		if got != tt.want || !slices.Equal(names, tt.names) {
			t.Errorf("Form(%q) = %q, %q; want %q, %q", tt.in, got, names, tt.want, tt.names)
		}
		if again, names := Form(got); again != got || names != nil {
			t.Errorf("Form(%q) = %q, %q; want it unchanged", got, again, names)
		}
	}
}

func TestURL(t *testing.T) {
	for _, tt := range []struct {
		in, want string
		names    []string
	}{
		{"https://app.example/cb?code=abc&state=xyz", "https://app.example/cb?code=abc&state=xyz", nil},
		{
			"https://app.example/cb#access_token=abc&token_type=bearer&id_token=" + jwt,
			"https://app.example/cb#access_token=***&token_type=bearer&id_token=***",
			[]string{"access_token", "id_token"},
		},
		{"/login?next=%2F&session=s1#session=s2", "/login?next=%2F&session=***#session=***", []string{"session"}},
		{"https://x.example/?t=" + jwt + "&q=a?b", "https://x.example/?t=***&q=a?b", []string{"t"}},
		{"https://x.example/#section-2", "https://x.example/#section-2", nil},
		{"https://x.example/?#", "https://x.example/?#", nil},
		// Does not parse: as it is.
		{"https://x.example/\x7f?token=abc", "https://x.example/\x7f?token=abc", nil},
		{"https://x.example:port/?token=abc", "https://x.example:port/?token=abc", nil},
	} {
		got, names := URL(tt.in)
		if got != tt.want || !slices.Equal(names, tt.names) {
			t.Errorf("URL(%q) = %q, %q; want %q, %q", tt.in, got, names, tt.want, tt.names)
		}
		if again, names := URL(got); again != got || names != nil {
			t.Errorf("URL(%q) = %q, %q; want it unchanged", got, again, names)
		}
	}
}

// TestTextLong checks that Text finds a token among much text, at either
// end and in the middle.
func TestTextLong(t *testing.T) {
	filler := strings.Repeat("lorem ipsum. ", 1000)
	in := jwt + " " + filler + jwt + " " + filler + jwt
	got, changed := Text(in)
	if want := "*** " + filler + "*** " + filler + "***"; got != want || !changed {
		t.Errorf("Text of %d bytes: %d tokens left", len(in), strings.Count(got, jwt))
	}
}
