package core

import (
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestOrigin checks that the origins vegtam compares are written one way:
// without the scheme's own port, in lower case, without a final dot, and
// an IPv6 address in its shortest form.
func TestOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.example.com":                    "https://api.example.com",
		"https://api.example.com:443/v1?q=1#top":     "https://api.example.com",
		"http://api.example.com:80/":                 "http://api.example.com",
		"http://api.example.com:443":                 "http://api.example.com:443", // the other scheme's port is no default
		"https://api.example.com:80":                 "https://api.example.com:80",
		"https://api.example.com:8443":               "https://api.example.com:8443",
		"HTTPS://API.Example.COM./":                  "https://api.example.com",
		"https://me:pa55@api.example.com/":           "https://api.example.com",
		"http://127.0.0.1:8080/x":                    "http://127.0.0.1:8080",
		"https://[2001:DB8::1]:443/":                 "https://[2001:db8::1]",
		"https://[2001:db8:0:0:0:0:0:1]:8443":        "https://[2001:db8::1]:8443",
		"http://[::1]:80":                            "http://[::1]",
		"http://[::ffff:127.0.0.1]:8080":             "http://127.0.0.1:8080", // the IPv4 address it maps, which a connection goes to
		"http://[::FFFF:7f00:1]:8080":                "http://127.0.0.1:8080",
		"http://[::127.0.0.1]:8080":                  "http://[::7f00:1]:8080",        // compatible, not mapped: another address
		"http://[64:ff9b::127.0.0.1]:8080":           "http://[64:ff9b::7f00:1]:8080", // NAT64: another address
		"https://api.example.com:00443":              "https://api.example.com:00443",
		"https://xn--bcher-kva.example":              "https://xn--bcher-kva.example",
		"https://api.example.com.:443/?next=https:/": "https://api.example.com",
	} {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := Origin(u); got != want {
			t.Errorf("Origin(%s) = %s, want %s", in, got, want)
		}
	}
	// Distinct servers stay distinct.
	seen := map[string]string{}
	for _, in := range []string{
		"https://api.example.com", "http://api.example.com", "https://api.example.com:8443", "https://api.example.com.evil.example",
		"https://127.0.0.1", "https://[::1]", "https://[::7f00:1]", "https://[64:ff9b::7f00:1]", "https://api-example.com",
	} {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		o := Origin(u)
		if other, ok := seen[o]; ok {
			t.Errorf("%s and %s are both %s", in, other, o)
		}
		seen[o] = in
	}
}

func TestParseOrigin(t *testing.T) {
	ok := map[string]string{
		"https://api.example.com":        "https://api.example.com",
		"https://api.example.com/":       "https://api.example.com",
		"https://api.example.com:443":    "https://api.example.com",
		"https://API.example.com.:443/":  "https://api.example.com",
		"https://auth.example.com:8443":  "https://auth.example.com:8443",
		"http://127.0.0.1:8080":          "http://127.0.0.1:8080",
		"http://127.0.0.1:8080/":         "http://127.0.0.1:8080",
		"http://localhost:3000":          "http://localhost:3000",
		"HTTP://LOCALHOST":               "http://localhost",
		"http://[::1]:8080":              "http://[::1]:8080",
		"https://[2001:DB8::1]":          "https://[2001:db8::1]",
		"http://[::ffff:127.0.0.1]:8080": "http://127.0.0.1:8080",
		"https://api.example.com:65535":  "https://api.example.com:65535",
		"https://a_b.example":            "https://a_b.example",
	}
	for in, want := range ok {
		if got, err := ParseOrigin(in); err != nil || got != want {
			t.Errorf("ParseOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	wildcard := "a secret goes to origins named one by one; a wildcard names none"
	for in, want := range map[string]string{
		"":                                "want an origin",
		"*":                               "want an origin",
		"api.example.com":                 "want an origin",
		"//api.example.com":               "want an origin",
		"api.example.com:443":             "want an origin",
		"https:api.example.com":           "want an origin",
		"https://":                        "want an origin",
		"https:///":                       "want an origin",
		"ftp://api.example.com":           "want an origin",
		"ws://api.example.com":            "want an origin",
		"https://*.example.com":           wildcard,
		"https://*":                       wildcard,
		"https://api.*":                   wildcard,
		"https://api.example.com/v1":      "want an origin",
		"https://api.example.com//":       "want an origin",
		"https://api.example.com/%2F":     "want an origin",
		"https://api.example.com?":        "want an origin",
		"https://api.example.com/?q=1":    "want an origin",
		"https://api.example.com#top":     "want an origin",
		"https://api.example.com#":        "want an origin",
		"http://..":                       "want an origin",
		"http://.api.example.com":         "want an origin",
		"http://api..example.com":         "want an origin",
		"http://api.example.com..":        "want an origin",
		"https://api.example.com/#":       "want an origin",
		"https://me@api.example.com":      "want an origin",
		"https://me:pa55@api.example.com": "want an origin",
		"https://@api.example.com":        "want an origin",
		"https://api.example.com:0":       "want an origin",
		"https://api.example.com:":        "want an origin",
		"https://api.example.com:65536":   "want an origin",
		"https://api.example.com:+443":    "want an origin",
		"https://api.example.com:x":       "want an origin",
		"https://[::1":                    "want an origin",
		"https://[fe80::1%25eth0]":        "want an origin",
		"https://b\u00fccher.example":     "want an origin",
		"https://api%2Eexample.com":       "want an origin",
		"https://api example.com":         "want an origin",
		"https://.":                       "want an origin",
		" https://api.example.com":        "want an origin",
	} {
		got, err := ParseOrigin(in)
		if err == nil || got != "" || !strings.HasPrefix(err.Error(), strconv.Quote(in)+": ") || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseOrigin(%q) = %q, %v; want an error with %q", in, got, err, want)
		}
	}
	if _, err := ParseOrigin("x"); err == nil || err.Error() != `"x": want an origin, such as https://api.example.com or http://127.0.0.1:8080` {
		t.Errorf("the error: %v", err)
	}
}

// lateSecrets are those of secretMap, but for the names in late, whose
// values are known only when the request is sent, as in a dry run.
type lateSecrets struct {
	secretMap
	late []string
}

func (s lateSecrets) SecretValue(sec Secret) (string, error) {
	if slices.Contains(s.late, sec.Name) {
		return "", ErrLate
	}
	return s.secretMap.SecretValue(sec)
}

// TestTextOrigin checks the origin of a URL with secrets in it: known if
// every part of the scheme, host and port is, whatever comes after them.
func TestTextOrigin(t *testing.T) {
	src := lateSecrets{secretMap{"host": "API.example.com:443", "base": "https://api.example.com/v1", "token": "t0k"}, []string{"late"}}
	text := func(parts ...string) Text {
		var t Text
		for _, p := range parts {
			if name, ok := strings.CutPrefix(p, "$"); ok {
				t = append(t, Segment{Secret: &Secret{Name: name}})
			} else {
				t = append(t, Segment{Text: p})
			}
		}
		return t
	}
	tests := []struct {
		name string
		url  Text
		want string // "" if not known
	}{
		{"plain", text("https://api.example.com:443/x"), "https://api.example.com"},
		{"a secret host", text("https://", "$host", "/x?t=", "$token"), "https://api.example.com"},
		{"a secret base", text("$base", "/users"), "https://api.example.com"},
		{"late after the path began", text("https://api.example.com/?t=", "$late"), "https://api.example.com"},
		{"late after the query began", text("https://api.example.com?t=", "$late"), "https://api.example.com"},
		{"late after the fragment began", text("https://api.example.com#", "$late"), "https://api.example.com"},
		{"late after a secret host", text("https://", "$host", "/", "$late"), "https://api.example.com"},
		{"late in the host", text("https://", "$late", "/x"), ""},
		{"late in the host, after a part", text("https://api.", "$late", "/x"), ""},
		{"late in the port", text("https://api.example.com:", "$late", "/x"), ""},
		{"late after the host, nothing between", text("https://api.example.com", "$late"), ""},
		{"late in the user", text("https://me:", "$late", "@api.example.com/"), ""},
		{"late in the scheme", text("$late", "://api.example.com/"), ""},
		{"late with no scheme yet", text("http", "$late", "/x"), ""},
		{"not a URL", text("https://[::1/x"), ""},
		{"not http", text("ftp://api.example.com/x"), ""},
		{"no host", text("https:///x"), ""},
		{"relative", text("/x"), ""},
	}
	for _, tt := range tests {
		got, ok, err := tt.url.Origin(src)
		if err != nil || got != tt.want || ok != (tt.want != "") {
			t.Errorf("%s: Origin = %q, %v, %v; want %q", tt.name, got, ok, err, tt.want)
		}
	}
	// A secret that has no value is an error.
	if _, _, err := text("https://", "$missing", "/").Origin(src); err == nil || errors.Is(err, ErrLate) {
		t.Errorf("a secret without a value: %v", err)
	}
}
