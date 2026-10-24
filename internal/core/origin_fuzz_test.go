package core

import (
	"strings"
	"testing"
)

// FuzzParseOrigin checks that no string makes ParseOrigin panic, and that
// what it returns is an origin as Origin writes it: one that parses as
// itself, of http or https, with no wildcard, user, path, query or
// fragment.
func FuzzParseOrigin(f *testing.F) {
	for _, s := range []string{
		"https://api.example.com", "https://API.example.com.:443/", "http://127.0.0.1:8080", "http://[::1]:80",
		"https://[2001:DB8::1]:8443", "http://[::ffff:127.0.0.1]", "http://[64:ff9b::1.2.3.4]", "https://[fe80::1%25eth0]",
		"https://*.example.com", "*", "https://me@api.example.com", "https://api.example.com/v1?q#f", "https://api.example.com:0",
		"https://api.example.com:00443", "https://api.example.com:65536", "https://api.example.com/#", "ftp://x", "https:x", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		o, err := ParseOrigin(s)
		if err != nil {
			if o != "" {
				t.Errorf("ParseOrigin(%q) = %q and %v", s, o, err)
			}
			return
		}
		if again, err := ParseOrigin(o); err != nil || again != o {
			t.Errorf("ParseOrigin(%q) = %q, which parses as %q, %v", s, o, again, err)
		}
		rest, ok := strings.CutPrefix(o, "https://")
		if !ok {
			rest, ok = strings.CutPrefix(o, "http://")
		}
		if !ok || rest == "" || strings.ContainsAny(rest, "*@?#/") {
			t.Errorf("ParseOrigin(%q) = %q", s, o)
		}
	})
}
