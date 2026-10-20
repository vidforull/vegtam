package netguard

import (
	"strings"
	"testing"
)

func TestParseRoutes(t *testing.T) {
	for in, want := range map[string]string{
		"api.example:443:127.0.0.1":                "api.example:443:127.0.0.1",
		"API.Example.:443:10.0.0.1,10.0.0.2":       "api.example:443:10.0.0.1,10.0.0.2",
		"api.example:8443:[::1],127.0.0.1":         "api.example:8443:[::1],127.0.0.1",
		"api.example:443:::1":                      "api.example:443:[::1]",
		"api.example:443:::ffff:127.0.0.1":         "api.example:443:[::ffff:127.0.0.1]",
		"localhost:80:192.0.2.1,[2001:db8::1]":     "localhost:80:192.0.2.1,[2001:db8::1]",
		"a-b.example:65535:198.51.100.7":           "a-b.example:65535:198.51.100.7",
		"api.example:443:127.0.0.1,198.51.100.255": "api.example:443:127.0.0.1,198.51.100.255",
	} {
		r, err := ParseResolve(in)
		if err != nil || r.String() != want {
			t.Errorf("ParseResolve(%q) = %s, %v; want %s", in, r, err, want)
		}
	}
	for _, in := range []string{
		"", "api.example", "api.example:443", "api.example:443:", "api.example:0:127.0.0.1", "api.example:443:nowhere",
		"api.example:https:127.0.0.1", ":443:127.0.0.1", "api.example:443:[fe80::1%eth0]", "api example:443:127.0.0.1",
		"api.example:0443:127.0.0.1",
	} {
		if _, err := ParseResolve(in); err == nil || !strings.Contains(err.Error(), "want host:port:address") {
			t.Errorf("ParseResolve(%q) = %v; want an error", in, err)
		}
	}
	for in, want := range map[string]string{
		"api.example:443:staging.example:8443": "api.example:443:staging.example:8443",
		"API.example:443:127.0.0.1:":           "api.example:443:127.0.0.1:",
		"::[::1]:8080":                         "::[::1]:8080",
		"[::1]:443:localhost:":                 "[::1]:443:localhost:",
		":::":                                  ":::",
	} {
		c, err := ParseConnectTo(in)
		if err != nil || c.String() != want {
			t.Errorf("ParseConnectTo(%q) = %s, %v; want %s", in, c, err, want)
		}
	}
	for _, in := range []string{"", "a:1:b", "a:1:b:2:3", "a:x:b:2", "a:1:b:0", "a:1:[b:2", "a b:1:c:2", "a:1:b]:2"} {
		if _, err := ParseConnectTo(in); err == nil {
			t.Errorf("ParseConnectTo(%q): want an error", in)
		}
	}
}

func TestRoute(t *testing.T) {
	var r Routes
	for _, s := range []string{"api.example:443:127.0.0.1,[::1]", "staging.example:8443:10.0.0.9"} {
		res, err := ParseResolve(s)
		if err != nil {
			t.Fatal(err)
		}
		r.Resolve = append(r.Resolve, res)
	}
	for _, s := range []string{"old.example:443:staging.example:8443", ":8080::9090", "[::1]:80:localhost:"} {
		c, err := ParseConnectTo(s)
		if err != nil {
			t.Fatal(err)
		}
		r.ConnectTo = append(r.ConnectTo, c)
	}
	for _, tt := range []struct {
		host, port, to, addrs, by string
	}{
		{"api.example", "443", "api.example", "127.0.0.1:443 [::1]:443", "--resolve"},
		{"API.EXAMPLE.", "443", "API.EXAMPLE.", "127.0.0.1:443 [::1]:443", "--resolve"},
		{"api.example", "80", "api.example", "api.example:80", ""},
		{"old.example", "443", "staging.example", "10.0.0.9:8443", "--resolve"}, // --connect-to, then --resolve
		{"any.example", "8080", "any.example", "any.example:9090", "--connect-to"},
		{"::1", "80", "localhost", "localhost:80", "--connect-to"},
		{"other.example", "443", "other.example", "other.example:443", ""},
	} {
		to, addrs, by := r.Route(tt.host, tt.port)
		if to != tt.to || strings.Join(addrs, " ") != tt.addrs || by != tt.by {
			t.Errorf("Route(%s, %s) = %s, %q, %q; want %s, %q, %q", tt.host, tt.port, to, addrs, by, tt.to, tt.addrs, tt.by)
		}
	}
}
