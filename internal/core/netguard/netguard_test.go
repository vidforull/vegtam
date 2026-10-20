package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func entries(t *testing.T, list ...string) []Entry {
	t.Helper()
	var es []Entry
	for _, s := range list {
		e, err := ParseEntry(s)
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, e)
	}
	return es
}

// TestCheck is the table of addresses and modes: what is refused always,
// what without a person unless allowed, and what never.
func TestCheck(t *testing.T) {
	allow := entries(t, "127.0.0.1:8080", "localhost:3000", "10.0.0.0/8", "::1", "fd00:ec2::/32", "169.254.0.0/16")
	tests := []struct {
		host, addr string
		class      Class
		// The outcome: "" allowed, "never", or "private" when no person
		// is at a terminal.
		person, alone, allowed string
	}{
		{"", "93.184.216.34:443", Public, "", "", ""},
		{"", "[2606:4700::1]:443", Public, "", "", ""},
		{"", "169.254.169.254:80", Metadata, "never", "never", "never"},
		{"", "[::ffff:169.254.169.254]:80", Metadata, "never", "never", "never"},
		{"", "[64:ff9b::a9fe:a9fe]:80", Metadata, "never", "never", "never"},    // 169.254.169.254 behind NAT64
		{"", "[64:ff9b:1::a9fe:a9fe]:80", Metadata, "never", "never", "never"},  // the same, behind a local NAT64 under a /96 (RFC 8215)
		{"", "[64:ff9b:1::5db8:d822]:80", LocalNAT64, "", "private", "private"}, // 93.184.216.34 so, maybe
		{"", "[64:ff9b:1:abcd::a9fe:a9fe]:80", Metadata, "never", "never", "never"},
		{"", "169.254.170.23:80", Metadata, "never", "never", "never"},
		{"", "[fd00:ec2::23]:80", Metadata, "never", "never", "never"},
		{"", "[fd00:c1::a9fe:a9fe]:80", Metadata, "never", "never", "never"},
		{"", "192.0.0.192:80", Metadata, "never", "never", "never"},
		{"", "169.254.170.2:80", Metadata, "never", "never", "never"},
		{"", "[fd00:ec2::254]:80", Metadata, "never", "never", "never"},
		{"", "[fd20:ce::254]:80", Metadata, "never", "never", "never"},
		{"", "100.100.100.200:80", Metadata, "never", "never", "never"},
		{"", "168.63.129.16:80", Metadata, "never", "never", "never"},
		{"", "169.254.1.1:80", LinkLocal, "never", "never", "never"},
		{"", "[fe80::1%eth0]:80", LinkLocal, "never", "never", "never"},
		{"", "224.0.0.1:80", Multicast, "never", "never", "never"},
		{"", "[ff02::1]:80", Multicast, "never", "never", "never"},
		{"", "0.0.0.0:80", Unspecified, "never", "never", "never"},
		{"", "0.1.2.3:80", Unspecified, "never", "never", "never"},
		{"", "[::]:80", Unspecified, "never", "never", "never"},
		{"", "255.255.255.255:80", Unspecified, "never", "never", "never"},
		{"", "127.0.0.1:8080", Loopback, "", "private", ""},
		{"", "127.0.0.1:8081", Loopback, "", "private", "private"}, // another port
		{"", "127.0.0.2:8080", Loopback, "", "private", "private"},
		{"", "[::ffff:127.0.0.1]:8080", Loopback, "", "private", ""},
		{"", "[::1]:9", Loopback, "", "private", ""}, // an address without a port: any port
		{"localhost", "127.0.0.1:3000", Loopback, "", "private", ""},
		{"LOCALHOST.", "[::1]:3000", Loopback, "", "private", ""},
		{"localhost", "127.0.0.1:3001", Loopback, "", "private", "private"},
		{"api.localhost", "127.0.0.1:3000", Loopback, "", "private", "private"},
		{"", "10.1.2.3:443", Private, "", "private", ""},
		{"", "172.16.0.1:443", Private, "", "private", "private"},
		{"", "192.168.1.1:443", Private, "", "private", "private"},
		{"", "100.64.0.1:443", Shared, "", "private", "private"},
		{"", "100.127.255.254:443", Shared, "", "private", "private"},
		{"", "[fd12:3456::1]:443", UniqueLocal, "", "private", "private"},
		{"", "[fd00:ec2::1]:443", UniqueLocal, "", "private", ""},
	}
	for _, tt := range tests {
		ap := netip.MustParseAddrPort(tt.addr)
		if c, never := Classify(ap.Addr()); c != tt.class || never != (tt.person == "never") {
			t.Errorf("Classify(%s) = %q, %v; want %q", tt.addr, c, never, tt.class)
		}
		for _, mode := range []struct {
			name  string
			rules Rules
			want  string
		}{
			{"with a person", Rules{Allow: allow}, tt.person},
			{"alone", Rules{Unattended: true}, tt.alone},
			{"alone, allowed", Rules{Unattended: true, Allow: allow}, tt.allowed},
		} {
			err := mode.rules.Check(tt.host, ap)
			var got string
			if e, ok := errors.AsType[*Error](err); ok {
				got = map[bool]string{true: "never", false: "private"}[e.Never]
				if e.Class != tt.class || !strings.Contains(e.Error(), ap.String()) {
					t.Errorf("%s %s %s: %v; want the class %q", mode.name, tt.host, tt.addr, err, tt.class)
				}
			} else if err != nil {
				t.Errorf("%s %s %s: %v, not an *Error", mode.name, tt.host, tt.addr, err)
			}
			if got != mode.want {
				t.Errorf("%s %s %s: %v; want %q", mode.name, tt.host, tt.addr, err, mode.want)
			}
		}
	}
}

func TestErrorMessages(t *testing.T) {
	r := Rules{Unattended: true}
	for addr, want := range map[string]string{
		"127.0.0.1:8080":     "address 127.0.0.1:8080 is private (loopback), and no person is at a terminal; allow it in policy: network.allow",
		"169.254.169.254:80": "address 169.254.169.254:80 is a cloud metadata address, which vegtam never connects to: it hands out the credentials of the machine",
		"224.0.0.1:80":       "address 224.0.0.1:80 is multicast, which vegtam never connects to: it is no single host's",
	} {
		if err := r.Check("", netip.MustParseAddrPort(addr)); err == nil || err.Error() != want {
			t.Errorf("%s: %v; want %q", addr, err, want)
		}
	}
}

func TestParseEntry(t *testing.T) {
	for in, want := range map[string]string{
		"localhost:3000":   "host localhost port 3000",
		"API.Example.:443": "host api.example port 443",
		"127.0.0.1":        "prefix 127.0.0.1/32 port 0",
		"127.0.0.1:8080":   "prefix 127.0.0.1/32 port 8080",
		"[::1]:8080":       "prefix ::1/128 port 8080",
		"::1":              "prefix ::1/128 port 0",
		"10.1.2.3/8":       "prefix 10.0.0.0/8 port 0",
		"fd00::/8":         "prefix fd00::/8 port 0",
	} {
		e, err := ParseEntry(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		got := "host " + e.host
		if e.host == "" {
			got = "prefix " + e.prefix.String()
		}
		if got += " port " + strconv.Itoa(int(e.port)); got != want || e.String() != in {
			t.Errorf("%q = %s (%s); want %s", in, got, e, want)
		}
	}
	for in, want := range map[string]string{
		"localhost":        "name the port too, such as localhost:8080",
		"localhost:0":      "want host:port",
		"localhost:99999":  "want host:port",
		"localhost:http":   "want host:port",
		"127.0.0.1:0":      "want host:port",
		"10.0.0.0/33":      "want host:port",
		"exa mple:80":      "want host:port",
		"*.example.com:80": "want host:port",
		"":                 "want host:port",
		"http://x:80":      "want host:port",
	} {
		if _, err := ParseEntry(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v; want %q", in, err, want)
		}
	}
}

func TestLegacyIPv4(t *testing.T) {
	for in, want := range map[string]string{
		"2852039166":          "169.254.169.254",
		"0251.0376.0251.0376": "169.254.169.254",
		"169.254.43518":       "169.254.169.254",
		"0xa9.0xfe.0xa9fe":    "169.254.169.254",
		"0XA9FEA9FE":          "169.254.169.254",
		"127.1":               "127.0.0.1",
		"0":                   "0.0.0.0",
		"10.0.0.1":            "10.0.0.1",
		"0x":                  "0.0.0.0",          // WHATWG's reading
		"0169.0254.0169.0254": "169.254.169.254",  // decimal, leading zeros and all: not octal
		"010.1":               "8.0.0.1 10.0.0.1", // octal, and decimal
	} {
		var got []string
		for _, ip := range legacyIPv4(in) {
			got = append(got, ip.String())
		}
		if strings.Join(got, " ") != want {
			t.Errorf("legacyIPv4(%q) = %q; want %s", in, got, want)
		}
	}
	for _, in := range []string{"api.example", "1.2.3.4.5", "256.1.1.1", "1.16777216", "4294967296", "", "1..2", "1e3", "0xg"} {
		if ips := legacyIPv4(in); len(ips) != 0 {
			t.Errorf("legacyIPv4(%q) = %s; want no address", in, ips)
		}
	}
}

// slowResolver answers when its context is done.
type slowResolver struct{}

func (slowResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, &net.DNSError{Err: ctx.Err().Error(), Name: host, IsTimeout: true}
}

// resolver answers lookups from a table; a host not in it does not exist.
type resolver map[string][]string

func (r resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	list, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var ips []netip.Addr
	for _, s := range list {
		ips = append(ips, netip.MustParseAddr(s))
	}
	return ips, nil
}

// TestCheckTarget checks the target of a request that goes to a proxy:
// every address it has here, and a name that has none.
func TestCheckTarget(t *testing.T) {
	// A lookup that gets no answer in time is no decision of the guard's.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := (Rules{Unattended: true}).CheckTarget(ctx, slowResolver{}, "slow.example", 80); !errors.Is(err, context.Canceled) {
		t.Errorf("a lookup canceled: %v", err)
	}
	res := resolver{
		"public.example":     {"93.184.216.34"},
		"mixed.example":      {"93.184.216.34", "169.254.169.254"},
		"internal.example":   {"10.1.2.3"},
		"blocked.example":    {"0.0.0.0", "::"}, // as a DNS that blocks a name answers
		"xn--80ajuz.example": {"169.254.169.254"},
	}
	allow := entries(t, "internal.example:443", "inside.example:443", "my_service.example:443", "xn--e1afmkfd.example:80")
	tests := []struct {
		host        string
		port        uint16
		person      string // "" for allowed, or what the error says
		alone, with string
	}{
		{"public.example", 443, "", "", ""},
		{"93.184.216.34", 443, "", "", ""},
		{"169.254.169.254", 80, "never connects", "never connects", "never connects"},
		{"mixed.example", 443, "never connects", "never connects", "never connects"},
		{"internal.example", 443, "", "is private", ""},
		{"internal.example", 8443, "", "is private", "is private"},
		{"inside.example", 443, "", "does not resolve here", ""}, // the proxy's DNS alone knows it
		{"inside.example", 80, "", "does not resolve here", "does not resolve here"},
		{"blocked.example", 443, "", "only to an unspecified address", "only to an unspecified address"},
		// What the resolver here would not read, and a proxy would.
		{"2852039166", 80, "never connects", "never connects", "never connects"},
		{"0251.0376.0251.0376", 80, "never connects", "never connects", "never connects"},
		{"169.254.169.254.", 80, "never connects", "never connects", "never connects"},
		{"127.1", 80, "", "is private", "is private"},
		{"мета.example", 80, "never connects", "never connects", "never connects"},
		{"２８５２０３９１６６", 80, "never connects", "never connects", "never connects"}, // as IDNA, then net/http, write it
		{"0x", 80, "never connects", "never connects", "never connects"},
		{"0169.0254.0169.0254", 80, "never connects", "never connects", "never connects"},
		{"my_service.example", 443, "", "does not resolve here", ""},                      // ASCII is not IDNA's to judge
		{"пример.example", 80, "", "does not resolve here", ""},                           // allowed as it is written in ASCII
		{"a\u0080b.example", 80, "not a host name", "not a host name", "not a host name"}, // IDNA refuses it
	}
	for _, tt := range tests {
		for _, mode := range []struct {
			rules Rules
			want  string
		}{{Rules{}, tt.person}, {Rules{Unattended: true}, tt.alone}, {Rules{Unattended: true, Allow: allow}, tt.with}} {
			err := mode.rules.CheckTarget(t.Context(), res, tt.host, tt.port)
			if mode.want == "" && err != nil || mode.want != "" && (err == nil || !strings.Contains(err.Error(), mode.want)) {
				t.Errorf("%s:%d, unattended %v: %v; want %q", tt.host, tt.port, mode.rules.Unattended, err, mode.want)
			}
			if _, ok := errors.AsType[*Error](err); err != nil && !ok {
				t.Errorf("%s:%d: %v, not an *Error", tt.host, tt.port, err)
			}
		}
	}
}
