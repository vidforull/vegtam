package netguard

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Routes send connections elsewhere than their URLs say, as curl's
// --resolve and --connect-to do. The URL keeps its host, which the Host
// header and the TLS of the connection (SNI, and the check of the
// certificate) go by; the guard checks the address connected to.
type Routes struct {
	Resolve   []Resolve
	ConnectTo []ConnectTo
}

// Resolve is a --resolve: the addresses that a host and port connect to,
// in place of what the host resolves to.
type Resolve struct {
	Host  string // lower case, without a final dot
	Port  string
	Addrs []netip.Addr
}

// ParseResolve parses host:port:addr[,addr], as curl's --resolve: an
// IPv6 address may be in brackets.
func ParseResolve(s string) (Resolve, error) {
	bad := fmt.Errorf("%q: want host:port:address, such as api.example:443:127.0.0.1, with more addresses after commas", s)
	host, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Resolve{}, bad
	}
	port, list, ok := strings.Cut(rest, ":")
	r := Resolve{Host: Name(host), Port: port}
	if !ok || r.Host == "" || !validPort(port) {
		return Resolve{}, bad
	}
	for a := range strings.SplitSeq(list, ",") {
		ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(a, "["), "]"))
		if err != nil || ip.Zone() != "" {
			return Resolve{}, bad
		}
		r.Addrs = append(r.Addrs, ip)
	}
	return r, nil
}

func (r Resolve) String() string {
	var addrs []string
	for _, a := range r.Addrs {
		s := a.String()
		if a.Is6() {
			s = "[" + s + "]"
		}
		addrs = append(addrs, s)
	}
	return r.Host + ":" + r.Port + ":" + strings.Join(addrs, ",")
}

// ConnectTo is a --connect-to: the host and port that connections to a
// host and port go to. An empty Host or Port matches any; an empty ToHost
// or ToPort keeps the one asked for.
type ConnectTo struct {
	Host, Port, ToHost, ToPort string
}

// ParseConnectTo parses host:port:to_host:to_port, as curl's
// --connect-to, with IPv6 addresses in brackets.
func ParseConnectTo(s string) (ConnectTo, error) {
	bad := fmt.Errorf("%q: want host:port:to_host:to_port, such as api.example:443:staging.example:8443; an empty part is any host or port, or the one asked for", s)
	parts, ok := splitColons(s)
	if !ok || len(parts) != 4 {
		return ConnectTo{}, bad
	}
	c := ConnectTo{Host: parts[0], Port: parts[1], ToHost: parts[2], ToPort: parts[3]}
	for _, h := range []*string{&c.Host, &c.ToHost} {
		if *h == "" {
			continue
		}
		if *h = hostOrIP(*h); *h == "" {
			return ConnectTo{}, bad
		}
	}
	for _, p := range []string{c.Port, c.ToPort} {
		if p != "" && !validPort(p) {
			return ConnectTo{}, bad
		}
	}
	return c, nil
}

func (c ConnectTo) String() string {
	return bracket(c.Host) + ":" + c.Port + ":" + bracket(c.ToHost) + ":" + c.ToPort
}

// Route returns where a connection to host and port goes: the host and
// port to connect to, after the first --connect-to that matches, and
// the addresses to dial, after the --resolve of that host and port; and
// which flag sent it there, "" for none.
func (r Routes) Route(host, port string) (to string, addrs []string, by string) {
	if n, err := strconv.ParseUint(port, 10, 16); err == nil {
		port = strconv.FormatUint(n, 10) // as the flags write it
	}
	name := Name(host)
	if ip, err := netip.ParseAddr(host); err == nil {
		name = ip.String()
	}
	toHost, toPort := host, port
	for _, c := range r.ConnectTo {
		if (c.Host == "" || c.Host == name) && (c.Port == "" || c.Port == port) {
			if c.ToHost != "" {
				toHost = c.ToHost
			}
			if c.ToPort != "" {
				toPort = c.ToPort
			}
			by = "--connect-to"
			break
		}
	}
	for _, res := range r.Resolve {
		if res.Host == Name(toHost) && res.Port == toPort {
			for _, a := range res.Addrs {
				addrs = append(addrs, net.JoinHostPort(a.String(), toPort))
			}
			by = "--resolve"
			break
		}
	}
	if addrs == nil {
		addrs = []string{net.JoinHostPort(toHost, toPort)}
	}
	return toHost, addrs, by
}

// splitColons splits s at the colons that are not in brackets.
func splitColons(s string) ([]string, bool) {
	var parts []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
		case ':':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
		if depth < 0 || depth > 1 {
			return nil, false
		}
	}
	return append(parts, s[start:]), depth == 0
}

// hostOrIP returns s, a host name or an IP address, IPv6 in brackets, as
// Route compares them; "" if it is neither.
func hostOrIP(s string) string {
	if ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")); err == nil && ip.Zone() == "" {
		return ip.String()
	}
	return Name(s)
}

// bracket returns host as a URL writes it: an IPv6 address in brackets.
func bracket(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func validPort(s string) bool {
	n, err := strconv.ParseUint(s, 10, 16)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}
