// Package netguard decides which addresses vegtam may connect to. Some it
// never connects to, whoever asks: the metadata services of clouds, which
// hand out credentials to whoever reaches them, and the addresses that are
// no single host's (link-local, multicast, unspecified). Loopback and
// private addresses it connects to when a person at a terminal runs the
// request; without one, for a script or an agent that a file or a
// response may lead, only to those that the operator's policy allows.
//
// The check is of the address each connection is made to, after the
// lookup, so that a name that resolves to one address when looked up and
// to another when connected to (DNS rebinding) gains nothing.
package netguard

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Class is what kind of address an address is, as the guard sees it.
type Class string

const (
	Public      Class = ""
	Metadata    Class = "a cloud metadata address"
	LinkLocal   Class = "link-local"
	Multicast   Class = "multicast"
	Unspecified Class = "unspecified"
	Loopback    Class = "loopback"
	Private     Class = "RFC 1918"
	Shared      Class = "shared, RFC 6598: carrier-grade NAT"
	UniqueLocal Class = "unique local, RFC 4193"
	LocalNAT64  Class = "behind a NAT64 of local use, RFC 8215"
)

// metadata are the addresses of the metadata services of clouds, which
// give the credentials of the machine to any request that reaches them.
// The first two are link-local anyway; they are named so that the error
// says what they are.
var metadata = []struct {
	addr netip.Addr
	of   string // whose, as their documentation names it
}{
	{netip.MustParseAddr("169.254.169.254"), "AWS, Azure, Google Cloud, Oracle Cloud, DigitalOcean, OpenStack and others"},
	{netip.MustParseAddr("169.254.170.2"), "AWS ECS, the credentials of a task"},
	{netip.MustParseAddr("169.254.170.23"), "AWS EKS Pod Identity"},
	{netip.MustParseAddr("fd00:ec2::254"), "AWS, the instance metadata service over IPv6"},
	{netip.MustParseAddr("fd00:ec2::23"), "AWS EKS Pod Identity over IPv6"},
	{netip.MustParseAddr("fd20:ce::254"), "Google Cloud, the metadata server over IPv6"},
	{netip.MustParseAddr("fd00:c1::a9fe:a9fe"), "Oracle Cloud, the instance metadata service over IPv6"},
	{netip.MustParseAddr("192.0.0.192"), "Oracle Cloud Classic"},
	{netip.MustParseAddr("100.100.100.200"), "Alibaba Cloud"},
	{netip.MustParseAddr("168.63.129.16"), "Azure, the host's WireServer"},
}

var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")      // RFC 1122: "this host on this network"; Linux connects it to the host itself
	shared      = netip.MustParsePrefix("100.64.0.0/10")  // RFC 6598
	nat64       = netip.MustParsePrefix("64:ff9b::/96")   // RFC 6052: an IPv4 address behind a NAT64 gateway
	nat64Local  = netip.MustParsePrefix("64:ff9b:1::/48") // RFC 8215: the same, for local use, under a prefix of the network's
)

// Classify returns the class of ip, and whether vegtam never connects to
// it. An IPv4 address written as IPv6, mapped (::ffff:a.b.c.d) or behind
// the NAT64 prefix of RFC 6052, is the IPv4 address it carries. Behind a
// NAT64 prefix of local use, whose length is the network's, it is read as
// under a /96, as most networks have it; one that is not never connected
// to is private, since which address it carries is not known.
func Classify(ip netip.Addr) (c Class, never bool) {
	ip = ip.WithZone("").Unmap()
	b := ip.As16()
	switch {
	case nat64.Contains(ip):
		ip = netip.AddrFrom4([4]byte(b[12:]))
	case nat64Local.Contains(ip):
		if c, never = Classify(netip.AddrFrom4([4]byte(b[12:]))); never {
			return c, true
		}
		return LocalNAT64, false
	}
	for _, m := range metadata {
		if ip == m.addr {
			return Metadata, true
		}
	}
	switch {
	case ip.IsUnspecified(), thisNetwork.Contains(ip), ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return Unspecified, true
	case ip.IsLinkLocalUnicast():
		return LinkLocal, true
	case ip.IsMulticast():
		return Multicast, true
	case ip.IsLoopback():
		return Loopback, false
	case ip.Is4() && ip.IsPrivate():
		return Private, false
	case ip.IsPrivate():
		return UniqueLocal, false
	case shared.Contains(ip):
		return Shared, false
	}
	return Public, false
}

// Never returns the addresses of the metadata services vegtam never
// connects to, each with whose it is.
func Never() []string {
	var list []string
	for _, m := range metadata {
		list = append(list, m.addr.String()+" ("+m.of+")")
	}
	return list
}

// Entry is an address that the policy allows without a person at a
// terminal: a host name and port, an IP address with a port or without
// one, or a prefix in CIDR notation.
type Entry struct {
	text   string
	host   string       // a name, in lower case, without a final dot; "" for an address
	port   uint16       // 0 for any
	prefix netip.Prefix // for an address or a prefix
}

func (e Entry) String() string { return e.text }

// ParseEntry parses an entry of the policy's network.allow: localhost:3000,
// 127.0.0.1, 127.0.0.1:8080, [::1]:8080 or 10.0.0.0/8. A name needs its
// port: the guard allows a name only where it is asked for.
func ParseEntry(s string) (Entry, error) {
	e := Entry{text: s}
	bad := fmt.Errorf("%q: want host:port, an IP address with or without a port, or a CIDR prefix such as 10.0.0.0/8", s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Entry{}, bad
		}
		e.prefix = p.Masked()
		return e, nil
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		e.prefix = netip.PrefixFrom(ip.WithZone(""), ip.BitLen())
		return e, nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		ip := ap.Addr().WithZone("")
		e.prefix, e.port = netip.PrefixFrom(ip, ip.BitLen()), ap.Port()
		if e.port == 0 {
			return Entry{}, bad
		}
		return e, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		if Name(s) != "" {
			return Entry{}, fmt.Errorf("%q: name the port too, such as %s:8080: a name is allowed for one port", s, s)
		}
		return Entry{}, bad
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if e.host = Name(host); e.host == "" || err != nil || n == 0 {
		return Entry{}, bad
	}
	e.port = uint16(n)
	return e, nil
}

// Name returns host as the guard compares names: in lower case, without
// a final dot; "" if it is no host name.
func Name(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || strings.Trim(host, "abcdefghijklmnopqrstuvwxyz0123456789-._") != "" {
		return ""
	}
	return host
}

// Rules are what the connections of a run may go to.
type Rules struct {
	// Unattended is set when no person is at a terminal: loopback and
	// private addresses are then refused, unless Allow names them.
	Unattended bool
	Allow      []Entry
}

// Error is a connection the guard refused.
type Error struct {
	Addr  string // the address, IP and port; or the host, for one that does not resolve
	Class Class
	Never bool  // whoever asks
	Err   error // why a host could not be checked
}

func (e *Error) Error() string {
	switch {
	case e.Err != nil && e.Never:
		return fmt.Sprintf("cannot check the address of %s through the proxy: %v", e.Addr, e.Err)
	case e.Err != nil:
		return fmt.Sprintf("cannot check the address of %s through the proxy: it does not resolve here (%v), "+
			"and no person is at a terminal; allow it in policy: network.allow", e.Addr, e.Err)
	case e.Class == Metadata:
		return fmt.Sprintf("address %s is %s, which vegtam never connects to: it hands out the credentials of the machine", e.Addr, e.Class)
	case e.Never:
		return fmt.Sprintf("address %s is %s, which vegtam never connects to: it is no single host's", e.Addr, e.Class)
	}
	return fmt.Sprintf("address %s is private (%s), and no person is at a terminal; allow it in policy: network.allow", e.Addr, e.Class)
}

func (e *Error) Unwrap() error { return e.Err }

// Check returns an *Error if a connection to addr is not allowed. host is
// the name the connection was asked for, as written; "" for an address.
func (r Rules) Check(host string, addr netip.AddrPort) error {
	c, never := Classify(addr.Addr())
	switch {
	case never:
		return &Error{Addr: addr.String(), Class: c, Never: true}
	case c == Public, !r.Unattended, r.allowed(Name(host), addr):
		return nil
	}
	return &Error{Addr: addr.String(), Class: c}
}

// allowed reports whether Allow names addr, or host, its name, and its port.
func (r Rules) allowed(host string, addr netip.AddrPort) bool {
	ip := addr.Addr().WithZone("").Unmap()
	for _, e := range r.Allow {
		switch {
		case e.port != 0 && e.port != addr.Port():
		case e.host != "" && e.host == host, e.host == "" && e.prefix.Contains(ip):
			return true
		}
	}
	return false
}

// allowedName reports whether Allow names host, a name, and port.
func (r Rules) allowedName(host string, port uint16) bool {
	for _, e := range r.Allow {
		if e.host != "" && e.host == host && e.port == port {
			return true
		}
	}
	return false
}

// Resolver looks up the addresses of a host, as net.DefaultResolver does.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// CheckTarget checks host and port before a request to them is handed to
// a proxy, which connects out of the guard's sight: every address the
// host has here must be allowed. The host is read as the proxy may read
// it: an IPv4 address in any form that inet_aton takes (2852039166,
// 0251.0376.0251.0376), a name not in ASCII as IDNA writes it. A host
// that does not resolve here, or only to an unspecified address, as a
// DNS that blocks it answers, cannot be checked: it passes with a person
// at a terminal, as behind a proxy that resolves names itself; without
// one, only if Allow names it.
func (r Rules) CheckTarget(ctx context.Context, res Resolver, host string, port uint16) error {
	where := net.JoinHostPort(host, strconv.Itoa(int(port)))
	host, aerr := ASCII(host)
	if aerr != nil {
		return &Error{Addr: where, Err: fmt.Errorf("not a host name: %w", aerr), Never: true}
	}
	host = strings.TrimSuffix(host, ".")
	if ips := legacyIPv4(host); len(ips) > 0 {
		for _, ip := range ips {
			if err := r.Check("", netip.AddrPortFrom(ip, port)); err != nil {
				return err
			}
		}
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return r.Check("", netip.AddrPortFrom(ip, port))
	}
	unknown := func(err error) error {
		if !r.Unattended || r.allowedName(Name(host), port) {
			return nil
		}
		return &Error{Addr: where, Err: err}
	}
	ips, err := res.LookupNetIP(ctx, "ip", host)
	if ctx.Err() != nil {
		return ctx.Err() // no answer in time: no decision of the guard's
	}
	if err != nil {
		return unknown(err)
	}
	if !slices.ContainsFunc(ips, func(ip netip.Addr) bool { return !ip.IsUnspecified() }) {
		return unknown(errors.New("only to an unspecified address"))
	}
	for _, ip := range ips {
		if err := r.Check(host, netip.AddrPortFrom(ip, port)); err != nil {
			return err
		}
	}
	return nil
}

// ASCII returns host as net/http sends it to a proxy and dials it: a name
// in ASCII as it is, and one that is not as IDNA writes it.
func ASCII(host string) (string, error) {
	for i := range len(host) {
		if host[i] >= 0x80 {
			return idna.Lookup.ToASCII(host)
		}
	}
	return host, nil
}

// legacyIPv4 returns the IPv4 addresses that a resolver or a proxy may
// read s as: as inet_aton does, one to four parts, each decimal, octal
// with a leading 0 or hex with 0x, the last one filling the bytes that are
// left; as the WHATWG URL standard does too, for which 0x alone is 0; and
// as some do, with leading zeros decimal. None if s is no number.
func legacyIPv4(s string) []netip.Addr {
	var ips []netip.Addr
	for _, octal := range []bool{true, false} {
		if ip, ok := numericIPv4(s, octal); ok && !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	return ips
}

// numericIPv4 reads s as an IPv4 address in parts, a leading 0 octal or
// not.
func numericIPv4(s string, octal bool) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var v []uint64
	for _, p := range parts {
		base := 10
		switch {
		case p == "0x" || p == "0X":
			p, base = "0", 16
		case len(p) > 1 && (p[:2] == "0x" || p[:2] == "0X"):
			p, base = p[2:], 16
		case len(p) > 1 && p[0] == '0' && octal:
			p, base = p[1:], 8
		}
		n, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		v = append(v, n)
	}
	last, bits := v[len(v)-1], 32-8*(len(v)-1)
	if last >= 1<<bits {
		return netip.Addr{}, false
	}
	var a uint64
	for _, n := range v[:len(v)-1] {
		if n > 255 {
			return netip.Addr{}, false
		}
		a = a<<8 | n
	}
	if a = a<<bits | last; a > math.MaxUint32 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, uint32(a)))), true
}
