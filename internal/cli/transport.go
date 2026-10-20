package cli

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/net/http/httpproxy"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/exec"
	"github.com/vidforull/vegtam/internal/core/netguard"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// netFlags are the transport flags of run and tui. What weakens a check,
// belongs to the machine or holds a secret is set here or in the
// operator's policy, never in a file.
type netFlags struct {
	cacert, cert, key      string
	insecure               bool
	http11, http2, h2c     bool
	connect, read, maxTime timeout
	timeoutUsed            bool // --timeout was given, the old name of --max-time
	noCookies              bool
	proxy, noProxy         string
	proxyAuth              string // "$env NAME"
	resolve, connectTo     []string
	unixSocket, abstract   string
	set                    *pflag.FlagSet // to tell a flag given from its default
}

// newNetFlags returns the flags as they are when not given. The read
// timeout is how long a server that has stopped is waited for; the max
// time is longer, so that a response that keeps coming has time.
func newNetFlags() netFlags {
	return netFlags{connect: timeout(10 * time.Second), read: timeout(30 * time.Second), maxTime: timeout(2 * time.Minute)}
}

func (f *netFlags) add(fl *pflag.FlagSet) {
	f.set = fl
	fl.Var(&f.connect, "connect-timeout", "time to get a connection: DNS, TCP, a proxy and the TLS handshake; 0 for no limit")
	fl.Var(&f.read, "read-timeout", "time to wait for data from the server once the request is sent, for the headers and during the body; 0 for no limit")
	fl.Var(&f.maxTime, "max-time", "time limit for each request, redirects and body included; 0 for no limit")
	// The name of the one limit before there were three, for a while.
	// pflag's own deprecation notice would go to stdout, into the JSON.
	fl.AddFlag(&pflag.Flag{
		Name: "timeout", Usage: "the same as --max-time", Value: renamed{&f.maxTime, &f.timeoutUsed},
		DefValue: f.maxTime.String(), Hidden: true,
	})
	fl.BoolVar(&f.http11, "http1.1", false, "speak HTTP/1.1, whatever the request line says")
	fl.BoolVar(&f.http2, "http2", false, "speak HTTP/2 over TLS, and nothing else")
	fl.BoolVar(&f.h2c, "http2-prior-knowledge", false, "speak HTTP/2 without agreeing on it first: h2c over http")
	fl.StringVar(&f.cacert, "cacert", "", "trust the CA certificates of this PEM file too, as well as the system's")
	fl.StringVar(&f.cert, "cert", "", "offer this PEM client certificate to the origin of each request as written")
	fl.StringVar(&f.key, "key", "", "the unencrypted PEM key of --cert, if it is not in the --cert file")
	fl.BoolVar(&f.insecure, "insecure", false, "do not check server certificates; only for a person at a terminal, or for the hosts the policy names")
	fl.BoolVar(&f.noCookies, "no-cookies", false, "keep no cookie jar: send no cookie that a response set, keep none")
	fl.StringVar(&f.proxy, "proxy", "", "send through this proxy, http, https, socks5 or socks5h://host:port; only for a person at a terminal: without one, the policy's")
	fl.StringVar(&f.noProxy, "noproxy", "", "hosts that go direct, in place of NO_PROXY and the policy's no_proxy: host,.domain,10.0.0.0/8; * for all")
	fl.StringVar(&f.proxyAuth, "proxy-auth", "", "the proxy's user and password, from the environment: '$env NAME' for a variable that holds user:password")
	fl.StringArrayVar(&f.resolve, "resolve", nil, "connect to host:port at these addresses, as host:port:addr[,addr], keeping the host for Host and TLS; again for more")
	fl.StringArrayVar(&f.connectTo, "connect-to", nil, "connect to host:port at another host and port, as host:port:to_host:to_port, keeping the host for Host and TLS; again for more")
	fl.StringVar(&f.unixSocket, "unix-socket", "", "send every request to this unix socket, the host of its URL going in Host, as for http://docker/v1.43/info")
	fl.StringVar(&f.abstract, "abstract-unix-socket", "", "the same, to a socket of Linux's abstract namespace, named without its @")
}

// given reports whether the flag name was given.
func (f *netFlags) given(name string) bool { return f.set != nil && f.set.Changed(name) }

// insecureWarning is printed on stderr by every run with --insecure.
const insecureWarning = "--insecure: server certificates are not checked; anyone between here and the server can read and change the requests, secrets included, and the responses"

// insecureBanner is how the warning shows on stderr.
const insecureBanner = "vegtam: warning: " + insecureWarning + "\n"

// transport returns the transport of a run (see merge), and prints its
// warnings, --insecure's among them.
func (f *netFlags) transport(cfg *Config, pol *policy.Policy) (exec.Transport, error) {
	tr, warnings, err := f.merged(cfg, pol)
	if err != nil {
		return exec.Transport{}, err
	}
	for _, w := range warnings {
		fmt.Fprintf(cfg.errOut, "vegtam: warning: %s\n", cfg.text(w))
	}
	return tr, nil
}

// merged is merge for this process: its mode and its environment.
func (f *netFlags) merged(cfg *Config, pol *policy.Policy) (exec.Transport, []string, error) {
	return merge(pol, f, cfg.unattended(), httpproxy.FromEnvironment(), env.Lookup)
}

// merge makes the transport of a run, in one order for every setting:
// what vegtam does on its own, then the operator's policy pol, then the
// flags f. The directives of a request may then lower its limits, and
// nothing else (see exec.Client.Settings). With unattended, no person is
// at a terminal: what weakens a check then comes from the policy alone,
// and a flag that would is an error that names the entry of the policy
// to write. proxyEnv is the proxy that the environment names; lookup
// reads the variable that holds the credentials of the proxy. It returns
// the warnings to print.
func merge(pol *policy.Policy, f *netFlags, unattended bool, proxyEnv *httpproxy.Config, lookup func(string) (string, bool)) (exec.Transport, []string, error) {
	m := &merger{pol: pol, f: f, unattended: unattended, tr: exec.Transport{
		Connect: time.Duration(f.connect), Read: time.Duration(f.read), Total: time.Duration(f.maxTime),
		NoCookies: f.noCookies, Guard: netguard.Rules{Unattended: unattended, Allow: slices.Clone(pol.Network.Allow)},
	}}
	m.limits()
	for _, step := range []func() error{m.version, m.tls, m.routes, m.socket, func() error { return m.proxy(proxyEnv, lookup) }} {
		if err := step(); err != nil {
			return exec.Transport{}, nil, err
		}
	}
	return m.tr, m.warnings, nil
}

// offline returns the transport of a command that sends nothing, as show:
// the time limits of f with the ceilings of the policy pol, and the
// variable of the proxy's credentials, which no request may read. It
// reads no file and no variable, so that a CA of hosts.* that cannot be
// read, or a proxy_auth variable that is not set, cannot stop it.
func (f *netFlags) offline(pol *policy.Policy) exec.Transport {
	m := &merger{pol: pol, f: f, tr: exec.Transport{Connect: time.Duration(f.connect), Read: time.Duration(f.read), Total: time.Duration(f.maxTime)}}
	m.limits()
	// As proxyUser names it for a run without --proxy-auth: the policy's
	// credentials go with its own proxy, a URL.
	if n := pol.Network; n.ProxyAuth != "" && n.Proxy != "" && n.Proxy != policy.ProxyEnvironment {
		m.tr.HiddenEnv = append(m.tr.HiddenEnv, n.ProxyAuth)
	}
	return m.tr
}

// merger is the state of merge.
type merger struct {
	pol        *policy.Policy
	f          *netFlags
	unattended bool
	tr         exec.Transport
	warnings   []string
}

func usage(format string, args ...any) error {
	return core.Errorf(core.KindUsage, core.Source{}, format, args...)
}

// version sets the HTTP version of the flags, if any.
func (m *merger) version() error {
	f := m.f
	for _, v := range []struct {
		set     bool
		version string
	}{{f.http11, core.HTTP11}, {f.http2, core.HTTP2}, {f.h2c, core.HTTP2PriorKnowledge}} {
		if v.set && m.tr.Version != "" {
			return usage("--http1.1, --http2 and --http2-prior-knowledge exclude each other")
		}
		if v.set {
			m.tr.Version = v.version
		}
	}
	return nil
}

// limits holds the time limits of the flags to the ceilings of the
// policy: a limit above one, or none, is the ceiling, with a warning if
// the flag was given.
func (m *merger) limits() {
	if m.f.timeoutUsed {
		m.warnings = append(m.warnings, "--timeout is now --max-time, and --read-timeout limits too, 30s unless given; the old name will go away")
	}
	tr, ceil := &m.tr, m.pol.Limits
	for _, l := range []struct {
		flag, ceiling string
		limit         *time.Duration
		max           time.Duration
		from          *string
	}{
		{"connect-timeout", "connect_timeout_ceiling", &tr.Connect, ceil.Connect, &tr.ConnectFrom},
		{"read-timeout", "read_timeout_ceiling", &tr.Read, ceil.Read, &tr.ReadFrom},
		{"max-time", "max_time_ceiling", &tr.Total, ceil.MaxTime, &tr.TotalFrom},
	} {
		if l.max == 0 || *l.limit != 0 && *l.limit <= l.max {
			continue
		}
		if m.f.given(l.flag) || l.flag == "max-time" && m.f.timeoutUsed {
			m.warnings = append(m.warnings, fmt.Sprintf("--%s %s is more than the policy allows, %s (limits.%s), which holds",
				l.flag, core.FormatTimeout(*l.limit), core.FormatTimeout(l.max), l.ceiling))
		}
		*l.limit, *l.from = l.max, "the policy's limits."+l.ceiling
	}
}

// tls reads the files of the TLS flags and of the policy's hosts. Without
// a person at a terminal, --insecure leaves unchecked only the hosts the
// policy names for it.
func (m *merger) tls() error {
	insecure, hosts := m.f.insecure, m.pol.Network.InsecureHosts
	switch {
	case insecure && m.unattended && len(hosts) == 0:
		return usage("--insecure needs a person at a terminal: stdin and stdout must be terminals, and --json is not given. " +
			"A script or an agent can trust the server's CA with --cacert instead, " +
			"or the operator can let --insecure leave the certificates of chosen hosts unchecked: network.insecure_hosts in the policy (see vegtam policy --help)")
	case insecure && m.unattended:
		for _, h := range hosts {
			m.tr.InsecureOrigins = append(m.tr.InsecureOrigins, "https://"+h)
		}
		m.warnings = append(m.warnings, fmt.Sprintf("--insecure: the certificates of %s are not checked, as the policy allows (network.insecure_hosts); "+
			"anyone between here and them can read and change the requests, secrets included, and the responses", strings.Join(hosts, ", ")))
		insecure = false
	case insecure:
		m.warnings = append(m.warnings, insecureWarning)
	}
	var err error
	if m.tr.TLS, err = exec.LoadTLS(m.f.cacert, m.f.cert, m.f.key, insecure); err != nil {
		return err
	}
	for _, h := range m.pol.Hosts {
		if m.tr.Hosts == nil {
			m.tr.Hosts = map[string]exec.TLS{}
		}
		if m.tr.Hosts[h.Origin], err = exec.HostTLS(m.tr.TLS, h.Name, h.CACert, h.Cert, h.Key); err != nil {
			return err
		}
	}
	return nil
}

// routes sets the routes of --resolve and --connect-to. Without a person
// at a terminal, each must be one the policy lists: it sends the requests
// of a host, and its secrets, to another address.
func (m *merger) routes() error {
	n := m.pol.Network
	for _, s := range m.f.resolve {
		r, err := netguard.ParseResolve(s)
		switch {
		case err != nil:
			return usage("--resolve %v", err)
		case m.unattended && !slices.ContainsFunc(n.Resolve, func(p netguard.Resolve) bool { return p.String() == r.String() }):
			return usage("--resolve %s needs a person at a terminal, or the operator's policy to list it: network.resolve (see vegtam policy --help)", r)
		}
		m.tr.Routes.Resolve = append(m.tr.Routes.Resolve, r)
	}
	for _, s := range m.f.connectTo {
		c, err := netguard.ParseConnectTo(s)
		switch {
		case err != nil:
			return usage("--connect-to %v", err)
		case m.unattended && !slices.Contains(n.ConnectTo, c):
			return usage("--connect-to %s needs a person at a terminal, or the operator's policy to list it: network.connect_to (see vegtam policy --help)", c)
		}
		m.tr.Routes.ConnectTo = append(m.tr.Routes.ConnectTo, c)
	}
	return nil
}

// socket sets the unix socket that every request goes to, if a flag names
// one. Without a person at a terminal, it must be one the policy lists: a
// socket such as Docker's is root on the machine.
func (m *merger) socket() error {
	f, path, flag := m.f, m.f.unixSocket, "--unix-socket"
	switch {
	case f.unixSocket != "" && f.abstract != "":
		return usage("--unix-socket and --abstract-unix-socket exclude each other")
	case f.abstract != "" && runtime.GOOS != "linux":
		return usage("--abstract-unix-socket: abstract sockets are Linux's")
	case f.abstract != "":
		path, flag = "@"+f.abstract, "--abstract-unix-socket"
	case path == "":
		return nil
	default:
		// A path, @ and all, as curl reads it: the socket is the file its
		// links lead to now, which is what is checked and connected to.
		abs, err := filepath.Abs(path)
		if err != nil {
			return usage("%s: %v", flag, err)
		}
		if path, err = filepath.EvalSymlinks(abs); err != nil {
			path = abs
		}
	}
	if f.proxy != "" || len(f.resolve) > 0 || len(f.connectTo) > 0 {
		return usage("%s goes with no --proxy, --resolve or --connect-to: every request goes to the socket", flag)
	}
	if m.unattended && !slices.ContainsFunc(m.pol.Network.UnixSockets, func(s string) bool { return sameSocket(s, path) }) {
		return usage("%s %s needs a person at a terminal, or the operator's policy to list it: network.unix_sockets (see vegtam policy --help)", flag, path)
	}
	m.tr.Socket = path
	return nil
}

// sameSocket reports whether entry, a socket of the policy, an absolute
// path or @name, is socket, a path whose links are resolved or @name.
func sameSocket(entry, socket string) bool {
	if strings.HasPrefix(entry, "@") || strings.HasPrefix(socket, "@") {
		return entry == socket
	}
	if r, err := filepath.EvalSymlinks(entry); err == nil {
		entry = r
	}
	return filepath.Clean(entry) == socket
}

// proxy sets the proxy of the run (see proxyOf), with the credentials
// that the flags or the policy name. The guard connects to it as the
// proxy, whatever its address, and to nothing else there.
func (m *merger) proxy(proxyEnv *httpproxy.Config, lookup func(string) (string, bool)) error {
	f := m.f
	if f.proxy != "" {
		u, err := url.Parse(f.proxy)
		switch {
		case m.unattended:
			return usage("--proxy needs a person at a terminal: without one, requests go through the proxy of the operator's policy, network.proxy (see vegtam policy --help)")
		case err == nil && u.User != nil:
			return usage("--proxy: the URL holds a user or password, which other processes can read in the arguments of a command: pass --proxy-auth '$env NAME', for a variable that holds user:password")
		}
		if err = policy.CheckProxy(f.proxy); err != nil {
			return usage("--proxy: %v", err)
		}
	}
	var noProxy *string
	if f.given("noproxy") {
		noProxy = &f.noProxy
	}
	proxy, warning := proxyOf(m.pol, m.unattended, proxyEnv, f.proxy, noProxy)
	if warning != "" {
		m.warnings = append(m.warnings, warning)
	}
	if proxy == nil {
		if f.proxyAuth != "" {
			return usage("--proxy-auth without a proxy")
		}
		return nil
	}
	for _, s := range []string{proxy.HTTPProxy, proxy.HTTPSProxy} {
		if u := proxyURL(s); u != nil && u.User != nil {
			pw, _ := u.User.Password()
			m.tr.Secrets = append(m.tr.Secrets, credentials(u.User.Username(), pw)...)
		}
	}
	user, err := m.proxyUser(lookup)
	if err != nil {
		return err
	}
	find := proxy.ProxyFunc()
	m.tr.Proxy = func(r *http.Request) (*url.URL, error) {
		u, err := find(r.URL)
		if u != nil && user != nil {
			with := *u
			with.User = user
			u = &with
		}
		return u, err
	}
	return nil
}

// proxyUser returns the user and password of the proxy, from the
// variable that --proxy-auth names, or the policy for its own proxy; nil
// for none. No request may read the variable: the credentials go to the
// proxy alone.
func (m *merger) proxyUser(lookup func(string) (string, bool)) (*url.Userinfo, error) {
	name, fail := "", func(format string, args ...any) error {
		return core.Errorf(core.KindPolicy, core.Source{File: m.pol.Path}, "network.proxy_auth: "+format, args...)
	}
	switch p := m.pol.Network.Proxy; {
	case m.f.proxyAuth != "" && m.unattended:
		return nil, usage("--proxy-auth needs a person at a terminal: without one, the policy gives its proxy's credentials, network.proxy_auth (see vegtam policy --help)")
	case m.f.proxyAuth != "":
		var ok bool
		if name, ok = policy.EnvRef(m.f.proxyAuth); !ok {
			return nil, usage("--proxy-auth: want '$env NAME', for an environment variable that holds user:password: the credentials never go in the arguments of a command")
		}
		fail = func(format string, args ...any) error { return usage("--proxy-auth: "+format, args...) }
	case m.f.proxy == "" && p != "" && p != policy.ProxyEnvironment:
		name = m.pol.Network.ProxyAuth // the policy's proxy, and no other, gets them
	}
	if name == "" {
		return nil, nil
	}
	m.tr.HiddenEnv = append(m.tr.HiddenEnv, name)
	v, ok := lookup(name)
	u, pw, colon := strings.Cut(v, ":")
	if !ok || !colon || u == "" {
		return nil, fail("$env %s must hold the proxy's user and password, as user:password", name)
	}
	m.tr.Secrets = append(m.tr.Secrets, credentials(u, pw)...)
	return url.UserPassword(u, pw), nil
}

// proxyOf returns the proxy of a run, or nil for none; and a warning when
// the environment names a proxy that is not used. A person at a terminal
// may name one, flag; the policy pol names that of a run without one, or
// "environment" for the environment's, and a person's run otherwise takes
// the environment's. Without a person, the environment's is used only if
// the policy says so: whoever sets the environment of a script or an
// agent would choose where its requests go. noProxy, if given, takes the
// place of NO_PROXY and of the policy's no_proxy.
func proxyOf(pol *policy.Policy, unattended bool, proxyEnv *httpproxy.Config, flag string, noProxy *string) (*httpproxy.Config, string) {
	list := strings.Join(pol.Network.NoProxy, ",")
	var cfg *httpproxy.Config
	switch p := pol.Network.Proxy; {
	case flag != "":
		cfg = &httpproxy.Config{HTTPProxy: flag, HTTPSProxy: flag, NoProxy: list}
	case p == policy.ProxyEnvironment, p == "" && !unattended:
		env := *proxyEnv
		if list != "" {
			env.NoProxy = strings.Trim(env.NoProxy+","+list, ",")
		}
		cfg = &env
	case p != "":
		cfg = &httpproxy.Config{HTTPProxy: p, HTTPSProxy: p, NoProxy: list}
	case proxyEnv.HTTPProxy != "" || proxyEnv.HTTPSProxy != "":
		return nil, "the proxy of the environment (HTTPS_PROXY, HTTP_PROXY) is not used without a person at a terminal: " +
			"the operator's policy names the proxy, network.proxy, or \"environment\" for that one (see vegtam policy --help)"
	default:
		return nil, ""
	}
	if noProxy != nil {
		cfg.NoProxy = *noProxy
	}
	return cfg, ""
}

// proxyURL returns the URL of a proxy as the environment writes it, with a
// scheme or without, as httpproxy reads it; nil for none.
func proxyURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		if u, err = url.Parse("http://" + s); err != nil || u.Host == "" {
			return nil
		}
	}
	return u
}

// minSecret is the length from which a user or a password of the proxy is
// hidden on its own, wherever it is: a shorter one, such as "e", would
// hide every "e" of the output. The two together are hidden whatever
// their length, and so is the base64 of them that Proxy-Authorization
// carries.
const minSecret = 8

// credentials returns the values to hide of a proxy's user and password.
func credentials(user, password string) []string {
	if user == "" && password == "" {
		return nil
	}
	values := []string{user + ":" + password}
	if len(password) >= minSecret {
		values = append(values, password)
	}
	if password == "" && len(user) >= minSecret { // a token given as the user
		values = append(values, user)
	}
	return values
}

// timeout is a time limit flag, written as the directives write it: 30
// (seconds), 500ms, 2m or 1m30s; 0 for no limit.
type timeout time.Duration

func (d *timeout) Set(s string) error {
	v, err := core.ParseTimeout(s)
	if err == nil {
		*d = timeout(v)
	}
	return err
}

func (d *timeout) String() string { return core.FormatTimeout(time.Duration(*d)) }

func (d *timeout) Type() string { return "time" }

// renamed is a time limit flag under an old name, which notes its use.
type renamed struct {
	*timeout
	used *bool
}

func (r renamed) Set(s string) error {
	*r.used = true
	return r.timeout.Set(s)
}
