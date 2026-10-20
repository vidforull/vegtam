package cli

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/net/http/httpproxy"

	"github.com/vidforull/vegtam/internal/core"
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
	return merge(pol, f, cfg.unattended(), httpproxy.FromEnvironment())
}

// merge makes the transport of a run, in one order for every setting:
// what vegtam does on its own, then the operator's policy pol, then the
// flags f. The directives of a request may then lower its limits, and
// nothing else (see exec.Client.Settings). With unattended, no person is
// at a terminal: what weakens a check then comes from the policy alone,
// and a flag that would is an error that names the entry of the policy
// to write. proxyEnv is the proxy that the environment names. It returns
// the warnings to print.
func merge(pol *policy.Policy, f *netFlags, unattended bool, proxyEnv *httpproxy.Config) (exec.Transport, []string, error) {
	m := &merger{pol: pol, f: f, unattended: unattended, tr: exec.Transport{
		Connect: time.Duration(f.connect), Read: time.Duration(f.read), Total: time.Duration(f.maxTime),
		NoCookies: f.noCookies, Guard: netguard.Rules{Unattended: unattended, Allow: slices.Clone(pol.Network.Allow)},
	}}
	for _, step := range []func() error{m.version, m.limits, m.tls, func() error { return m.proxy(proxyEnv) }} {
		if err := step(); err != nil {
			return exec.Transport{}, nil, err
		}
	}
	return m.tr, m.warnings, nil
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
func (m *merger) limits() error {
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
	return nil
}

// tls reads the files of the TLS flags. Without a person at a terminal,
// --insecure leaves unchecked only the hosts the policy names for it.
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
	m.tr.TLS, err = exec.LoadTLS(m.f.cacert, m.f.cert, m.f.key, insecure)
	return err
}

// proxy sets the proxy of the run (see proxyOf). The guard connects to
// it as the proxy, whatever its address, and to nothing else there.
func (m *merger) proxy(proxyEnv *httpproxy.Config) error {
	proxy, warning := proxyOf(m.pol, m.unattended, proxyEnv)
	if warning != "" {
		m.warnings = append(m.warnings, warning)
	}
	if proxy == nil {
		return nil
	}
	for _, s := range []string{proxy.HTTPProxy, proxy.HTTPSProxy} {
		if u := proxyURL(s); u != nil && u.User != nil {
			pw, _ := u.User.Password()
			m.tr.Secrets = append(m.tr.Secrets, credentials(u.User.Username(), pw)...)
		}
	}
	find := proxy.ProxyFunc()
	m.tr.Proxy = func(r *http.Request) (*url.URL, error) { return find(r.URL) }
	return nil
}

// proxyOf returns the proxy of a run, as the policy pol says, or nil for
// none; and a warning when the environment names a proxy that is not
// used. Without a person at a terminal, the environment's proxy is used
// only if the policy says so: whoever sets the environment of a script
// or an agent would choose where its requests go.
func proxyOf(pol *policy.Policy, unattended bool, proxyEnv *httpproxy.Config) (*httpproxy.Config, string) {
	noProxy := strings.Join(pol.Network.NoProxy, ",")
	switch p := pol.Network.Proxy; {
	case p == policy.ProxyEnvironment, p == "" && !unattended:
		cfg := *proxyEnv
		if noProxy != "" {
			cfg.NoProxy = strings.Trim(cfg.NoProxy+","+noProxy, ",")
		}
		return &cfg, ""
	case p != "":
		return &httpproxy.Config{HTTPProxy: p, HTTPSProxy: p, NoProxy: noProxy}, ""
	case proxyEnv.HTTPProxy != "" || proxyEnv.HTTPSProxy != "":
		return nil, "the proxy of the environment (HTTPS_PROXY, HTTP_PROXY) is not used without a person at a terminal: " +
			"the operator's policy names the proxy, network.proxy, or \"environment\" for that one (see vegtam policy --help)"
	}
	return nil, ""
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
