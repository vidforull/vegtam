package cli

import (
	"fmt"
	"time"

	"github.com/spf13/pflag"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/exec"
)

// netFlags are the transport flags of run and tui. What weakens a check,
// belongs to the machine or holds a secret is set here, never in a file.
type netFlags struct {
	cacert, cert, key      string
	insecure               bool
	http11, http2, h2c     bool
	connect, read, maxTime timeout
	timeoutUsed            bool // --timeout was given, the old name of --max-time
}

// newNetFlags returns the flags as they are when not given. The read
// timeout is how long a server that has stopped is waited for; the max
// time is longer, so that a response that keeps coming has time.
func newNetFlags() netFlags {
	return netFlags{connect: timeout(10 * time.Second), read: timeout(30 * time.Second), maxTime: timeout(2 * time.Minute)}
}

func (f *netFlags) add(fl *pflag.FlagSet) {
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
	fl.BoolVar(&f.insecure, "insecure", false, "do not check server certificates; only for a person at a terminal")
}

// insecureBanner is printed on stderr by every run with --insecure.
const insecureBanner = "vegtam: warning: --insecure: server certificates are not checked; anyone between here and the server can read and change the requests, secrets included, and the responses\n"

// transport returns the transport that the flags say, with the files of
// the TLS flags read. --insecure needs a person at a terminal: a script or
// an agent, which may be led by what a file or a response says, cannot
// turn the check off.
func (f *netFlags) transport(cfg *Config) (exec.Transport, error) {
	if f.insecure && (!cfg.Interactive || cfg.json) {
		return exec.Transport{}, core.Errorf(core.KindUsage, core.Source{},
			"--insecure needs a person at a terminal: stdin and stdout must be terminals, and --json is not given. "+
				"A script or an agent can trust the server's CA with --cacert instead; "+
				"turning the check off for a host will be a matter for the operator's policy file")
	}
	var version string
	for _, v := range []struct {
		set     bool
		version string
	}{{f.http11, core.HTTP11}, {f.http2, core.HTTP2}, {f.h2c, core.HTTP2PriorKnowledge}} {
		if v.set && version != "" {
			return exec.Transport{}, core.Errorf(core.KindUsage, core.Source{}, "--http1.1, --http2 and --http2-prior-knowledge exclude each other")
		}
		if v.set {
			version = v.version
		}
	}
	t, err := exec.LoadTLS(f.cacert, f.cert, f.key, f.insecure)
	if err != nil {
		return exec.Transport{}, err
	}
	if f.timeoutUsed {
		fmt.Fprint(cfg.errOut, "vegtam: warning: --timeout is now --max-time, and --read-timeout limits too, 30s unless given; the old name will go away\n")
	}
	return exec.Transport{
		TLS: t, Version: version, Connect: time.Duration(f.connect), Read: time.Duration(f.read), Total: time.Duration(f.maxTime),
	}, nil
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
