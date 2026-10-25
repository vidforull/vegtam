package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/http/httpproxy"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
)

func newPolicyCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "policy",
		Short: "Print the operator's policy and what it allows",
		Long: `Print the operator's policy: what it allows vegtam beyond what vegtam
does on its own, and the limits it holds vegtam to. It is the file
$XDG_CONFIG_HOME/vegtam/policy.json, ~/.config/vegtam/policy.json if
XDG_CONFIG_HOME is not set, beside the trust store, and is read from
there alone: never from a directory of .http files, nor from the current
one. Others must not be able to write it or its directory. Without it,
vegtam does what it does on its own. Every field may be left out:

  {
    "limits": {"max_time_ceiling": "5m", "read_timeout_ceiling": "2m",
               "connect_timeout_ceiling": "30s"},
    "network": {"allow": ["127.0.0.1:8080", "localhost:3000", "10.0.0.0/8"],
                "proxy": "http://proxy.example:3128",
                "proxy_auth": "$env PROXY_AUTH", "no_proxy": ["localhost"],
                "insecure_hosts": ["dev.example:8443"],
                "resolve": ["api.example:443:127.0.0.1"],
                "connect_to": ["api.example:443:staging.example:8443"],
                "unix_sockets": ["/var/run/docker.sock"],
                "confirm": "mutations"},
    "hosts": {"api.internal.example:443": {"cacert": "~/certs/corp.pem",
              "cert": "~/certs/me.pem", "key": "~/certs/me.key"}},
    "secrets": {"env": {"API_TOKEN": ["https://api.example.com"]},
                "cmd": {"TOKEN": ["https://api.example.com",
                                  "https://auth.example.com:8443"]},
                "unattended": "deny", "keeper_asks": "always"}
  }

limits are ceilings on the time limits of every request: on the flags,
and so on the directives of a file, which may only lower them.

vegtam never connects to the metadata services of clouds, nor to
link-local, multicast and unspecified addresses, whoever asks. Loopback
and private addresses it connects to for a person at a terminal. When no
person is at one, as for a script or an agent (stdin or stdout is not a
terminal, or --json is given), it connects to them only as network.allow
names them: host:port, an IP address with a port or without, or a CIDR
prefix. Such a run also takes nothing else that weakens a check from a
flag: --insecure leaves unchecked only the hosts of
network.insecure_hosts, --resolve and --connect-to must be ones that
network.resolve and network.connect_to list, as the flags write them,
and --unix-socket one of network.unix_sockets.

network.proxy is the proxy of every request, or "environment" for that
of HTTPS_PROXY, HTTP_PROXY and NO_PROXY; without it, a person's run uses
the environment's, and a run with no person none. The proxy's user and
password are never written in the policy: proxy_auth names the
environment variable that holds them, as user:password. no_proxy lists
hosts that go direct. Through a proxy, the target of each request is
checked here, as the connection would be, before the proxy gets it.

hosts gives an origin, host or host:port (443 if not given), CAs trusted
for it alone, on top of the system's and --cacert's, and a client
certificate offered to it alone. The paths are absolute, or ~/path; a
key must be private to its owner.

network.confirm says which requests a run without a person sends only
with --confirm: "mutations", the default, those whose method is not
GET, HEAD or OPTIONS; "never" none of them, for an operator who trusts
whatever runs vegtam. Only the policy says "never": no flag, variable
or file can. A request with "# @note" needs --confirm whatever it says.

secrets gives the values of {{$env NAME}} and {{$cmd NAME}}, by NAME,
the origins they may go to: scheme://host, and :port unless it is the
scheme's own, such as https://api.example.com or http://127.0.0.1:8080;
never a wildcard. Nothing else binds them: they are the machine's
values, and every other file may have come with the requests.
http-client.private.env.json binds its own values, in "$allow"; neither
the public environment file nor a .http file binds any. A secret goes
to its origins alone, and one bound to none goes nowhere: a request
that would send it elsewhere is not sent, unless a person at a terminal
confirms that request by name.

secrets.unattended is what a run without a person does with a request
that needs a secret value: "deny", the default, refuses it, exit code
6, and such a run holds no secret value at all; "keeper" sends it
through the keeper, a process in the person's terminal that holds the
values, sends the request, and gives back what the run may see.
secrets.keeper_asks is when the keeper asks its person: "always", the
default, before each request with a secret; "unbound" only before one
that would send a secret where it is not bound, or that runs a
{{$cmd NAME}}, which runs as the person. Whatever weakens these
is said here alone: no flag, variable or file can say it.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			pol, err := cfg.loadPolicy()
			if err != nil {
				return err
			}
			p := cfg.policyDoc(pol)
			if cfg.asJSON() {
				cfg.writeJSON(output.Document{SchemaVersion: output.SchemaVersion, Policy: p})
				return nil
			}
			fmt.Fprint(cfg.out, cfg.text(policyText(p)))
			return nil
		},
	}
}

// policyDoc returns pol as vegtam policy prints it, with what applies to
// a run in the mode of this one.
func (c *Config) policyDoc(pol *policy.Policy) *output.Policy {
	run := output.PolicyRun{Unattended: c.unattended(), Secrets: runSecrets(c.unattended(), pol)}
	run.ConfirmMutations = run.Unattended && pol.Network.ConfirmMutations()
	if proxy, _ := proxyOf(pol, run.Unattended, httpproxy.FromEnvironment(), "", nil); proxy != nil {
		run.HTTPSProxy, run.HTTPProxy, run.NoProxy = output.ProxyURL(proxy.HTTPSProxy), output.ProxyURL(proxy.HTTPProxy), proxy.NoProxy
	}
	return output.NewPolicy(pol, run)
}

// runSecrets returns what a run does with a request that needs a secret
// value, as output.PolicyRun.Secrets says, with pol, or with no policy
// that can be read if pol is nil.
func runSecrets(unattended bool, pol *policy.Policy) string {
	switch {
	case !unattended:
		return output.RunSecretsAll
	case pol != nil && pol.Secrets.Keeper():
		return output.RunSecretsKeeper
	}
	return output.RunSecretsNone
}

// policyText returns p as text.
func policyText(p *output.Policy) string {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	switch {
	case p.Path == "":
		fmt.Fprintln(tw, "policy\tnone: there is no place for it")
	case !p.Found:
		fmt.Fprintf(tw, "policy\t%s, not found: vegtam does what it does on its own\n", p.Path)
	default:
		fmt.Fprintf(tw, "policy\t%s\n", p.Path)
	}
	if l := p.Limits; l != nil {
		var parts []string
		for _, c := range []struct {
			name string
			ms   float64
		}{{"max time", l.MaxTimeMS}, {"read timeout", l.ReadMS}, {"connect timeout", l.ConnectMS}} {
			if c.ms > 0 {
				parts = append(parts, c.name+" at most "+core.FormatTimeout(msDuration(c.ms)))
			}
		}
		fmt.Fprintf(tw, "limits\t%s\n", strings.Join(parts, ", "))
	}
	if n := p.Network; n != nil {
		for _, row := range [][2]string{
			{"allow", strings.Join(n.Allow, ", ")},
			{"proxy", n.Proxy},
			{"proxy auth", n.ProxyAuth},
			{"no proxy", strings.Join(n.NoProxy, ", ")},
			{"insecure hosts", strings.Join(n.InsecureHosts, ", ")},
			{"resolve", strings.Join(n.Resolve, ", ")},
			{"connect to", strings.Join(n.ConnectTo, ", ")},
			{"unix sockets", strings.Join(n.UnixSockets, ", ")},
			{"confirm", n.Confirm},
		} {
			if row[1] != "" {
				fmt.Fprintf(tw, "%s\t%s\n", row[0], row[1])
			}
		}
	}
	for _, h := range p.Hosts {
		var parts []string
		for _, f := range [][2]string{{"cacert", h.CACert}, {"cert", h.Cert}, {"key", h.Key}} {
			if f[1] != "" {
				parts = append(parts, f[0]+" "+f[1])
			}
		}
		fmt.Fprintf(tw, "host %s\t%s\n", h.Host, strings.Join(parts, ", "))
	}
	secretRows(tw, p.Secrets)
	fmt.Fprintf(tw, "unattended\t%s\n", p.SecretsMode.Unattended)
	fmt.Fprintf(tw, "keeper asks\t%s\n", p.SecretsMode.KeeperAsks)
	tw.Flush()
	r := p.Run
	if r.Unattended {
		b.WriteString("\nThis run has no person at a terminal: loopback and private addresses only as network.allow names them.\n")
	} else {
		b.WriteString("\nThis run has a person at a terminal: loopback and private addresses are allowed.\n")
	}
	switch r.Secrets {
	case output.RunSecretsNone:
		b.WriteString("It gets no secret value: a request that needs one is not sent (secrets.unattended is \"deny\").\n")
	case output.RunSecretsKeeper:
		b.WriteString("A request that needs a secret value goes through the keeper, which asks its person; this run never sees the value.\n")
	}
	if r.ConfirmMutations {
		b.WriteString("A method other than GET, HEAD or OPTIONS, and a request with # @note, are sent only with --confirm.\n")
	} else {
		b.WriteString("Any method is sent without --confirm; a request with # @note only with it.\n")
	}
	switch {
	case r.HTTPSProxy == "" && r.HTTPProxy == "":
		b.WriteString("Requests go to no proxy.\n")
	case r.HTTPSProxy == r.HTTPProxy:
		fmt.Fprintf(&b, "Requests go through %s", r.HTTPSProxy)
	default:
		fmt.Fprintf(&b, "Requests to https URLs go through %s, to http URLs through %s", or(r.HTTPSProxy, "none"), or(r.HTTPProxy, "none"))
	}
	if r.HTTPSProxy != "" || r.HTTPProxy != "" {
		if r.NoProxy != "" {
			fmt.Fprintf(&b, ", but for %s", r.NoProxy)
		}
		b.WriteString(".\n")
	}
	fmt.Fprintf(&b, "Never connected to: %s.\n", strings.Join(p.Never, "; "))
	return b.String()
}

// secretRows writes a row to w for each secret that the policy binds,
// with the origins it may go to.
func secretRows(w io.Writer, secrets []output.Secret) {
	for _, s := range secrets {
		fmt.Fprintf(w, "secret %s\t%s\n", s.Name, or(strings.Join(s.Allowed, ", "), "bound to none: goes nowhere"))
	}
}

// msDuration returns ms milliseconds as a duration.
func msDuration(ms float64) time.Duration { return time.Duration(ms * float64(time.Millisecond)) }

// or returns s, or alt if s is "".
func or(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}
