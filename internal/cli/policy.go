package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/http/httpproxy"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
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
                "proxy": "http://proxy.example:3128", "no_proxy": ["localhost"],
                "insecure_hosts": ["dev.example:8443"]}
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
network.insecure_hosts.

network.proxy is the proxy of every request, or "environment" for that
of HTTPS_PROXY, HTTP_PROXY and NO_PROXY; without it, a person's run uses
the environment's, and a run with no person none. The proxy's user and
password are never written in the policy. no_proxy lists hosts that go
direct. Through a proxy, the target of each request is checked here, as
the connection would be, before the proxy gets it.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			pol, err := cfg.loadPolicy()
			if err != nil {
				return err
			}
			run := output.PolicyRun{Unattended: cfg.unattended()}
			if proxy, _ := proxyOf(pol, run.Unattended, httpproxy.FromEnvironment()); proxy != nil {
				run.HTTPSProxy, run.HTTPProxy, run.NoProxy = output.ProxyURL(proxy.HTTPSProxy), output.ProxyURL(proxy.HTTPProxy), proxy.NoProxy
			}
			p := output.NewPolicy(pol, run)
			if cfg.asJSON() {
				cfg.writeJSON(output.Document{SchemaVersion: output.SchemaVersion, Policy: p})
				return nil
			}
			fmt.Fprint(cfg.out, cfg.text(policyText(p)))
			return nil
		},
	}
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
			{"no proxy", strings.Join(n.NoProxy, ", ")},
			{"insecure hosts", strings.Join(n.InsecureHosts, ", ")},
		} {
			if row[1] != "" {
				fmt.Fprintf(tw, "%s\t%s\n", row[0], row[1])
			}
		}
	}
	tw.Flush()
	r := p.Run
	if r.Unattended {
		b.WriteString("\nThis run has no person at a terminal: loopback and private addresses only as network.allow names them.\n")
	} else {
		b.WriteString("\nThis run has a person at a terminal: loopback and private addresses are allowed.\n")
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

// msDuration returns ms milliseconds as a duration.
func msDuration(ms float64) time.Duration { return time.Duration(ms * float64(time.Millisecond)) }

// or returns s, or alt if s is "".
func or(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}
