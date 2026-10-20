package output

import (
	"net/url"

	"github.com/vidforull/vegtam/internal/core/netguard"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// Policy is the operator's policy as vegtam policy prints it: what its
// file says, and what of it applies to a run in the mode of this one. It
// holds no secret: the user and password of a proxy URL show as ***.
type Policy struct {
	Path     string         `json:"path,omitempty"` // absent if there is no place for it
	Found    bool           `json:"found"`
	Limits   *PolicyLimits  `json:"limits,omitempty"`
	Network  *PolicyNetwork `json:"network,omitempty"`
	Run      PolicyRun      `json:"run"`
	Never    []string       `json:"never"` // the addresses vegtam never connects to
	Warnings []Warning      `json:"warnings,omitempty"`
}

// PolicyLimits are the ceilings of the time limits, in milliseconds.
type PolicyLimits struct {
	MaxTimeMS float64 `json:"max_time_ceiling_ms,omitempty"`
	ReadMS    float64 `json:"read_timeout_ceiling_ms,omitempty"`
	ConnectMS float64 `json:"connect_timeout_ceiling_ms,omitempty"`
}

// PolicyNetwork is the network part of the policy, as written.
type PolicyNetwork struct {
	Allow         []string `json:"allow,omitempty"`
	Proxy         string   `json:"proxy,omitempty"`
	NoProxy       []string `json:"no_proxy,omitempty"`
	InsecureHosts []string `json:"insecure_hosts,omitempty"`
}

// PolicyRun is what applies to a run in the mode of this one.
type PolicyRun struct {
	// Unattended is true when no person is at a terminal: loopback and
	// private addresses only as network.allow names them, and no flag
	// that weakens a check beyond what the policy allows.
	Unattended bool   `json:"unattended"`
	HTTPSProxy string `json:"https_proxy,omitempty"` // for https URLs; absent for none
	HTTPProxy  string `json:"http_proxy,omitempty"`  // for http URLs
	NoProxy    string `json:"no_proxy,omitempty"`    // the hosts that go direct, as NO_PROXY writes them
}

// NewPolicy returns p as vegtam policy prints it, with run, what applies.
func NewPolicy(p *policy.Policy, run PolicyRun) *Policy {
	out := &Policy{Path: p.Path, Found: p.Found, Run: run, Never: never()}
	for _, w := range p.Warnings {
		out.Warnings = append(out.Warnings, Warning{Message: w})
	}
	if l := p.Limits; l != (policy.Limits{}) {
		out.Limits = &PolicyLimits{MaxTimeMS: ms(l.MaxTime), ReadMS: ms(l.Read), ConnectMS: ms(l.Connect)}
	}
	n := p.Network
	if len(n.Allow) > 0 || n.Proxy != "" || len(n.NoProxy) > 0 || len(n.InsecureHosts) > 0 {
		out.Network = &PolicyNetwork{Proxy: n.Proxy, NoProxy: n.NoProxy, InsecureHosts: n.InsecureHosts}
		for _, e := range n.Allow {
			out.Network.Allow = append(out.Network.Allow, e.String())
		}
	}
	return out
}

// never returns the addresses vegtam never connects to.
func never() []string {
	return append(netguard.Never(), "link-local addresses (169.254.0.0/16, fe80::/10)",
		"multicast addresses (224.0.0.0/4, ff00::/8)", "unspecified addresses (0.0.0.0/8, ::, 255.255.255.255)")
}

// ProxyURL returns the URL of a proxy as the environment writes it, with
// or without a scheme, with its user and password shown as ***; "" for
// none, and *** for one that does not parse.
func ProxyURL(s string) string {
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		if u, err = url.Parse("http://" + s); err != nil || u.Host == "" {
			return "***"
		}
	}
	return proxy(u, nil)
}
