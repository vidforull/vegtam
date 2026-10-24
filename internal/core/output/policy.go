package output

import (
	"maps"
	"net/url"
	"slices"

	"github.com/vidforull/vegtam/internal/core/netguard"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// Policy is the operator's policy as vegtam policy prints it: what its
// file says, and what of it applies to a run in the mode of this one. It
// holds no secret: the credentials of the proxy show as the variable that
// holds them, and the user and password of a proxy URL as ***.
type Policy struct {
	Path     string         `json:"path,omitempty"` // absent if there is no place for it
	Found    bool           `json:"found"`
	Limits   *PolicyLimits  `json:"limits,omitempty"`
	Network  *PolicyNetwork `json:"network,omitempty"`
	Hosts    []PolicyHost   `json:"hosts,omitempty"`
	Secrets  []Secret       `json:"secrets,omitempty"` // {{$env NAME}} and {{$cmd NAME}}, with the origins the policy binds them to
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
	ProxyAuth     string   `json:"proxy_auth,omitempty"` // "$env NAME"
	NoProxy       []string `json:"no_proxy,omitempty"`
	InsecureHosts []string `json:"insecure_hosts,omitempty"`
	Resolve       []string `json:"resolve,omitempty"`
	ConnectTo     []string `json:"connect_to,omitempty"`
	UnixSockets   []string `json:"unix_sockets,omitempty"`
	Confirm       string   `json:"confirm,omitempty"` // mutations or never, as written
}

// PolicyHost is the TLS of one origin.
type PolicyHost struct {
	Host   string `json:"host"`
	Origin string `json:"origin"`
	CACert string `json:"cacert,omitempty"`
	Cert   string `json:"cert,omitempty"`
	Key    string `json:"key,omitempty"`
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
	// ConfirmMutations is true when vegtam run sends a request whose
	// method is not GET, HEAD or OPTIONS only with --confirm.
	ConfirmMutations bool `json:"confirm_mutations"`
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
	if len(n.Allow) > 0 || n.Proxy != "" || len(n.NoProxy) > 0 || len(n.InsecureHosts) > 0 || len(n.Resolve) > 0 || len(n.ConnectTo) > 0 ||
		len(n.UnixSockets) > 0 || n.Confirm != "" {
		out.Network = &PolicyNetwork{Proxy: n.Proxy, NoProxy: n.NoProxy, InsecureHosts: n.InsecureHosts, UnixSockets: n.UnixSockets, Confirm: n.Confirm}
		for _, e := range n.Allow {
			out.Network.Allow = append(out.Network.Allow, e.String())
		}
		for _, r := range n.Resolve {
			out.Network.Resolve = append(out.Network.Resolve, r.String())
		}
		for _, c := range n.ConnectTo {
			out.Network.ConnectTo = append(out.Network.ConnectTo, c.String())
		}
		if n.ProxyAuth != "" {
			out.Network.ProxyAuth = "$env " + n.ProxyAuth
		}
	}
	for _, h := range p.Hosts {
		out.Hosts = append(out.Hosts, PolicyHost{Host: h.Name, Origin: h.Origin, CACert: h.CACert, Cert: h.Cert, Key: h.Key})
	}
	// By placeholder, those of {{$env NAME}} first; never a value.
	for _, c := range []struct {
		fn      string
		origins map[string][]string
	}{{"$env", p.Secrets.Env}, {"$cmd", p.Secrets.Cmd}} {
		for _, name := range slices.Sorted(maps.Keys(c.origins)) {
			out.Secrets = append(out.Secrets, Secret{Name: "{{" + c.fn + " " + name + "}}", Allowed: append([]string{}, c.origins[name]...)})
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
