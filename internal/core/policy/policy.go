package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/netguard"
)

// Policy is what the operator allows vegtam beyond what it does on its
// own, and the limits they hold it to: the file policy.json in vegtam's
// configuration directory, beside the trust store. It is read from there
// alone, never from a directory of .http files nor from the current one:
// whoever writes it decides what vegtam does without a person at a
// terminal. Every field may be left out.
type Policy struct {
	Path     string // the file, found or not; "" if there is no place for it
	Found    bool
	Limits   Limits
	Network  Network
	Hosts    []Host // by origin
	Secrets  Secrets
	Warnings []string // about the file itself
}

// Secrets are the origins that the values of {{$env NAME}} and
// {{$cmd NAME}} may go to, by NAME, each as core.Origin writes it. A
// value whose NAME they leave out goes nowhere, unless the private
// environment file binds it ($allow).
type Secrets struct {
	Env map[string][]string // by environment variable
	Cmd map[string][]string // by command, of any command file
}

// Limits are ceilings on the time limits of a request: on the flags, and
// so on the directives of a file, which may only lower those. 0 is none.
type Limits struct {
	MaxTime, Read, Connect time.Duration
}

// Network is how and where connections go.
type Network struct {
	// Allow are the loopback and private addresses that a run without a
	// person at a terminal may connect to.
	Allow []netguard.Entry
	// Proxy is the proxy of every request, a URL; ProxyEnvironment for
	// the environment's (HTTPS_PROXY, HTTP_PROXY, NO_PROXY); "" for none
	// without a person at a terminal, and the environment's with one.
	Proxy string
	// ProxyAuth names the environment variable that holds the user and
	// password of the proxy, as user:password; "" for none.
	ProxyAuth string
	NoProxy   []string // hosts that bypass Proxy, as NO_PROXY writes them
	// InsecureHosts are the hosts, host:port, whose certificates --insecure
	// may leave unchecked without a person at a terminal.
	InsecureHosts []string
	// Resolve and ConnectTo are the --resolve and --connect-to that a run
	// without a person at a terminal may give.
	Resolve   []netguard.Resolve
	ConnectTo []netguard.ConnectTo
	// UnixSockets are the sockets that --unix-socket may name without a
	// person at a terminal: absolute paths, and "@name" for those of
	// --abstract-unix-socket.
	UnixSockets []string
	// Confirm is which requests a run without a person at a terminal
	// sends only with --confirm: ConfirmMutations, the default, or
	// ConfirmNever; "" if the file does not say.
	Confirm string
}

// ProxyEnvironment is the value of network.proxy that takes the proxy
// from the environment.
const ProxyEnvironment = "environment"

// The values of network.confirm.
const (
	// ConfirmMutations: a request whose method is not GET, HEAD or OPTIONS
	// needs --confirm.
	ConfirmMutations = "mutations"
	// ConfirmNever: any method goes without --confirm, for an operator who
	// trusts what runs vegtam. A request with an @note still needs it.
	ConfirmNever = "never"
)

// ConfirmMutations reports whether a run without a person at a terminal
// sends a request whose method is not GET, HEAD or OPTIONS only with
// --confirm.
func (n Network) ConfirmMutations() bool { return n.Confirm != ConfirmNever }

// Host is the TLS of one origin: CAs trusted for it alone, on top of the
// system's, and a client certificate offered to it alone. The paths are
// absolute.
type Host struct {
	Origin string // https://host:port
	Name   string // as the file writes it
	CACert string
	Cert   string
	Key    string // "" if in Cert
}

// PolicyFile is the name of the policy's file, in vegtam's configuration
// directory.
const PolicyFile = "policy.json"

// maxPolicy is the most bytes of the file that are read.
const maxPolicy = 1 << 20

// Load reads the policy from $XDG_CONFIG_HOME/vegtam/policy.json, or from
// ~/.config/vegtam/policy.json if XDG_CONFIG_HOME is not set. With no
// file, or no place for one, the policy is empty: vegtam does what it does
// on its own.
func Load() (*Policy, error) {
	dir, err := xdgDir("XDG_CONFIG_HOME", ".config")
	if err != nil {
		return &Policy{Warnings: []string{fmt.Sprintf("no policy file: %v", err)}}, nil
	}
	return LoadFile(filepath.Join(dir, PolicyFile))
}

// LoadFile reads the policy from the file at path. A file that others can
// change, or in a directory they can, is refused: it would decide what
// vegtam does. So is one that does not parse: its limits would be lost.
func LoadFile(path string) (*Policy, error) {
	p := &Policy{Path: path}
	fail := func(format string, args ...any) error {
		return core.Errorf(core.KindPolicy, core.Source{File: path}, format, args...)
	}
	// Through an os.Root of its directory, as the trust store: the
	// directory checked must be the one the file is in.
	dir, name := filepath.Split(path)
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	} else if err != nil {
		return nil, fail("%v", err)
	}
	defer root.Close()
	// The directory first: whoever can write it could put anything in the
	// file's place between the checks below and the open.
	if derr := checkDir(root, filepath.Dir(path), "it is not read", fail); derr != nil {
		return nil, derr
	}
	// A named pipe would block the open until something writes to it.
	if fi, serr := root.Stat(name); errors.Is(serr, fs.ErrNotExist) {
		return p, nil
	} else if serr != nil {
		return nil, fail("%v", serr)
	} else if !fi.Mode().IsRegular() {
		return nil, fail("not a regular file")
	}
	f, err := root.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	} else if err != nil {
		return nil, fail("%v", err)
	}
	b, warnings, err := readPolicy(f, path, fail)
	if cerr := f.Close(); err == nil && cerr != nil {
		err = fail("%v", cerr)
	}
	if err != nil {
		return nil, err
	}
	if p, err = Parse(path, b); err != nil {
		return nil, err
	}
	p.Warnings = warnings
	return p, nil
}

// readPolicy reads the file f once its owner and modes are checked.
func readPolicy(f *os.File, path string, fail func(string, ...any) error) ([]byte, []string, error) {
	fi, err := f.Stat()
	switch {
	case err != nil:
		return nil, nil, fail("%v", err)
	case !fi.Mode().IsRegular():
		return nil, nil, fail("not a regular file")
	case !ownedByUser(fi):
		return nil, nil, fail("it belongs to another user, so it is not read")
	case fi.Mode().Perm()&0o022 != 0:
		return nil, nil, fail("others can write it, so it is not read; make it private: chmod 600 %s", path)
	}
	var warnings []string
	if fi.Mode().Perm()&0o044 != 0 {
		warnings = append(warnings, fmt.Sprintf("%s: others can read the policy; it holds no secret, but says what vegtam may do: chmod 600 %s", path, path))
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPolicy+1))
	switch {
	case err != nil:
		return nil, nil, fail("%v", err)
	case len(b) > maxPolicy:
		return nil, nil, fail("larger than %d bytes", maxPolicy)
	}
	return b, warnings, nil
}

// checkDir refuses dir, opened as root, if it belongs to another user or
// others can write it: so, as then says, the file in it is not taken.
func checkDir(root *os.Root, dir, then string, fail func(string, ...any) error) error {
	di, err := root.Stat(".")
	switch {
	case err != nil:
		return fail("%v", err)
	case !ownedByUser(di):
		return fail("its directory belongs to another user, so %s", then)
	case di.Mode().Perm()&0o022 != 0:
		return fail("others can write its directory, so %s; make it private: chmod 700 %s", then, dir)
	}
	return nil
}

// file is the layout of the policy's file.
type file struct {
	Limits *struct {
		MaxTime string `json:"max_time_ceiling"`
		Read    string `json:"read_timeout_ceiling"`
		Connect string `json:"connect_timeout_ceiling"`
	} `json:"limits"`
	Network *struct {
		Allow         []string `json:"allow"`
		Proxy         string   `json:"proxy"`
		ProxyAuth     string   `json:"proxy_auth"`
		NoProxy       []string `json:"no_proxy"`
		InsecureHosts []string `json:"insecure_hosts"`
		Resolve       []string `json:"resolve"`
		ConnectTo     []string `json:"connect_to"`
		UnixSockets   []string `json:"unix_sockets"`
		Confirm       string   `json:"confirm"`
	} `json:"network"`
	Hosts   map[string]fileHost `json:"hosts"`
	Secrets fileSecrets         `json:"secrets"`
}

// fileHost is the TLS of one host in the policy's file.
type fileHost struct {
	CACert string `json:"cacert"`
	Cert   string `json:"cert"`
	Key    string `json:"key"`
}

// fileSecrets are the origins that the values of {{$env NAME}} and
// {{$cmd NAME}} may go to, by NAME, in the policy's file:
// {"env": {"API_TOKEN": ["https://api.example.com"]}, "cmd": {"TOKEN": [...]}}.
type fileSecrets struct {
	Env map[string][]string `json:"env"`
	Cmd map[string][]string `json:"cmd"`
}

// Parse parses b, the contents of the policy file at path.
func Parse(path string, b []byte) (*Policy, error) {
	p := &Policy{Path: path, Found: true}
	fail := func(format string, args ...any) error {
		return core.Errorf(core.KindPolicy, core.Source{File: path}, format, args...)
	}
	var f file
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fail("%v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fail("data after the policy")
	}
	if l := f.Limits; l != nil {
		for _, c := range []struct {
			name, value string
			to          *time.Duration
		}{{"max_time_ceiling", l.MaxTime, &p.Limits.MaxTime}, {"read_timeout_ceiling", l.Read, &p.Limits.Read}, {"connect_timeout_ceiling", l.Connect, &p.Limits.Connect}} {
			if c.value == "" {
				continue
			}
			d, err := core.ParseTimeout(c.value)
			switch {
			case err != nil:
				return nil, fail("limits.%s %q: %v", c.name, c.value, err)
			case d == 0:
				return nil, fail("limits.%s %q: a ceiling of none is no ceiling; leave it out", c.name, c.value)
			}
			*c.to = d
		}
	}
	if n := f.Network; n != nil {
		if err := p.network(n.Allow, n.Proxy, n.ProxyAuth, n.NoProxy, n.InsecureHosts); err != nil {
			return nil, fail("network.%v", err)
		}
		if err := p.routes(n.Resolve, n.ConnectTo); err != nil {
			return nil, fail("network.%v", err)
		}
		for _, s := range n.UnixSockets {
			if name, ok := strings.CutPrefix(s, "@"); ok && name != "" {
				p.Network.UnixSockets = append(p.Network.UnixSockets, s)
				continue
			}
			path, err := expand(s)
			if err != nil {
				return nil, fail("network.unix_sockets: %v; or @name for an abstract one", err)
			}
			p.Network.UnixSockets = append(p.Network.UnixSockets, path)
		}
		switch n.Confirm {
		case "", ConfirmMutations, ConfirmNever:
			p.Network.Confirm = n.Confirm
		default:
			return nil, fail("network.confirm %q: want %q, the default, or %q", n.Confirm, ConfirmMutations, ConfirmNever)
		}
	}
	if err := p.hosts(f.Hosts); err != nil {
		return nil, fail("hosts.%v", err)
	}
	if err := p.secrets(f.Secrets.Env, f.Secrets.Cmd); err != nil {
		return nil, fail("secrets.%v", err)
	}
	return p, nil
}

// hosts sets the hosts of p from the field of the file, in the order of
// their names.
func (p *Policy) hosts(hosts map[string]fileHost) error {
	for _, name := range slices.Sorted(maps.Keys(hosts)) {
		h := hosts[name]
		host, err := p.host(name, h.CACert, h.Cert, h.Key)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		p.Hosts = append(p.Hosts, host)
	}
	return nil
}

var envVar = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// secrets sets the secrets of p from the fields of the file; a field
// left out binds none.
func (p *Policy) secrets(env, cmd map[string][]string) error {
	for _, c := range []struct {
		field string
		from  map[string][]string
		to    *map[string][]string
		valid func(string) bool
		want  string
	}{
		{"env", env, &p.Secrets.Env, envVar.MatchString, "the name of an environment variable, such as API_TOKEN"},
		{"cmd", cmd, &p.Secrets.Cmd, core.IsVarName, "the name of a command of a command file, such as TOKEN"},
	} {
		for _, name := range slices.Sorted(maps.Keys(c.from)) {
			if !c.valid(name) {
				return fmt.Errorf("%s: %q: want %s", c.field, name, c.want)
			}
			origins, err := parseOrigins(c.from[name])
			if err != nil {
				return fmt.Errorf("%s.%s: %w", c.field, name, err)
			}
			if *c.to == nil {
				*c.to = map[string][]string{}
			}
			(*c.to)[name] = origins
		}
	}
	return nil
}

// parseOrigins returns list, origins as a person writes them, as
// core.Origin writes them, sorted and each once.
func parseOrigins(list []string) ([]string, error) {
	origins := make([]string, 0, len(list))
	for _, s := range list {
		o, err := core.ParseOrigin(s)
		if err != nil {
			return nil, err
		}
		origins = append(origins, o)
	}
	slices.Sort(origins)
	return slices.Compact(origins), nil
}

var envName = regexp.MustCompile(`^\$env ([A-Za-z_][A-Za-z0-9_]*)$`)

// EnvRef returns the name of the environment variable that s, "$env
// NAME", names, as network.proxy_auth and --proxy-auth do.
func EnvRef(s string) (string, bool) {
	m := envName.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// network sets the network of p from the fields of the file.
func (p *Policy) network(allow []string, proxy, auth string, noProxy, insecure []string) error {
	n := &p.Network
	for _, s := range allow {
		e, err := netguard.ParseEntry(s)
		if err != nil {
			return fmt.Errorf("allow: %w", err)
		}
		n.Allow = append(n.Allow, e)
	}
	if proxy != "" && proxy != ProxyEnvironment {
		if err := CheckProxy(proxy); err != nil {
			return fmt.Errorf("proxy: %w; or %q for the environment's", err, ProxyEnvironment)
		}
	}
	n.Proxy = proxy
	if auth != "" {
		name, ok := EnvRef(auth)
		switch {
		case !ok:
			return fmt.Errorf("proxy_auth: want \"$env NAME\", an environment variable that holds user:password; the credentials are never written in the policy")
		case proxy == "":
			return fmt.Errorf("proxy_auth without a proxy")
		case proxy == ProxyEnvironment:
			return fmt.Errorf("proxy_auth goes with the policy's proxy, a URL, not the environment's, which whoever sets the environment chooses")
		}
		n.ProxyAuth = name
	}
	for _, s := range noProxy {
		if s == "" || strings.ContainsAny(s, ", \t") {
			return fmt.Errorf("no_proxy: %q: want one host, domain or prefix for each entry", s)
		}
		n.NoProxy = append(n.NoProxy, s)
	}
	for _, s := range insecure {
		hp, err := hostPort(s, "")
		if err != nil {
			return fmt.Errorf("insecure_hosts: %w", err)
		}
		n.InsecureHosts = append(n.InsecureHosts, hp)
	}
	return nil
}

// routes sets the routes of p from the fields of the file.
func (p *Policy) routes(resolve, connectTo []string) error {
	n := &p.Network
	for _, s := range resolve {
		r, err := netguard.ParseResolve(s)
		if err != nil {
			return fmt.Errorf("resolve: %w", err)
		}
		n.Resolve = append(n.Resolve, r)
	}
	for _, s := range connectTo {
		c, err := netguard.ParseConnectTo(s)
		if err != nil {
			return fmt.Errorf("connect_to: %w", err)
		}
		n.ConnectTo = append(n.ConnectTo, c)
	}
	return nil
}

// CheckProxy checks the URL of a proxy, as the policy or a flag gives it:
// http, https, socks5 or socks5h, with a host and nothing after it. Its
// user and password are refused: they would be written in a file, or in
// the arguments of a command, which other processes can read.
func CheckProxy(s string) error {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return fmt.Errorf("%q is no URL", s)
	case u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h":
		return fmt.Errorf("%q: want an http, https, socks5 or socks5h URL, such as http://proxy.example:3128", s)
	case u.User != nil:
		return errors.New("the URL holds a user or password, which is never written there: name an environment variable that holds them, \"$env NAME\"")
	case u.Hostname() == "", u.Path != "" && u.Path != "/", u.RawQuery != "", u.Fragment != "":
		return fmt.Errorf("%q: want a scheme, a host and a port, and nothing more", s)
	}
	return nil
}

// host returns the TLS of the host name, host or host:port, from the
// paths of the file.
func (p *Policy) host(name, ca, cert, key string) (Host, error) {
	hp, err := hostPort(name, "443")
	if err != nil {
		return Host{}, err
	}
	h := Host{Origin: "https://" + hp, Name: name}
	switch {
	case key != "" && cert == "":
		return Host{}, errors.New("key needs cert")
	case ca == "" && cert == "":
		return Host{}, errors.New("give cacert, or cert, or both")
	}
	for _, f := range []struct {
		name, path string
		to         *string
	}{{"cacert", ca, &h.CACert}, {"cert", cert, &h.Cert}, {"key", key, &h.Key}} {
		if f.path == "" {
			continue
		}
		if *f.to, err = expand(f.path); err != nil {
			return Host{}, fmt.Errorf("%s: %w", f.name, err)
		}
	}
	return h, nil
}

// hostPort returns s, host:port, with the host in lower case and without
// a final dot; with a port of def if s has none and def is not "".
func hostPort(s, def string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil && def != "" {
		host, port, err = s, def, nil
	}
	n, perr := strconv.ParseUint(port, 10, 16)
	name := netguard.Name(strings.Trim(host, "[]"))
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		name = ip.String()
	}
	if err != nil || perr != nil || n == 0 || name == "" {
		return "", fmt.Errorf("%q: want host:port, such as api.example:443", s)
	}
	return net.JoinHostPort(name, port), nil
}

// expand returns path, absolute or under the home directory as ~/path.
func expand(path string) (string, error) {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, rest), nil
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%q: want an absolute path, or ~/path for one in the home directory", path)
	}
	return filepath.Clean(path), nil
}

// HostFor returns the TLS of the policy for origin, if it has one.
func (p *Policy) HostFor(origin string) (Host, bool) {
	i := slices.IndexFunc(p.Hosts, func(h Host) bool { return h.Origin == origin })
	if i < 0 {
		return Host{}, false
	}
	return p.Hosts[i], true
}
