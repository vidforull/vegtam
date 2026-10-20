package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
	Warnings []string // about the file itself
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
	Proxy   string
	NoProxy []string // hosts that bypass Proxy, as NO_PROXY writes them
	// InsecureHosts are the hosts, host:port, whose certificates --insecure
	// may leave unchecked without a person at a terminal.
	InsecureHosts []string
}

// ProxyEnvironment is the value of network.proxy that takes the proxy
// from the environment.
const ProxyEnvironment = "environment"

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
		NoProxy       []string `json:"no_proxy"`
		InsecureHosts []string `json:"insecure_hosts"`
	} `json:"network"`
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
		if err := p.network(n.Allow, n.Proxy, n.NoProxy, n.InsecureHosts); err != nil {
			return nil, fail("network.%v", err)
		}
	}
	return p, nil
}

// network sets the network of p from the fields of the file.
func (p *Policy) network(allow []string, proxy string, noProxy, insecure []string) error {
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
	for _, s := range noProxy {
		if s == "" || strings.ContainsAny(s, ", \t") {
			return fmt.Errorf("no_proxy: %q: want one host, domain or prefix for each entry", s)
		}
		n.NoProxy = append(n.NoProxy, s)
	}
	for _, s := range insecure {
		hp, err := hostPort(s)
		if err != nil {
			return fmt.Errorf("insecure_hosts: %w", err)
		}
		n.InsecureHosts = append(n.InsecureHosts, hp)
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
		return errors.New("the URL holds a user or password, which is never written there")
	case u.Hostname() == "", u.Path != "" && u.Path != "/", u.RawQuery != "", u.Fragment != "":
		return fmt.Errorf("%q: want a scheme, a host and a port, and nothing more", s)
	}
	return nil
}

// hostPort returns s, host:port, with the host in lower case and without
// a final dot, as exec writes the host of an origin.
func hostPort(s string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	n, perr := strconv.ParseUint(port, 10, 16)
	name := netguard.Name(host)
	if ip := net.ParseIP(host); ip != nil {
		name = ip.String()
	}
	if err != nil || perr != nil || n == 0 || name == "" {
		return "", fmt.Errorf("%q: want host:port, such as api.example:443", s)
	}
	return net.JoinHostPort(name, port), nil
}
