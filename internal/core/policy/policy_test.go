package policy

import (
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/netguard"
)

// The policy of the task's example, all of it.
const fullPolicy = `{
  "limits":  {"max_time_ceiling": "5m", "read_timeout_ceiling": "2m", "connect_timeout_ceiling": "30s"},
  "network": {"allow": ["127.0.0.1:8080", "localhost:3000", "10.0.0.0/8"], "proxy": "http://proxy.example:3128",
              "proxy_auth": "$env PROXY_AUTH", "no_proxy": ["localhost"], "insecure_hosts": ["Dev.Example.:8443"]},
  "hosts":   {"api.internal.example:443": {"cacert": "~/certs/corp.pem", "cert": "/certs/me.pem", "key": "/certs/me.key"},
              "ca.example": {"cacert": "/certs/ca.pem"}}
}`

func TestParse(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse("policy.json", []byte(fullPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Found || p.Limits != (Limits{MaxTime: 5 * time.Minute, Read: 2 * time.Minute, Connect: 30 * time.Second}) {
		t.Errorf("limits %+v", p.Limits)
	}
	n := p.Network
	var allow []string
	for _, e := range n.Allow {
		allow = append(allow, e.String())
	}
	if strings.Join(allow, " ") != "127.0.0.1:8080 localhost:3000 10.0.0.0/8" || n.Proxy != "http://proxy.example:3128" || n.ProxyAuth != "PROXY_AUTH" ||
		strings.Join(n.NoProxy, " ") != "localhost" || strings.Join(n.InsecureHosts, " ") != "dev.example:8443" {
		t.Errorf("network %+v", n)
	}
	want := []Host{
		{Origin: "https://api.internal.example:443", Name: "api.internal.example:443", CACert: filepath.Join(home, "certs", "corp.pem"), Cert: "/certs/me.pem", Key: "/certs/me.key"},
		{Origin: "https://ca.example:443", Name: "ca.example", CACert: "/certs/ca.pem"},
	}
	if len(p.Hosts) != 2 || p.Hosts[0] != want[0] || p.Hosts[1] != want[1] {
		t.Errorf("hosts %+v; want %+v", p.Hosts, want)
	}
	if h, ok := p.HostFor("https://ca.example:443"); !ok || h != want[1] {
		t.Errorf("HostFor = %+v, %v", h, ok)
	}
	if _, ok := p.HostFor("https://other.example:443"); ok {
		t.Error("HostFor found a host the policy does not name")
	}
	if p, err := Parse("policy.json", []byte(`{"network": {"unix_sockets": ["/var/run/docker.sock", "~/run/api.sock", "@vegtam"]}}`)); err != nil ||
		strings.Join(p.Network.UnixSockets, " ") != "/var/run/docker.sock "+filepath.Join(home, "run", "api.sock")+" @vegtam" {
		t.Errorf("unix_sockets: %+v, %v", p, err)
	}
	for in, want := range map[string]bool{`{}`: true, `{"network": {"confirm": "mutations"}}`: true, `{"network": {"confirm": "never"}}`: false} {
		if p, err := Parse("policy.json", []byte(in)); err != nil || p.Network.ConfirmMutations() != want {
			t.Errorf("%s: ConfirmMutations() = %v, %v; want %v", in, p.Network.ConfirmMutations(), err, want)
		}
	}
	for _, other := range []string{`{}`, `{"limits": {}, "network": {}}`, `{"network": {"proxy": "environment", "insecure_hosts": ["[::1]:8443"]}}`} {
		if p, err := Parse("policy.json", []byte(other)); err != nil || p.Limits != (Limits{}) || len(p.Network.Allow) != 0 {
			t.Errorf("%s: %+v, %v", other, p, err)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for in, want := range map[string]string{
		``:                          "EOF",
		`[]`:                        "cannot unmarshal array",
		`{} {}`:                     "data after the policy",
		`{"limit": {}}`:             `unknown field "limit"`,
		`{"network": {"alow": []}}`: `unknown field "alow"`,
		`{"limits": {"max_time_ceiling": "soon"}}`:                            `limits.max_time_ceiling "soon": want a time`,
		`{"limits": {"read_timeout_ceiling": "0"}}`:                           "a ceiling of none is no ceiling",
		`{"network": {"allow": ["localhost"]}}`:                               "network.allow: \"localhost\": name the port too",
		`{"network": {"proxy": "proxy.example:3128"}}`:                        "network.proxy: \"proxy.example:3128\": want an http, https, socks5 or socks5h URL",
		`{"network": {"proxy": "ftp://proxy.example"}}`:                       "want an http, https, socks5 or socks5h URL",
		`{"network": {"proxy": "http://u:p@proxy.example"}}`:                  "holds a user or password",
		`{"network": {"proxy": "http://proxy.example/x"}}`:                    "nothing more",
		`{"network": {"proxy": "http://"}}`:                                   "nothing more",
		`{"network": {"no_proxy": ["a,b"]}}`:                                  "no_proxy: \"a,b\": want one host",
		`{"network": {"insecure_hosts": ["dev.example"]}}`:                    "insecure_hosts: \"dev.example\": want host:port",
		`{"network": {"insecure_hosts": ["dev.example:0"]}}`:                  "want host:port",
		`{"network": {"proxy": "http://p", "proxy_auth": "u:p"}}`:             "proxy_auth: want \"$env NAME\"",
		`{"network": {"proxy": "http://p", "proxy_auth": "$env 1"}}`:          "proxy_auth: want",
		`{"network": {"proxy_auth": "$env AUTH"}}`:                            "proxy_auth without a proxy",
		`{"network": {"proxy": "environment", "proxy_auth": "$env AUTH"}}`:    "proxy_auth goes with the policy's proxy, a URL",
		`{"hosts": {"api.example": {}}}`:                                      "hosts.api.example: give cacert, or cert, or both",
		`{"hosts": {"api.example": {"key": "/k"}}}`:                           "key needs cert",
		`{"hosts": {"api.example": {"cacert": "certs/ca.pem"}}}`:              `cacert: "certs/ca.pem": want an absolute path`,
		`{"hosts": {"api.example:0": {"cacert": "/ca.pem"}}}`:                 "want host:port",
		`{"hosts": {"http://api.example": {"cacert": "/ca.pem"}}}`:            "want host:port",
		`{"hosts": {"api.example": {"cacert": "/ca.pem", "pass": "x"}}}`:      `unknown field "pass"`,
		`{"network": {"unix_sockets": ["api.sock"]}}`:                         `network.unix_sockets: "api.sock": want an absolute path`,
		`{"network": {"unix_sockets": ["@"]}}`:                                `network.unix_sockets: "@": want an absolute path`,
		`{"network": {"confirm": "always"}}`:                                  `network.confirm "always": want "mutations", the default, or "never"`,
		`{"network": {"confirm": "Never"}}`:                                   `network.confirm "Never"`,
		`{"network": {"confirm": true}}`:                                      "cannot unmarshal bool",
		`{"secrets": {"env": {"API_TOKEN": ["api.example.com"]}}}`:            `secrets.env.API_TOKEN: "api.example.com": want an origin, such as https://api.example.com`,
		`{"secrets": {"env": {"API_TOKEN": ["https://api.example.com/v1"]}}}`: `secrets.env.API_TOKEN: "https://api.example.com/v1": want an origin`,
		`{"secrets": {"env": {"API_TOKEN": ["https://u@api.example.com"]}}}`:  `secrets.env.API_TOKEN: "https://u@api.example.com": want an origin`,
		`{"secrets": {"env": {"API_TOKEN": ["https://api.example.com:0"]}}}`:  `secrets.env.API_TOKEN: "https://api.example.com:0": want an origin`,
		`{"secrets": {"cmd": {"TOKEN": ["https://*.example.com"]}}}`:          `secrets.cmd.TOKEN: "https://*.example.com": a secret goes to origins named one by one; a wildcard names none`,
		`{"secrets": {"cmd": {"TOKEN": ["*"]}}}`:                              `secrets.cmd.TOKEN: "*": want an origin`,
		`{"secrets": {"env": {"1X": []}}}`:                                    `secrets.env: "1X": want the name of an environment variable, such as API_TOKEN`,
		`{"secrets": {"env": {"a.b": []}}}`:                                   `secrets.env: "a.b": want the name of an environment variable`,
		`{"secrets": {"env": {"$env A": []}}}`:                                `secrets.env: "$env A": want the name of an environment variable`,
		`{"secrets": {"cmd": {"x y": []}}}`:                                   `secrets.cmd: "x y": want the name of a command of a command file, such as TOKEN`,
		`{"secrets": {"cmd": {"": []}}}`:                                      `secrets.cmd: "": want the name of a command`,
		`{"secrets": {"env": {"A": "https://api.example.com"}}}`:              "cannot unmarshal string",
		`{"secrets": {"env": ["A"]}}`:                                         "cannot unmarshal array",
		`{"secrets": {"vars": {}}}`:                                           `unknown field "vars"`,
		`{"secrets": {"unattended": "allow"}}`:                                `secrets.unattended "allow": want "deny", the default, or "keeper"`,
		`{"secrets": {"unattended": "Deny"}}`:                                 `secrets.unattended "Deny": want "deny"`,
		`{"secrets": {"unattended": true}}`:                                   "cannot unmarshal bool",
		`{"secrets": {"keeper_asks": "never"}}`:                               `secrets.keeper_asks "never": want "always", the default, or "unbound"`,
	} {
		_, err := Parse("policy.json", []byte(in))
		if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != core.KindPolicy || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v; want a policy error with %q", in, err, want)
		}
	}
}

// TestParseSecrets checks that secrets binds each NAME to its origins, as
// core.Origin writes them, sorted and each once.
func TestParseSecrets(t *testing.T) {
	p, err := Parse("policy.json", []byte(secretsPolicy))
	if err != nil {
		t.Fatal(err)
	}
	want := Secrets{
		Env: map[string][]string{"API_TOKEN": {"http://127.0.0.1:8080", "https://api.example.com"}, "NOWHERE": {}, "_x1": {"http://[::1]"}},
		Cmd: map[string][]string{"TOKEN": {"https://auth.example.com:8443"}, "my.token-2": {"https://api.example.com"}},
	}
	if !maps.EqualFunc(p.Secrets.Env, want.Env, slices.Equal) || !maps.EqualFunc(p.Secrets.Cmd, want.Cmd, slices.Equal) {
		t.Errorf("secrets %q\nwant    %q", p.Secrets, want)
	}
	for _, in := range []string{`{}`, `{"secrets": {}}`, `{"secrets": null}`, `{"secrets": {"env": {}, "cmd": null}}`} {
		if p, err := Parse("policy.json", []byte(in)); err != nil || p.Secrets.Env != nil || p.Secrets.Cmd != nil {
			t.Errorf("%s: %+v, %v; want no secrets", in, p, err)
		}
	}
}

// TestParseUnattended checks secrets.unattended and secrets.keeper_asks,
// and that their defaults are the strict ones: no secret without a person,
// and a keeper that asks each time.
func TestParseUnattended(t *testing.T) {
	for in, want := range map[string]Secrets{
		`{}`:                                                 {},
		`{"secrets": {"unattended": "deny"}}`:                {Unattended: UnattendedDeny},
		`{"secrets": {"unattended": "keeper"}}`:              {Unattended: UnattendedKeeper},
		`{"secrets": {"keeper_asks": "always"}}`:             {KeeperAsks: KeeperAsksAlways},
		`{"secrets": {"keeper_asks": "unbound"}}`:            {KeeperAsks: KeeperAsksUnbound},
		`{"secrets": {"unattended": "", "keeper_asks": ""}}`: {},
	} {
		p, err := Parse("policy.json", []byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if p.Secrets.Unattended != want.Unattended || p.Secrets.KeeperAsks != want.KeeperAsks {
			t.Errorf("%s: %q, %q; want %q, %q", in, p.Secrets.Unattended, p.Secrets.KeeperAsks, want.Unattended, want.KeeperAsks)
		}
		if keeper := want.Unattended == UnattendedKeeper; p.Secrets.Keeper() != keeper {
			t.Errorf("%s: Keeper() = %v", in, !keeper)
		}
		if always := want.KeeperAsks != KeeperAsksUnbound; p.Secrets.AsksAlways() != always {
			t.Errorf("%s: AsksAlways() = %v", in, !always)
		}
	}
}

// secretsPolicy binds secrets of both kinds.
const secretsPolicy = `{"secrets": {
  "env": {"API_TOKEN": ["https://API.example.com:443/", "https://api.example.com", "http://127.0.0.1:8080"], "NOWHERE": [], "_x1": ["http://[::1]:80"]},
  "cmd": {"TOKEN": ["https://auth.example.com.:8443"], "my.token-2": ["https://api.example.com/"]}
}}`

// configDir returns a directory for policy.json, private as vegtam wants
// it: t.TempDir is group-writable where the umask is 0002.
func configDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vegtam")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadFile(t *testing.T) {
	dir := configDir(t)
	path := filepath.Join(dir, PolicyFile)
	if p, err := LoadFile(path); err != nil || p.Found || p.Path != path {
		t.Errorf("no file: %+v, %v", p, err)
	}
	if p, err := LoadFile(filepath.Join(dir, "none", PolicyFile)); err != nil || p.Found {
		t.Errorf("no directory: %+v, %v", p, err)
	}
	if err := os.WriteFile(path, []byte(`{"network": {"allow": ["127.0.0.1"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadFile(path)
	if err != nil || !p.Found || len(p.Network.Allow) != 1 || p.Warnings != nil {
		t.Errorf("a private file: %+v, %v", p, err)
	}
	if err = os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if p, err = LoadFile(path); err != nil || len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "others can read the policy") {
		t.Errorf("a file others can read: %+v, %v", p, err)
	}
	for _, c := range []struct {
		file, dir os.FileMode
		want      string
	}{
		{0o664, 0o700, "others can write it, so it is not read; make it private: chmod 600"},
		{0o602, 0o700, "others can write it"},
		{0o600, 0o770, "others can write its directory, so it is not read; make it private: chmod 700"},
	} {
		if err := os.Chmod(path, c.file); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, c.dir); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%o in %o: %v; want %q", c.file, c.dir, err, c.want)
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"network": {"allow": ["nowhere"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), path+": network.allow") {
		t.Errorf("a file that does not parse: %v; want the error to name it", err)
	}
	// A symbolic link that leads out of the directory is refused, as the
	// trust store refuses it.
	other := filepath.Join(configDir(t), "elsewhere.json")
	if err := os.WriteFile(other, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Error("a link out of the directory was followed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: %v", err)
	}
}

func TestLoad(t *testing.T) {
	dir := configDir(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Dir(dir))
	if err := os.WriteFile(filepath.Join(dir, PolicyFile), []byte(`{"limits": {"max_time_ceiling": "1m"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, err := Load(); err != nil || p.Limits.MaxTime != time.Minute || p.Path != filepath.Join(dir, PolicyFile) {
		t.Errorf("Load = %+v, %v", p, err)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if p, err := Load(); err != nil || p.Found || len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "no policy file") {
		t.Errorf("without a home: %+v, %v", p, err)
	}
}

// FuzzParsePolicy checks that no policy file makes Parse panic, and that
// what it takes is as the rest of vegtam reads it.
func FuzzParsePolicy(f *testing.F) {
	for _, s := range []string{
		fullPolicy, `{}`, `{"network": {"allow": ["[::1]:80", "fd00::/8"]}}`, `{"network": {"insecure_hosts": ["[::1]:8443"]}}`, `{"hosts": {"[::1]:8443": {"cacert": "/x"}}}`,
		`{"network": {"resolve": ["a.example:443:[::1],10.0.0.1"], "connect_to": ["[::1]:80::8080", ":::"]}}`,
		`{"network": {"confirm": "never"}}`, `{"network": {"confirm": "mutations", "allow": ["127.0.0.1"]}}`,
		secretsPolicy, `{"secrets": {"env": {"A": ["http://[::ffff:127.0.0.1]:8080", "https://*.example"]}, "cmd": {"x y": []}}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse("policy.json", b)
		if err != nil {
			return
		}
		for _, h := range p.Network.InsecureHosts {
			if _, _, err := net.SplitHostPort(h); err != nil || h != strings.ToLower(h) {
				t.Errorf("insecure host %q", h)
			}
		}
		if px := p.Network.Proxy; px != "" && px != ProxyEnvironment && CheckProxy(px) != nil {
			t.Errorf("proxy %q", px)
		}
		for _, h := range p.Hosts {
			if !strings.HasPrefix(h.Origin, "https://") || h.CACert == "" && h.Cert == "" || h.Key != "" && h.Cert == "" {
				t.Errorf("host %+v", h)
			}
		}
		if p.Network.ProxyAuth != "" && p.Network.Proxy == "" {
			t.Errorf("proxy_auth without a proxy: %+v", p.Network)
		}
		// Only "never", in full, lifts the rule on methods.
		if c := p.Network.Confirm; c != "" && c != ConfirmMutations && c != ConfirmNever || p.Network.ConfirmMutations() != (c != ConfirmNever) {
			t.Errorf("confirm %q", c)
		}
		// A route lists as the flag that it allows is written.
		for _, r := range p.Network.Resolve {
			if again, err := netguard.ParseResolve(r.String()); err != nil || again.String() != r.String() {
				t.Errorf("resolve %s: %s, %v", r, again, err)
			}
		}
		for _, c := range p.Network.ConnectTo {
			if again, err := netguard.ParseConnectTo(c.String()); err != nil || again != c {
				t.Errorf("connect_to %s: %s, %v", c, again, err)
			}
		}
		// A secret is bound by a name its placeholder can give, to origins
		// as the requests' are written, each once.
		for kind, m := range map[string]map[string][]string{"env": p.Secrets.Env, "cmd": p.Secrets.Cmd} {
			for name, origins := range m {
				if kind == "env" && !envVar.MatchString(name) || !core.IsVarName(name) {
					t.Errorf("secrets.%s: %q", kind, name)
				}
				if !slices.IsSorted(origins) || len(slices.Compact(slices.Clone(origins))) != len(origins) {
					t.Errorf("secrets.%s.%s: %q", kind, name, origins)
				}
				for _, o := range origins {
					if again, err := core.ParseOrigin(o); err != nil || again != o {
						t.Errorf("secrets.%s.%s: %q parses as %q, %v", kind, name, o, again, err)
					}
				}
			}
		}
	})
}
