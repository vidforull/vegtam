package policy

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
)

// The policy of the task's example, all of it.
const fullPolicy = `{
  "limits":  {"max_time_ceiling": "5m", "read_timeout_ceiling": "2m", "connect_timeout_ceiling": "30s"},
  "network": {"allow": ["127.0.0.1:8080", "localhost:3000", "10.0.0.0/8"], "proxy": "http://proxy.example:3128",
              "no_proxy": ["localhost"], "insecure_hosts": ["Dev.Example.:8443"]}
}`

func TestParse(t *testing.T) {
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
	if strings.Join(allow, " ") != "127.0.0.1:8080 localhost:3000 10.0.0.0/8" || n.Proxy != "http://proxy.example:3128" ||
		strings.Join(n.NoProxy, " ") != "localhost" || strings.Join(n.InsecureHosts, " ") != "dev.example:8443" {
		t.Errorf("network %+v", n)
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
		`{"limits": {"max_time_ceiling": "soon"}}`:           `limits.max_time_ceiling "soon": want a time`,
		`{"limits": {"read_timeout_ceiling": "0"}}`:          "a ceiling of none is no ceiling",
		`{"network": {"allow": ["localhost"]}}`:              "network.allow: \"localhost\": name the port too",
		`{"network": {"proxy": "proxy.example:3128"}}`:       "network.proxy: \"proxy.example:3128\": want an http, https, socks5 or socks5h URL",
		`{"network": {"proxy": "ftp://proxy.example"}}`:      "want an http, https, socks5 or socks5h URL",
		`{"network": {"proxy": "http://u:p@proxy.example"}}`: "holds a user or password",
		`{"network": {"proxy": "http://proxy.example/x"}}`:   "nothing more",
		`{"network": {"proxy": "http://"}}`:                  "nothing more",
		`{"network": {"no_proxy": ["a,b"]}}`:                 "no_proxy: \"a,b\": want one host",
		`{"network": {"insecure_hosts": ["dev.example"]}}`:   "insecure_hosts: \"dev.example\": want host:port",
		`{"network": {"insecure_hosts": ["dev.example:0"]}}`: "want host:port",
		`{"hosts": {}}`: `unknown field "hosts"`,
	} {
		_, err := Parse("policy.json", []byte(in))
		if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != core.KindPolicy || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v; want a policy error with %q", in, err, want)
		}
	}
}

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
	for _, s := range []string{fullPolicy, `{}`, `{"network": {"allow": ["[::1]:80", "fd00::/8"]}}`, `{"network": {"insecure_hosts": ["[::1]:8443"]}}`} {
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
	})
}
