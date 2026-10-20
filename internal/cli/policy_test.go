package cli

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/net/http/httpproxy"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// flagsOf returns the transport flags that args give.
func flagsOf(t *testing.T, args ...string) *netFlags {
	t.Helper()
	f := newNetFlags()
	fl := pflag.NewFlagSet("run", pflag.ContinueOnError)
	f.add(fl)
	if err := fl.Parse(args); err != nil {
		t.Fatal(err)
	}
	return &f
}

// proxyFor returns the proxy that tr sends a request to u through, or "".
func proxyFor(t *testing.T, tr func(*http.Request) (*url.URL, error), u string) string {
	t.Helper()
	if tr == nil {
		return ""
	}
	p, err := tr(httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil))
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		return ""
	}
	return p.String()
}

// TestMerge is the table of merge: what vegtam does on its own, then the
// policy, then the flags, with a person at a terminal and without one.
func TestMerge(t *testing.T) {
	env := &httpproxy.Config{HTTPSProxy: "http://env-proxy.example:3128", HTTPProxy: "env-proxy.example:3128", NoProxy: "skip.example"}
	tests := []struct {
		name       string
		policy     string
		args       []string
		unattended bool
		env        *httpproxy.Config
		// What the transport has: its limits and where they come from, the
		// proxies of an https and of an http URL, and the rest as said.
		limits             [3]time.Duration
		from               [3]string
		httpsProxy, plain  string
		direct             []string // URLs that go to no proxy
		insecure           bool
		insecureOrigins    []string
		allow              []string
		secrets            []string
		warnings, errorHas []string
	}{
		{
			name: "on its own", policy: `{}`,
			limits: [3]time.Duration{10 * time.Second, 30 * time.Second, 2 * time.Minute},
		},
		{
			name: "flags", policy: `{}`, args: []string{"--connect-timeout", "1s", "--read-timeout", "0", "--max-time", "1m"},
			limits: [3]time.Duration{time.Second, 0, time.Minute},
		},
		{
			name: "ceilings below the defaults", policy: `{"limits": {"connect_timeout_ceiling": "5s", "max_time_ceiling": "1m"}}`,
			limits: [3]time.Duration{5 * time.Second, 30 * time.Second, time.Minute},
			from:   [3]string{"the policy's limits.connect_timeout_ceiling", "", "the policy's limits.max_time_ceiling"},
		},
		{
			name: "flags under the ceilings", policy: `{"limits": {"read_timeout_ceiling": "2m", "max_time_ceiling": "5m"}}`,
			args:   []string{"--read-timeout", "1m", "--max-time", "5m"},
			limits: [3]time.Duration{10 * time.Second, time.Minute, 5 * time.Minute},
		},
		{
			name: "flags over the ceilings", policy: `{"limits": {"read_timeout_ceiling": "2m", "max_time_ceiling": "5m"}}`,
			args:   []string{"--read-timeout", "0", "--timeout", "10m"},
			limits: [3]time.Duration{10 * time.Second, 2 * time.Minute, 5 * time.Minute},
			from:   [3]string{"", "the policy's limits.read_timeout_ceiling", "the policy's limits.max_time_ceiling"},
			warnings: []string{
				"--timeout is now --max-time",
				"--read-timeout none is more than the policy allows, 2m (limits.read_timeout_ceiling), which holds",
				"--max-time 10m is more than the policy allows, 5m (limits.max_time_ceiling), which holds",
			},
		},
		{
			name: "--insecure with a person", policy: `{}`, args: []string{"--insecure"},
			insecure: true, warnings: []string{insecureWarning},
		},
		{
			name: "--insecure alone", policy: `{}`, args: []string{"--insecure"}, unattended: true,
			errorHas: []string{"--insecure needs a person at a terminal", "network.insecure_hosts"},
		},
		{
			name: "--insecure alone, hosts allowed", policy: `{"network": {"insecure_hosts": ["dev.example:8443", "[::1]:8443"]}}`,
			args: []string{"--insecure"}, unattended: true,
			insecureOrigins: []string{"https://dev.example:8443", "https://[::1]:8443"},
			warnings:        []string{"--insecure: the certificates of dev.example:8443, [::1]:8443 are not checked, as the policy allows (network.insecure_hosts)"},
		},
		{
			name: "insecure hosts, without --insecure", policy: `{"network": {"insecure_hosts": ["dev.example:8443"]}}`, unattended: true,
		},
		{
			name: "allow, alone", policy: `{"network": {"allow": ["127.0.0.1:8080", "10.0.0.0/8"]}}`, unattended: true,
			allow: []string{"127.0.0.1:8080", "10.0.0.0/8"},
		},
		{
			name: "the environment's proxy, with a person", policy: `{}`, env: env,
			httpsProxy: "http://env-proxy.example:3128", plain: "http://env-proxy.example:3128",
			direct: []string{"https://skip.example/", "http://localhost/", "http://127.0.0.1:8080/"},
		},
		{
			name: "the environment's proxy, with credentials", policy: `{}`,
			env:        &httpproxy.Config{HTTPSProxy: "user:e@env-proxy.example:3128", HTTPProxy: "http://T0kenAsAUser:@env-proxy.example:3128"},
			httpsProxy: "http://user:e@env-proxy.example:3128", plain: "http://T0kenAsAUser:@env-proxy.example:3128",
			secrets: []string{"T0kenAsAUser:", "T0kenAsAUser", "user:e"},
		},
		{
			name: "the environment's proxy, alone", policy: `{}`, env: env, unattended: true,
			warnings: []string{"the proxy of the environment (HTTPS_PROXY, HTTP_PROXY) is not used without a person at a terminal"},
		},
		{
			name: "the environment's proxy, alone, as the policy says", policy: `{"network": {"proxy": "environment", "no_proxy": ["api.example"]}}`,
			env: env, unattended: true,
			httpsProxy: "http://env-proxy.example:3128", plain: "http://env-proxy.example:3128",
			direct: []string{"https://skip.example/", "https://api.example/"},
		},
		{
			name: "the policy's proxy", policy: `{"network": {"proxy": "socks5h://proxy.example", "no_proxy": ["api.example"]}}`,
			env: env, unattended: true,
			httpsProxy: "socks5h://proxy.example", plain: "socks5h://proxy.example",
			direct: []string{"https://api.example/", "http://sub.api.example/"},
		},
		{name: "versions", policy: `{}`, args: []string{"--http1.1", "--http2"}, errorHas: []string{"exclude each other"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol, err := policy.Parse("policy.json", []byte(tt.policy))
			if err != nil {
				t.Fatal(err)
			}
			proxyEnv := tt.env
			if proxyEnv == nil {
				proxyEnv = &httpproxy.Config{}
			}
			tr, warnings, err := merge(pol, flagsOf(t, tt.args...), tt.unattended, proxyEnv)
			if tt.errorHas != nil {
				e, ok := errors.AsType[*core.Error](err)
				for _, want := range tt.errorHas {
					if !ok || e.Kind != core.KindUsage || !strings.Contains(err.Error(), want) {
						t.Errorf("%v; want a usage error with %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(tr.Secrets, tt.secrets) {
				t.Errorf("secrets %q, want %q", tr.Secrets, tt.secrets)
			}
			if got := [3]time.Duration{tr.Connect, tr.Read, tr.Total}; got != tt.limits && tt.limits != ([3]time.Duration{}) {
				t.Errorf("limits %v, want %v", got, tt.limits)
			}
			if got := [3]string{tr.ConnectFrom, tr.ReadFrom, tr.TotalFrom}; got != tt.from {
				t.Errorf("from %q, want %q", got, tt.from)
			}
			if got := proxyFor(t, tr.Proxy, "https://api.example.test/"); got != tt.httpsProxy {
				t.Errorf("proxy of an https URL %q, want %q", got, tt.httpsProxy)
			}
			if got := proxyFor(t, tr.Proxy, "http://api.example.test/"); got != tt.plain {
				t.Errorf("proxy of an http URL %q, want %q", got, tt.plain)
			}
			for _, u := range tt.direct {
				if got := proxyFor(t, tr.Proxy, u); got != "" {
					t.Errorf("%s goes through %s", u, got)
				}
			}
			if tr.TLS.Insecure != tt.insecure || !slices.Equal(tr.InsecureOrigins, tt.insecureOrigins) {
				t.Errorf("insecure %v %v, want %v %v", tr.TLS.Insecure, tr.InsecureOrigins, tt.insecure, tt.insecureOrigins)
			}
			var allow []string
			for _, e := range tr.Guard.Allow {
				allow = append(allow, e.String())
			}
			if tr.Guard.Unattended != tt.unattended || !slices.Equal(allow, tt.allow) {
				t.Errorf("guard %v %v, want %v %v", tr.Guard.Unattended, allow, tt.unattended, tt.allow)
			}
			if len(warnings) != len(tt.warnings) {
				t.Errorf("warnings %q, want %q", warnings, tt.warnings)
			}
			for i := range min(len(warnings), len(tt.warnings)) {
				if !strings.HasPrefix(warnings[i], tt.warnings[i]) {
					t.Errorf("warning %q, want %q", warnings[i], tt.warnings[i])
				}
			}
		})
	}
}

// TestGuardRun runs a request to the server of the tests, on loopback,
// with a person at a terminal and without one: refused unless the policy
// allows it, with an error that says where to allow it and shows no
// secret.
func TestGuardRun(t *testing.T) {
	fx := newFixture(t)
	echo := []string{"run", fx.path("api.http") + "#echo", "-e", "test"}
	for _, tt := range []struct {
		name     string
		policy   string
		terminal bool
		args     []string
		code     int
	}{
		{"allowed", loopbackPolicy, false, echo, exitOK},
		{"not allowed", `{}`, false, echo, exitPolicy},
		{"another port allowed", `{"network": {"allow": ["127.0.0.1:1"]}}`, false, echo, exitPolicy},
		{"a person", `{}`, true, echo, exitOK},
		{"a person, --json", `{}`, true, append(echo, "--json"), exitPolicy},
		{"no policy", "", false, echo, exitPolicy},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(fx.config, policy.PolicyFile), []byte(tt.policy), 0o600); err != nil {
				t.Fatal(err)
			}
			if tt.policy == "" {
				if err := os.Remove(filepath.Join(fx.config, policy.PolicyFile)); err != nil {
					t.Fatal(err)
				}
			}
			code, stdout, stderr := runCLI(t, false, tt.args...)
			if tt.terminal {
				code, stdout, stderr = runAt(t, tt.args...)
			}
			if code != tt.code {
				t.Fatalf("%q = %d\n%s\n%s", tt.args, code, stdout, stderr)
			}
			if code == exitPolicy {
				validateJSON(t, stdout)
				var doc struct{ Error docError }
				decode(t, stdout, &doc)
				if doc.Error.Kind != "policy" || !strings.Contains(doc.Error.Message, "is private (loopback), and no person is at a terminal; allow it in policy: network.allow") {
					t.Errorf("error %+v", doc.Error)
				}
			}
			for _, s := range []string{privateSecret, envSecret} {
				if strings.Contains(stdout+stderr, s) {
					t.Errorf("%q in the output\n%s\n%s", s, stdout, stderr)
				}
			}
		})
	}
}

// docError is the error of a JSON document.
type docError struct {
	Kind, Message string
}

// TestPolicyCommand prints a policy as text and as JSON, and refuses one
// that others can write.
func TestPolicyCommand(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://user:pr0xy-pass@env-proxy.example:3128")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("NO_PROXY", "")
	dir := writePolicy(t, `{
  "limits":  {"max_time_ceiling": "5m", "connect_timeout_ceiling": "30s"},
  "network": {"allow": ["127.0.0.1:8080", "localhost:3000"], "proxy": "environment", "no_proxy": ["localhost"],
              "insecure_hosts": ["dev.example:8443"]}
}`)
	path := filepath.Join(dir, policy.PolicyFile)
	code, stdout, stderr := runCLI(t, true, "policy")
	for _, want := range []string{
		"policy          " + path + "\n",
		"limits          max time at most 5m, connect timeout at most 30s\n",
		"allow           127.0.0.1:8080, localhost:3000\n",
		"proxy           environment\n",
		"no proxy        localhost\n",
		"insecure hosts  dev.example:8443\n",
		"This run has no person at a terminal: loopback and private addresses only as network.allow names them.\n",
		"Requests to https URLs go through http://***@env-proxy.example:3128, to http URLs through none, but for localhost.\n",
		"Never connected to: 169.254.169.254 (AWS, Azure",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("text lacks %q\n%s", want, stdout)
		}
	}
	if code != exitOK || stderr != "" || strings.Contains(stdout, "pr0xy-pass") {
		t.Errorf("policy = %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, _ = runAt(t, "policy", "--json")
	validateJSON(t, stdout)
	var doc struct {
		Policy struct {
			Path    string
			Found   bool
			Limits  map[string]float64
			Network struct{ Allow []string }
			Run     struct {
				Unattended bool
				HTTPS      string `json:"https_proxy"`
			}
			Never []string
		}
	}
	decode(t, stdout, &doc)
	p := doc.Policy
	if code != exitOK || p.Path != path || !p.Found || p.Limits["max_time_ceiling_ms"] != 300000 || len(p.Network.Allow) != 2 ||
		!p.Run.Unattended || p.Run.HTTPS != "http://***@env-proxy.example:3128" || len(p.Never) < 6 || strings.Contains(stdout, "pr0xy-pass") {
		t.Errorf("policy --json = %d\n%s", code, stdout)
	}
	// Readable by others: a warning; writable: refused.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr = runCLI(t, true, "policy"); code != exitOK || !strings.Contains(stderr, "warning: "+path+": others can read the policy") {
		t.Errorf("a policy others can read = %d, %s", code, stderr)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCLI(t, false, "policy")
	if code != exitPolicy || !strings.Contains(stderr, "others can write it, so it is not read") || !strings.Contains(stdout, `"kind":"policy"`) {
		t.Errorf("a policy others can write = %d\n%s\n%s", code, stdout, stderr)
	}
	// So does every command that reads it.
	if code, _, stderr = runCLI(t, false, "run", "none.http"); code != exitPolicy || !strings.Contains(stderr, "others can write it") {
		t.Errorf("run with a policy others can write = %d, %s", code, stderr)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if code, stdout, _ = runAt(t, "policy"); code != exitOK || !strings.Contains(stdout, "This run has a person at a terminal: loopback and private addresses are allowed.") {
		t.Errorf("policy at a terminal = %d\n%s", code, stdout)
	}
	if code, stdout, _ = runCLI(t, true, "policy"); code != exitOK || !strings.Contains(stdout, "not found: vegtam does what it does on its own") {
		t.Errorf("no policy = %d\n%s", code, stdout)
	}
}

// TestPolicyCeilings checks that show and a dry run give the limits of a
// run with the policy's ceilings, and the warnings of a flag and of a
// directive above one.
func TestPolicyCeilings(t *testing.T) {
	fx := newFixture(t)
	writePolicy(t, `{"network": {"allow": ["127.0.0.1"]}, "limits": {"max_time_ceiling": "1m", "read_timeout_ceiling": "20s"}}`)
	raised := fx.transportFile(t) + "#raised" // @max-time 10 m
	for _, args := range [][]string{{"show", raised}, {"run", raised, "-e", "test", "--dry-run"}} {
		code, stdout, stderr := runCLI(t, false, args...)
		validateJSON(t, stdout)
		var doc struct {
			Transport map[string]float64
			Warnings  []struct{ Message string }
		}
		decode(t, stdout, &doc)
		want := "@max-time 10 m is more than the policy's limits.max_time_ceiling allows, 1m, which holds"
		if code != exitOK || doc.Transport["max_time_ms"] != 60000 || doc.Transport["read_timeout_ms"] != 20000 ||
			len(doc.Warnings) != 1 || doc.Warnings[0].Message != want {
			t.Errorf("%q = %d\n%s\n%s", args, code, stdout, stderr)
		}
	}
	code, stdout, stderr := runCLI(t, false, "run", raised, "-e", "test", "--dry-run", "--max-time", "5m")
	if code != exitOK || !strings.Contains(stderr, "warning: --max-time 5m is more than the policy allows, 1m (limits.max_time_ceiling), which holds") ||
		!strings.Contains(stdout, `"max_time_ms":60000`) {
		t.Errorf("--max-time over the ceiling = %d\n%s\n%s", code, stdout, stderr)
	}
}

// TestInsecureHosts runs --insecure without a person at a terminal: only
// the hosts the policy names go unchecked.
func TestInsecureHosts(t *testing.T) {
	fx := newFixture(t)
	file := fx.transportFile(t)
	var env struct {
		Test map[string]string `json:"test"`
	}
	b, err := os.ReadFile(fx.path("http-client.env.json"))
	if err != nil {
		t.Fatal(err)
	}
	decode(t, string(b), &env)
	tlsHost := strings.TrimPrefix(env.Test["tls"], "https://")
	writePolicy(t, `{"network": {"allow": ["127.0.0.1"], "insecure_hosts": ["`+tlsHost+`"]}}`)
	code, stdout, stderr := runCLI(t, false, "run", file+"#untrusted", "-e", "test", "--insecure")
	if code != exitOK || !strings.Contains(stdout, `"tls_verified":false`) ||
		!strings.Contains(stderr, "warning: --insecure: the certificates of "+tlsHost+" are not checked, as the policy allows (network.insecure_hosts)") {
		t.Errorf("a host the policy names = %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, stderr = runCLI(t, false, "run", file+"#mtls", "-e", "test", "--insecure")
	if code != exitNetwork || !strings.Contains(stderr, "certificate signed by unknown authority") {
		t.Errorf("another host = %d\n%s\n%s", code, stdout, stderr)
	}
}

// TestEnvironmentProxy checks that a person's run goes through the proxy
// of the environment, and that a run without a person does not, and says
// so.
func TestEnvironmentProxy(t *testing.T) {
	fx := newFixture(t)
	var mu sync.Mutex
	var got []string
	proxy := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, r.URL.String())
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	// An address of the documentation's, which the proxy answers itself;
	// net/http sends nothing on loopback through a proxy.
	if err := os.WriteFile(fx.path("proxied.http"), []byte("GET http://192.0.2.1/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runAt(t, "run", fx.path("proxied.http")+"#1")
	mu.Lock()
	sent := slices.Clone(got)
	mu.Unlock()
	if code != exitOK || stderr != "" || !slices.Equal(sent, []string{"http://192.0.2.1/x"}) {
		t.Errorf("with a person = %d, the proxy got %q\n%s\n%s", code, sent, stdout, stderr)
	}
	echo := []string{"run", fx.path("api.http") + "#echo", "-e", "test"}
	code, _, stderr = runCLI(t, false, echo...)
	if code != exitOK || !strings.Contains(stderr, "warning: the proxy of the environment (HTTPS_PROXY, HTTP_PROXY) is not used without a person at a terminal") {
		t.Errorf("%q = %d, %s", echo, code, stderr)
	}
}
