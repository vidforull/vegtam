package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// transportRequests are the requests of the transport tests, which the
// tests that need them write beside api.http.
const transportRequests = `### A TLS server whose certificate is trusted only with --cacert
# @name untrusted
GET {{tls}}/echo?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
Authorization: Bearer {{token}}

### A TLS server that wants a client certificate
# @name mtls
GET {{mtls}}/echo?key={{token}}&env={{$env VEGTAM_TEST_KEY}}

### A server that takes the connection and says nothing, TLS neither
# @name silent
GET https://{{silent}}/?key={{token}}&env={{$env VEGTAM_TEST_KEY}}

### No response: the directive lowers the read timeout
# @name lowered
# @timeout 50 ms
GET {{host}}/slow?key={{token}}

### A directive above the flag's limit
# @name raised
# @max-time 10 m
GET {{host}}/echo

### Basic, written as user and password; the server echoes it
# @name basic
GET {{host}}/echo
Authorization: Basic alice {{token}}

### A host from the private file, which redirects to itself
# @name moved
GET {{live}}/moved?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
Authorization: Bearer {{token}}
`

// cookieRequests sign in and send the session cookie the jar keeps.
const cookieRequests = `### The session comes back as a cookie, and in the body
# @name login
POST {{host}}/login

### The jar sends it, and the server echoes it
# @name me
GET {{host}}/me
`

// cookieFile writes the cookie requests and returns their file.
func (fx *fixture) cookieFile(t *testing.T) string {
	t.Helper()
	path := fx.path("cookies.http")
	if err := os.WriteFile(path, []byte(cookieRequests), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// transportFile writes the transport requests and returns their file.
func (fx *fixture) transportFile(t *testing.T) string {
	t.Helper()
	path := fx.path("transport.http")
	if err := os.WriteFile(path, []byte(transportRequests), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// clientCert writes a self-signed client certificate and its key to dir.
func clientCert(t *testing.T, dir string) (cert, key string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "me"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cert, key = filepath.Join(dir, "me.pem"), filepath.Join(dir, "me.key")
	for path, b := range map[string]*pem.Block{cert: {Type: "CERTIFICATE", Bytes: der}, key: {Type: "PRIVATE KEY", Bytes: kder}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cert, key
}

// runAt runs the command line args as a person at a terminal would: stdin
// and stdout are terminals.
func runAt(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(t.Context(), args, Config{Stdout: &out, Stderr: &errOut, TTY: true, Interactive: true, Version: "v1.2.3"})
	return code, out.String(), errOut.String()
}

func TestTLSFlags(t *testing.T) {
	fx := newFixture(t)
	file := fx.transportFile(t)
	cert, key := clientCert(t, t.TempDir())
	untrusted, mtls := []string{"run", file + "#untrusted", "-e", "test"}, []string{"run", file + "#mtls", "-e", "test", "--cacert", fx.ca}
	refused := "--insecure needs a person at a terminal"
	tests := []struct {
		name        string
		terminal    bool // stdin and stdout are terminals
		args        []string
		code        int
		out, errOut string // what they contain
	}{
		{"unknown CA", true, untrusted, exitNetwork, "", "certificate signed by unknown authority: add the CA that signed it with --cacert"},
		{"--cacert", false, append(untrusted, "--cacert", fx.ca), exitOK, `"tls_verified":true`, ""},
		{"http", false, []string{"run", fx.path("api.http") + "#echo", "-e", "test"}, exitOK, `"tls_verified":false`, ""},
		{"--insecure", true, append(untrusted, "--insecure"), exitOK, "HTTP/1.1 200 OK", insecureBanner},
		{"--insecure, not at a terminal", false, append(untrusted, "--insecure"), exitUsage, `"kind":"usage","message":"` + refused, refused},
		{"--insecure --json", true, append(untrusted, "--insecure", "--json"), exitUsage, `"kind": "usage"`, refused},
		{"--cacert missing", false, append(untrusted, "--cacert", fx.path("none.pem")), exitUsage, "", "--cacert: open "},
		{"no client certificate", false, mtls, exitNetwork, "", "pass --cert and --key"},
		{"--cert and --key", false, append(mtls, "--cert", cert, "--key", key), exitOK, `"status":200`, ""},
		{"--key alone", false, append(mtls, "--key", key), exitUsage, "", "--key needs --cert"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, false, tt.args...)
			if tt.terminal {
				code, stdout, stderr = runAt(t, tt.args...)
			}
			if code != tt.code || !strings.Contains(stdout, tt.out) || !strings.Contains(stderr, tt.errOut) {
				t.Errorf("%q = %d\nstdout: %s\nstderr: %s\nwant %d, %q, %q", tt.args, code, stdout, stderr, tt.code, tt.out, tt.errOut)
			}
			if strings.Contains(stderr, insecureBanner) != (tt.errOut == insecureBanner) {
				t.Errorf("the banner: %s", stderr)
			}
		})
	}
}

func TestTimeoutFlags(t *testing.T) {
	fx := newFixture(t)
	file := fx.transportFile(t)
	slow := []string{"run", fx.path("api.http") + "#slow", "-e", "test"}
	tests := []struct {
		name    string
		args    []string
		code    int
		phase   string             // of the error
		limits  map[string]float64 // of transport, in ms
		warning string             // on stderr and in warnings
	}{
		{"--read-timeout", append(slow, "--read-timeout", "100ms"), exitNetwork, "read", map[string]float64{"read_timeout_ms": 100}, ""},
		{"--max-time in seconds", append(slow, "--max-time", "0.1"), exitNetwork, "total", map[string]float64{"max_time_ms": 100}, ""},
		{"--timeout", append(slow, "--timeout", "100ms"), exitNetwork, "total", map[string]float64{"max_time_ms": 100}, "--timeout is now --max-time"},
		{
			"--connect-timeout",
			[]string{"run", file + "#silent", "-e", "test", "--connect-timeout", "100ms"},
			exitNetwork, "connect",
			map[string]float64{"connect_timeout_ms": 100, "read_timeout_ms": 30000, "max_time_ms": 120000},
			"",
		},
		{"lowered", []string{"run", file + "#lowered", "-e", "test"}, exitNetwork, "read", map[string]float64{"read_timeout_ms": 50}, ""},
		{
			"raised",
			[]string{"run", file + "#raised", "-e", "test", "--dry-run"},
			exitOK, "",
			map[string]float64{"max_time_ms": 120000},
			"@max-time 10 m is more than --max-time allows, 2m, which holds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, false, tt.args...)
			validateJSON(t, stdout)
			var doc struct {
				Transport map[string]float64 `json:"transport"`
				Warnings  []struct{ Message string }
				Error     *struct {
					Phase string `json:"timeout_phase"`
				}
			}
			decode(t, stdout, &doc)
			phase := ""
			if doc.Error != nil {
				phase = doc.Error.Phase
			}
			if code != tt.code || phase != tt.phase {
				t.Errorf("%q = %d, phase %q\n%s\n%s", tt.args, code, phase, stdout, stderr)
			}
			for k, v := range tt.limits {
				if doc.Transport[k] != v {
					t.Errorf("transport.%s = %v, want %v", k, doc.Transport[k], v)
				}
			}
			if tt.warning != "" && !strings.Contains(stderr, "warning: "+tt.warning) {
				t.Errorf("stderr: %s", stderr)
			}
			if tt.warning != "" && tt.name == "raised" && (len(doc.Warnings) != 1 || doc.Warnings[0].Message != tt.warning) {
				t.Errorf("warnings = %+v", doc.Warnings)
			}
		})
	}
}

func TestHTTPVersionFlags(t *testing.T) {
	fx := newFixture(t)
	tls := []string{"run", fx.transportFile(t) + "#untrusted", "-e", "test", "--cacert", fx.ca}
	for _, tt := range []struct {
		args []string
		code int
		want string // in stdout and stderr
	}{
		{append(tls, "--http1.1"), exitOK, `"proto":"HTTP/1.1"`},
		{append(tls, "--http1.1", "--dry-run"), exitOK, `"transport":{"version":"HTTP/1.1",`},
		{append(tls, "--http2"), exitNetwork, "the server does not speak HTTP/2 over TLS"},
		{append(tls, "--http2", "--http1.1"), exitUsage, "exclude each other"},
		// A server of HTTP/1 may reset the connection before the answer to
		// HTTP/2 is read, and then there is nothing to tell from.
		{[]string{"run", fx.path("api.http") + "#fail", "-e", "test", "--http2-prior-knowledge"}, exitNetwork, `"kind":"network"`},
	} {
		code, stdout, stderr := runCLI(t, false, tt.args...)
		if code != tt.code || !strings.Contains(stdout+stderr, tt.want) {
			t.Errorf("%q = %d\n%s\n%s\nwant %d, %q", tt.args, code, stdout, stderr, tt.code, tt.want)
		}
	}
}

// TestForeignSettings checks what vegtam does with the settings of other
// clients: a transport directive stops the request with the flag to use,
// the rest are warnings on stderr and in the JSON, the ones of the
// environment files once, with the first request of their directory.
func TestForeignSettings(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.http":                       "# @note sure?\nGET https://example.test/a\n\n###\nGET https://example.test/b\n",
		"b.http":                       "# @no-reject-unauthorized\nGET https://example.test/c\n",
		"sub/c.http":                   "GET https://example.test/d\n", // the same environment files
		"http-client.env.json":         `{"dev": {}}`,
		"http-client.private.env.json": `{"dev": {"SSLConfiguration": {"verifyHostCertificate": false}}}`,
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, stdout, stderr := runCLI(t, false, "run", dir, "-e", "dev", "--dry-run")
	validateJSON(t, stdout)
	var doc struct {
		Results []struct {
			Warnings []struct{ Message string }
			Error    *struct{ Kind, Message string }
		}
	}
	decode(t, stdout, &doc)
	if code != exitUsage || len(doc.Results) != 4 {
		t.Fatalf("run = %d\n%s\n%s", code, stdout, stderr)
	}
	ignored := "dev.SSLConfiguration.verifyHostCertificate is ignored"
	if w := doc.Results[0].Warnings; len(w) != 2 || !strings.HasPrefix(w[0].Message, ignored) || w[1].Message != "@note (httpyac) is not supported: ignored" {
		t.Errorf("warnings of the first request: %+v", w)
	}
	if w := doc.Results[1].Warnings; len(w) != 0 {
		t.Errorf("warnings of the second request: %+v", w)
	}
	if e := doc.Results[2].Error; e == nil || e.Kind != "parse" || !strings.Contains(e.Message, "--insecure does it") {
		t.Errorf("error of b.http: %+v", e)
	}
	if strings.Count(stderr, "warning: ") != 2 || !strings.Contains(stderr, "warning: "+ignored) {
		t.Errorf("stderr: %s", stderr)
	}
}
