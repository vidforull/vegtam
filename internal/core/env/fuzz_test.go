package env

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
)

// FuzzEnvFile checks that no private environment file makes loading an
// environment panic, and that what its $allow binds is as the rest of
// vegtam reads it: names a placeholder can name, and origins as
// core.Origin writes them, sorted and each once.
func FuzzEnvFile(f *testing.F) {
	for _, s := range []string{
		`{"$shared": {"$allow": {"token": ["https://api.example.com"]}},
		  "dev": {"token": "t0ken", "password": "pa55",
		          "$allow": {"token": ["https://api.example.com"], "password": ["https://api.example.com", "https://auth.example.com:8443"],
		                     "$env API_TOKEN": ["https://api.example.com"], "$cmd TOKEN": ["https://api.example.com"]}}}`,
		`{"dev": {"token": "t0ken", "$allow": {"token": ["HTTPS://API.Example.com.:443/", "http://[::ffff:127.0.0.1]:8080", "http://[2001:DB8::1]:80"]}}}`,
		`{"dev": {"token": "t0ken", "$allow": {"token": [], "host": ["https://a.example"]}}, "prod": {"$allow": {}}}`,
		`{"dev": {"$allow": {"token": ["https://*.example.com"]}}}`,
		`{"dev": {"$allow": {"x y": []}}}`,
		`{"dev": {"$allow": []}}`,
		`{"dev": {"SSLConfiguration": {"verifyHostCertificate": false}, "n": 1, "b": true}}`,
		`{"$allow": {"token": ["https://api.example.com"]}}`,
		`{"dev": {"$allow": {"token": ["https://api.example.com:0"]}}}`,
		`{}`, `[]`, `{"dev": null}`,
	} {
		f.Add([]byte(s))
	}
	dir := f.TempDir()
	path := filepath.Join(dir, "a.http")
	f.Fuzz(func(t *testing.T, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, PrivateFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Names(path); err != nil {
			return
		}
		v, err := NewLoader(Options{Env: "dev"}).For(path)
		if err != nil {
			return
		}
		if _, ok := v.private[allowKey]; ok {
			t.Errorf("$allow is a variable")
		}
		for name, origins := range v.allow {
			if !allowable(name) {
				t.Errorf("$allow binds %q", name)
			}
			if _, ok := v.private[name]; !ok && !strings.HasPrefix(name, "$") {
				t.Errorf("$allow binds %q, which is no variable", name)
			}
			if !slices.IsSorted(origins) || len(slices.Compact(slices.Clone(origins))) != len(origins) {
				t.Errorf("%s: origins %q", name, origins)
			}
			for _, o := range origins {
				if again, err := core.ParseOrigin(o); err != nil || again != o {
					t.Errorf("%s: origin %q parses as %q, %v", name, o, again, err)
				}
			}
		}
	})
}
