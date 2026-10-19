package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
)

// leaks returns the forms of the test secrets that s contains: the value,
// its escaped forms, its first four characters, which is what a cut-off
// value would leave, and the host and port of the base URL in the private
// file.
func (fx *fixture) leaks(s string) []string {
	_, port, _ := strings.Cut(fx.hidden, ":")
	found := slices.DeleteFunc([]string{fx.hidden, ":" + port}, func(h string) bool { return !strings.Contains(s, h) })
	for _, secret := range []string{privateSecret, envSecret} {
		j, _ := json.Marshal(secret)
		forms := []string{secret, url.QueryEscape(secret), url.PathEscape(secret), string(j[1 : len(j)-1]),
			strings.ReplaceAll(secret, "/", `\/`), strings.ReplaceAll(secret, "+", `\u002B`),
			strings.ReplaceAll(secret, "+", " "), secret[:4]}
		for _, f := range forms {
			if strings.Contains(s, f) {
				found = append(found, f)
			}
		}
	}
	return found
}

// bodies returns the base64-encoded bodies in a JSON document, decoded.
func bodies(v any) []string {
	var out []string
	switch v := v.(type) {
	case map[string]any:
		if v["encoding"] == "base64" {
			b, _ := base64.StdEncoding.DecodeString(v["body"].(string))
			out = append(out, string(b))
		}
		for _, x := range v {
			out = append(out, bodies(x)...)
		}
	case []any:
		for _, x := range v {
			out = append(out, bodies(x)...)
		}
	}
	return out
}

// TestNoSecretInOutput runs every kind of outcome in every output mode and
// checks that neither secret reaches stdout or stderr in any form.
func TestNoSecretInOutput(t *testing.T) {
	fx := newFixture(t)
	api := fx.path("api.http")
	scenarios := []struct {
		name string
		args []string
		code int
		want string // what shows that the secret was there and got masked
	}{
		{"success", []string{"run", api + "#echo"}, exitOK, "***"},
		{"HTTP 500", []string{"run", api + "#fail"}, exitOK, "***"},
		{"HTTP 500 with --fail", []string{"run", api + "#fail", "--fail"}, exitStatus, "***"},
		{"network error", []string{"run", api + "#refused"}, exitNetwork, "?key={{token}}&env={{$env VEGTAM_TEST_KEY}}"},
		{"timeout", []string{"run", api + "#slow", "--timeout", "100ms"}, exitNetwork, "?key={{token}}&env={{$env VEGTAM_TEST_KEY}}"},
		{"dry run", []string{"run", api + "#echo", "--dry-run"}, exitOK, "Bearer {{token}}"},
		{"binary body", []string{"run", api + "#binary"}, exitOK, ""},
		{"truncated body", []string{"run", api + "#big", "--max-body", "106"}, exitOK, "xx***"},
		{"secret host", []string{"run", api + "#hidden"}, exitNetwork, "{{base}}/?key={{token}}"},
		{"directory", []string{"run", fx.dir, "--timeout", "100ms", "--max-body", "106", "--fail"}, exitStatus, "***"},
		{"show", []string{"show", api + "#echo"}, exitOK, "Bearer {{token}}"},
	}
	modes := []struct {
		name      string
		tty, json bool
		args      []string
	}{
		{"text", true, false, nil},
		{"text --verbose", true, false, []string{"--verbose"}},
		{"--json", true, true, []string{"--json"}},
		{"not a terminal", false, true, nil},
		{"not a terminal --verbose", false, true, []string{"--verbose"}},
	}
	for _, sc := range scenarios {
		for _, m := range modes {
			if sc.args[0] == "show" && len(m.args) > 0 && m.args[0] == "--verbose" {
				continue
			}
			t.Run(sc.name+"/"+m.name, func(t *testing.T) {
				args := append(append([]string{}, sc.args...), "-e", "test")
				code, stdout, stderr := runCLI(t, m.tty, append(args, m.args...)...)
				if code != sc.code {
					t.Errorf("exit code %d, want %d\nstdout: %s\nstderr: %s", code, sc.code, stdout, stderr)
				}
				all := stdout + "\n" + stderr
				if m.json {
					validateJSON(t, stdout)
					var doc any
					json.Unmarshal([]byte(stdout), &doc)
					all += "\n" + strings.Join(bodies(doc), "\n")
				}
				if found := fx.leaks(all); len(found) > 0 {
					t.Errorf("secret forms %q in the output\nstdout: %s\nstderr: %s", found, stdout, stderr)
				}
				if !strings.Contains(all, sc.want) {
					t.Errorf("output lacks %q\nstdout: %s\nstderr: %s", sc.want, stdout, stderr)
				}
			})
		}
	}
	// The secrets did reach the server, so the masking above was tested.
	want := "key=" + privateSecret + "&env=" + envSecret
	fx.mu.Lock()
	defer fx.mu.Unlock()
	if !strings.Contains(strings.Join(fx.seen, "\n"), want) {
		t.Errorf("the server never saw %q: %q", want, fx.seen)
	}
}

// TestMaskedWriter checks the last layer alone: whatever a command writes
// is masked, even if nothing upstream masked it.
func TestMaskedWriter(t *testing.T) {
	var out strings.Builder
	cfg := &Config{Stdout: &out, TTY: true, masker: core.NewMasker([]string{privateSecret, envSecret, "url"})}
	cfg.out = masked{&out, cfg}
	cfg.out.Write([]byte("text " + privateSecret + " " + url.QueryEscape(envSecret) + "\n"))
	cfg.writeJSON(map[string]string{"url": "url " + envSecret})
	want := "text *** ***\n{\n  \"url\": \"*** ***\"\n}\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}
