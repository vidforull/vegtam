package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/tui"
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
		forms := []string{
			secret, url.QueryEscape(secret), url.PathEscape(secret), string(j[1 : len(j)-1]),
			strings.ReplaceAll(secret, "/", `\/`), strings.ReplaceAll(secret, "+", `\u002B`),
			strings.ReplaceAll(secret, "+", " "), secret[:4],
		}
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
		if body, ok := v["body"].(string); ok && v["encoding"] == "base64" {
			b, _ := base64.StdEncoding.DecodeString(body)
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
		{"redirect error", []string{"run", api + "#hops"}, exitNetwork, "stopped after 10 redirects"},
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
					decode(t, stdout, &doc)
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
	if _, err := cfg.out.Write([]byte("text " + privateSecret + " " + url.QueryEscape(envSecret) + "\n")); err != nil {
		t.Fatal(err)
	}
	cfg.writeJSON(map[string]string{"url": "url " + envSecret})
	want := "text *** ***\n{\n  \"url\": \"*** ***\"\n}\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

// panicWriter panics when it is written to, with a message that names a
// secret, as a bug might.
type panicWriter struct{ msg string }

func (w panicWriter) Write([]byte) (int, error) { panic(w.msg) }

// TestPanicIsMasked checks that a panic, whose value may hold a secret,
// is printed masked: Go would print it as is.
func TestPanicIsMasked(t *testing.T) {
	fx := newFixture(t)
	var stderr strings.Builder
	code := Run(t.Context(), []string{"run", fx.path("api.http") + "#echo", "-e", "test"},
		Config{Stdout: panicWriter{"cannot print " + privateSecret}, Stderr: &stderr, TTY: true})
	if code != exitPanic || !strings.HasPrefix(stderr.String(), "vegtam: internal error: cannot print ***\ngoroutine ") {
		t.Errorf("Run = %d\n%s", code, stderr.String())
	}
	if found := fx.leaks(stderr.String()); len(found) > 0 {
		t.Errorf("secret forms %q in\n%s", found, stderr.String())
	}
}

// TestPanicBeforeOutputIsMasked checks a panic that comes while requests
// are resolved, before the command has a masker: the secrets the loader
// has read mask it, and its text cannot drive the terminal.
func TestPanicBeforeOutputIsMasked(t *testing.T) {
	fx := newFixture(t)
	loader := env.NewLoader(env.Options{Env: "test"})
	if _, err := loader.For(fx.path("api.http")); err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cfg := &Config{Stderr: &stderr, secrets: loader.Masker}
	cfg.errOut = masked{&stderr, cfg}
	cfg.internalError("cannot resolve "+privateSecret+" \x1b]0;title\x07", []byte("goroutine 1 [running]:\n"))
	want := `vegtam: internal error: cannot resolve *** \x1b]0;title\x07` + "\ngoroutine 1 [running]:\n"
	if stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}
}

// TestTUIPanicIsMasked checks a panic that the terminal interface caught
// and raised again once the terminal was restored: its own value and
// stack are printed, masked.
func TestTUIPanicIsMasked(t *testing.T) {
	var stderr strings.Builder
	cfg := &Config{Stderr: &stderr, secrets: func() *core.Masker { return core.NewMasker([]string{privateSecret}) }}
	cfg.errOut = masked{&stderr, cfg}
	p := &tui.Panic{Value: "cannot show " + privateSecret, Stack: []byte("goroutine 7 [running]:\ntui.(*Model).View\n")}
	cfg.internalError(p, []byte("goroutine 1 [running]:\ncli.Run\n"))
	want := "vegtam: internal error: cannot show ***\ngoroutine 7 [running]:\ntui.(*Model).View\n"
	if stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}
}
