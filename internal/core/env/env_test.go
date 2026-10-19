package env

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/httpfile"
)

const (
	privateToken = "s3cr3t-dev-token"
	processKey   = "k3y-from-env"
)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// tree writes environment files and a .http file with src, and returns
// the path of the .http file.
func tree(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		PublicFile: `{"$shared": {"scheme": "https"},
			"dev": {"host": "api.example.test", "token": "public-token", "n": 42, "on": true},
			"prod": {"host": "example.com"}}`,
		"sub/" + PrivateFile:      `{"dev": {"token": "` + privateToken + `"}}`,
		"sub/deeper/payload.json": `{"from": "file", "raw": "{{not-a-variable}}"}`,
		"sub/deeper/a.http":       src,
	})
	return filepath.Join(dir, "sub", "deeper", "a.http")
}

func prepare(t *testing.T, l *Loader, path string) (*core.Prepared, error) {
	t.Helper()
	f, err := httpfile.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := l.For(path)
	if err != nil {
		return nil, err
	}
	return v.Prepare(t.Context(), f.Requests[0])
}

func TestPrepare(t *testing.T) {
	t.Setenv("VEGTAM_TEST_KEY", processKey)
	path := tree(t, `POST {{scheme}}://{{host}}/items?n={{n}}&on={{on}}
Authorization: Bearer {{token}}
X-Key: {{ $env VEGTAM_TEST_KEY }}

{"token": "{{token}}"}`)
	l := NewLoader(Options{Env: "dev"})
	p, err := prepare(t, l, path)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{p.URL.Masked(), p.Headers[0].Value.Masked(), p.Headers[1].Value.Masked(), p.Body.Masked()}
	want := []string{"https://api.example.test/items?n=42&on=true", "Bearer {{token}}", "{{$env VEGTAM_TEST_KEY}}", `{"token": "{{token}}"}`}
	if !slices.Equal(got, want) {
		t.Errorf("masked = %q, want %q", got, want)
	}
	if p.URL.HasSecret() || !p.Headers[0].Value.HasSecret() || !p.Body.HasSecret() {
		t.Error("HasSecret: want secrets in the header and body only")
	}

	// The prepared request refers to secrets by name only.
	b, err := json.Marshal(p) //nolint:musttag // every field of the internal type, whatever its name
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); strings.Contains(s, privateToken) || strings.Contains(s, processKey) {
		t.Errorf("prepared request holds a secret value: %s", s)
	}

	v, _ := l.For(path)
	auth, err1 := p.Headers[0].Value.Reveal(v)
	key, err2 := p.Headers[1].Value.Reveal(v)
	if auth != "Bearer "+privateToken || key != processKey || err1 != nil || err2 != nil {
		t.Errorf("revealed %q, %q (%v, %v); want the private token and the process value", auth, key, err1, err2)
	}
	if got := l.Masker().Mask("Bearer " + privateToken + " " + processKey); got != "Bearer *** ***" {
		t.Errorf("Masker().Mask = %q", got)
	}
}

func TestPrepareBodyFile(t *testing.T) {
	p, err := prepare(t, NewLoader(Options{}), tree(t, "POST https://example.com\n\n< ./payload.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Body.Masked(); got != `{"from": "file", "raw": "{{not-a-variable}}"}` {
		t.Errorf("body = %q, want the file as is", got)
	}
}

// A body file is read through an os.Root of the .http file's directory: no
// path leads outside it, by "..", as an absolute path or through a
// symbolic link.
func TestPrepareBodyFileStaysInside(t *testing.T) {
	path := tree(t, "")
	dir := filepath.Dir(path)
	outside := filepath.Join(filepath.Dir(dir), "outside.json")
	writeFiles(t, filepath.Dir(dir), map[string]string{"outside.json": "OUTSIDE", "deeper/in/x.json": "inside"})
	for link, target := range map[string]string{
		"inlink.json":  "in/x.json",
		"abslink.json": outside,
		"rellink.json": "../outside.json",
		"up":           "..",
	} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		file string
		want string // the body, or what the error says
		ok   bool
	}{
		{"./in/x.json", "inside", true},
		{"in/../in/x.json", "inside", true},
		{"inlink.json", "inside", true},
		{"../outside.json", "is outside the directory of the .http file", false},
		{outside, "is outside the directory of the .http file", false},
		{"abslink.json", "escapes", false},
		{"rellink.json", "escapes", false},
		{"up/outside.json", "escapes", false},
	}
	for _, tt := range tests {
		if err := os.WriteFile(path, []byte("POST https://example.com\n\n< "+tt.file), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := prepare(t, NewLoader(Options{}), path)
		switch {
		case tt.ok && (err != nil || p.Body.Masked() != tt.want):
			t.Errorf("< %s: %v, %v; want the body %q", tt.file, p, err, tt.want)
		case tt.ok:
		case err == nil:
			t.Errorf("< %s: read %q, want an error", tt.file, p.Body.Masked())
		case !isKind(err, core.KindRequest) || !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), "OUTSIDE"):
			t.Errorf("< %s: error %v, want kind request saying %q", tt.file, err, tt.want)
		}
	}
}

// TestPrepareBodyFileKind checks that a body file is a regular file of
// at most MaxBodyFile bytes.
func TestPrepareBodyFileKind(t *testing.T) {
	path := tree(t, "")
	dir := filepath.Dir(path)
	if err := os.Mkdir(filepath.Join(dir, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]int64{"max.bin": MaxBodyFile, "over.bin": MaxBodyFile + 1} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Truncate(size); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for file, want := range map[string]string{
		"folder":   "body file: folder is a directory: a body file must be a regular file",
		"over.bin": "body file: over.bin is 16777217 bytes, more than the 16 MiB a body file may be",
		"max.bin":  "",
	} {
		if err := os.WriteFile(path, []byte("POST https://example.com\n\n< "+file), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := prepare(t, NewLoader(Options{}), path)
		switch {
		case want == "" && (err != nil || len(p.Body.Masked()) != MaxBodyFile):
			t.Errorf("< %s: %v", file, err)
		case want != "" && (!isKind(err, core.KindRequest) || !strings.HasSuffix(err.Error(), want)):
			t.Errorf("< %s: error %v, want kind request ending %q", file, err, want)
		}
	}
}

func isKind(err error, k core.Kind) bool {
	e, ok := errors.AsType[*core.Error](err)
	return ok && e.Kind == k
}

func TestPrepareErrors(t *testing.T) {
	tests := []struct {
		name, env, src string
		kind           core.Kind
		want           string
		vars           []string
	}{
		{
			"unresolved without -e", "", "GET {{host}}/x?a={{a}}&b={{a}}\nX-Key: {{$env VEGTAM_UNSET}}", core.KindVariable,
			"unresolved variables: host, a, $env VEGTAM_UNSET (no environment selected; use -e <name>)",
			[]string{"host", "a", "$env VEGTAM_UNSET"},
		},
		{
			"unresolved with -e", "prod", "GET https://{{host}}/{{token}}", core.KindVariable,
			"a.http:1: unresolved variables: token\n",
			[]string{"token"},
		},
		{
			"$cmd without a command file", "", "GET https://example.com/{{$cmd TOKEN}}", core.KindVariable,
			"{{$cmd TOKEN}}: no http-client.cmd.json in ", nil,
		},
		{"$cmd without a name", "", "GET https://example.com/{{$cmd}}", core.KindVariable, "want {{$cmd NAME}}", nil},
		{
			"unknown dynamic variable", "", "GET https://example.com/{{$uuid}}", core.KindVariable,
			"{{$uuid}}: unknown dynamic variable $uuid (supported: $env, $cmd)", nil,
		},
		{"$env without a name", "", "GET https://example.com/{{$env}}", core.KindVariable, "want {{$env NAME}}", nil},
		{"missing body file", "", "POST https://example.com\n\n< ./nope.json", core.KindRequest, "body file: ./nope.json: no such file or directory", nil},
		{
			"unknown environment", "staging", "GET https://example.com", core.KindUsage,
			`environment "staging" is not defined in`, nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := prepare(t, NewLoader(Options{Env: tt.env}), tree(t, tt.src))
			e, ok := errors.AsType[*core.Error](err)
			if !ok || e.Kind != tt.kind || !strings.Contains(e.Error()+"\n", tt.want) || !slices.Equal(e.Variables, tt.vars) {
				t.Errorf("error = %#v; want %s error with %q, variables %q", err, tt.kind, tt.want, tt.vars)
			}
		})
	}
}

func TestEnvironmentFiles(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		kind  core.Kind
		want  string
	}{
		{
			"defined list",
			map[string]string{PublicFile: `{"$shared": {}, "b": {}}`, PrivateFile: `{"a": {}, "b": {}}`},
			core.KindUsage, "(defined: a, b)",
		},
		{"no files", nil, core.KindUsage, "no http-client.env.json or http-client.private.env.json in"},
		{"bad JSON", map[string]string{PublicFile: `{"dev": `}, core.KindParse, PublicFile + ": unexpected EOF"},
		{
			"object value",
			map[string]string{PrivateFile: `{"dev": {"auth": {"type": "x"}}}`},
			core.KindParse,
			"dev.auth: value must be a string, number or boolean",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, tt.files)
			_, err := NewLoader(Options{Env: "dev"}).For(filepath.Join(dir, "a.http"))
			if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != tt.kind || !strings.Contains(e.Error(), tt.want) {
				t.Errorf("error = %v; want %s error with %q", err, tt.kind, tt.want)
			}
		})
	}
}

func TestNames(t *testing.T) {
	path := tree(t, "GET https://{{host}}/")
	writeFiles(t, filepath.Dir(path), map[string]string{PrivateFile: `{"$shared": {}, "$other": {}, "staging": {}, "dev": {}}`})
	if got, err := Names(path); err != nil || !slices.Equal(got, []string{"dev", "prod", "staging"}) {
		t.Errorf("Names = %q, %v; want dev, prod, staging", got, err)
	}
	if got, err := Names(filepath.Join(t.TempDir(), "a.http")); err != nil || len(got) != 0 {
		t.Errorf("Names without files = %q, %v", got, err)
	}
	broken := t.TempDir()
	writeFiles(t, broken, map[string]string{PublicFile: "{"})
	if _, err := Names(filepath.Join(broken, "a.http")); !isKind(err, core.KindParse) {
		t.Errorf("Names of a broken file: %v, want a parse error", err)
	}
}

// TestReload checks that a reloaded loader reads the environment files
// again, keeps what was captured, and still masks the secrets it had.
func TestReload(t *testing.T) {
	path := tree(t, "GET https://{{host}}/{{user}}?t={{token}}")
	l := NewLoader(Options{Env: "dev"})
	l.Declare("user")
	l.Capture("user", "7", false)
	if p, err := prepare(t, l, path); err != nil || p.URL.Masked() != "https://api.example.test/{{user}}?t={{token}}" {
		t.Fatalf("before = %v, %v", p, err)
	}
	writeFiles(t, filepath.Dir(path), map[string]string{
		PrivateFile: `{"dev": {"token": "n3w-t0ken", "host": "new.example.test"}}`,
	})
	if p, _ := prepare(t, l, path); p.URL.Masked() != "https://api.example.test/{{user}}?t={{token}}" {
		t.Errorf("without Reload the files are read again: %s", p.URL.Masked())
	}
	l.Reload()
	p, err := prepare(t, l, path)
	if err != nil || p.URL.Masked() != "https://{{host}}/{{user}}?t={{token}}" {
		t.Fatalf("after Reload = %v, %v", p, err)
	}
	if p, err = l.Fill(p); err != nil || p.URL.Masked() != "https://{{host}}/7?t={{token}}" {
		t.Errorf("the captured value is gone: %v, %v", p, err)
	}
	if got := l.Masker().Mask(privateToken + " n3w-t0ken"); got != "*** ***" {
		t.Errorf("masker after Reload: %q", got)
	}
}

func TestCaptures(t *testing.T) {
	path := tree(t, `GET {{scheme}}://{{host}}/users/{{user}}
Authorization: Bearer {{token}}

{{token}}`)
	f, err := httpfile.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLoader(Options{Env: "dev"})
	v, err := l.For(path)
	if err != nil {
		t.Fatal(err)
	}
	// Before an @capture declares it, token is the private one.
	l.Declare("user")
	before, err := v.Prepare(t.Context(), f.Requests[0])
	if err != nil {
		t.Fatal(err)
	}
	l.Declare("token")
	after, err := v.Prepare(t.Context(), f.Requests[0])
	if err != nil {
		t.Fatal(err)
	}
	// Prepared after it, the request refers to the captured values, over
	// the environment; they are late until captured.
	if got := after.URL.Masked() + " " + after.Headers[0].Value.Masked(); got != "https://api.example.test/users/{{user}} Bearer {{token}}" {
		t.Errorf("masked = %q", got)
	}
	if _, err = after.URL.Reveal(v); err == nil || !strings.Contains(err.Error(), "user was not captured") {
		t.Errorf("Reveal before the capture = %v", err)
	}
	if _, err = after.URL.Reveal(NewLoader(Options{DryRun: true}).must(t, path)); !errors.Is(err, core.ErrLate) {
		t.Errorf("Reveal in a dry run = %v, want ErrLate", err)
	}

	if _, err = l.Fill(after); err == nil ||
		!strings.HasSuffix(err.Error(), "not captured: user (an earlier request took no value), token (an earlier request took no value)") {
		t.Errorf("Fill before the captures = %v", err)
	}
	l.Capture("token", "c4ptured-t0ken", true)
	l.Capture("user", "7", false)
	p, err := l.Fill(after)
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := p.Headers[0].Value.Reveal(v)
	old, _ := before.Headers[0].Value.Reveal(v)
	if got := p.URL.Masked() + " " + p.Headers[0].Value.Masked(); got != "https://api.example.test/users/7 Bearer {{token}}" ||
		p.URL.HasSecret() || auth != "Bearer c4ptured-t0ken" || old != "Bearer "+privateToken {
		t.Errorf("filled = %q, %q; the request before the capture sends %q", got, auth, old)
	}
	if after.URL.Masked() != "https://api.example.test/users/{{user}}" {
		t.Error("Fill changed its argument")
	}
	if got := l.Masker().Mask("c4ptured-t0ken 7"); got != "*** 7" {
		t.Errorf("Masker().Mask = %q, want the secret capture only", got)
	}

	// A capture that took nothing leaves no older value behind, and the
	// masker still knows the old one.
	l.Forget("token", "a.http#login")
	if _, err = p.Headers[0].Value.Reveal(v); err == nil {
		t.Error("Reveal after Forget: want an error")
	}
	_, err = l.Fill(after)
	if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != core.KindVariable || !slices.Equal(e.Variables, []string{"token"}) ||
		!strings.HasSuffix(e.Msg, "not captured: token (a.http#login took no value)") {
		t.Errorf("Fill after Forget = %v", err)
	}
	if got := l.Masker().Mask("c4ptured-t0ken"); got != "***" {
		t.Errorf("Masker().Mask after Forget = %q", got)
	}
}

func (l *Loader) must(t *testing.T, path string) *Vars {
	t.Helper()
	v, err := l.For(path)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestClasses checks that what Classes says of each placeholder is what
// Prepare makes of it.
func TestClasses(t *testing.T) {
	t.Setenv("VEGTAM_TEST_KEY", processKey)
	path := tree(t, `POST {{scheme}}://{{host}}/{{user}}?k={{$env VEGTAM_TEST_KEY}}&u={{$env VEGTAM_UNSET}}
Authorization: Bearer {{ token }}
X-Command: {{$cmd login}}
X-Bad: {{$env bad-name}} {{$uuid}}

{{session}} {{missing}}`)
	f, err := httpfile.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLoader(Options{Env: "dev", DryRun: true})
	l.Declare("session")
	l.Declare("user")
	got := l.must(t, path).Classes(f.Requests[0])
	want := map[string]Class{
		"{{scheme}}": Plain, "{{host}}": Plain, "{{user}}": Captured, "{{$env VEGTAM_TEST_KEY}}": Secret,
		"{{$env VEGTAM_UNSET}}": Unresolved, "{{token}}": Secret, "{{$cmd login}}": Secret,
		"{{$env bad-name}}": Unresolved, "{{$uuid}}": Unresolved, "{{session}}": Captured, "{{missing}}": Unresolved,
	}
	if !maps.Equal(got, want) {
		t.Errorf("Classes = %v\nwant      %v", got, want)
	}
	// Without an environment, only the process environment and captures
	// resolve.
	none := NewLoader(Options{DryRun: true})
	none.Declare("user")
	got = none.must(t, path).Classes(f.Requests[0])
	if got["{{host}}"] != Unresolved || got["{{token}}"] != Unresolved || got["{{user}}"] != Captured ||
		got["{{$env VEGTAM_TEST_KEY}}"] != Secret {
		t.Errorf("Classes without an environment = %v", got)
	}
}

// TestFillDryRun checks that a dry run leaves a variable that is not
// captured yet a placeholder, and fails on one that a capture lost.
func TestFillDryRun(t *testing.T) {
	path := tree(t, "GET https://{{host}}/{{user}}\nX-Token: {{token}}")
	l := NewLoader(Options{Env: "dev", DryRun: true})
	l.Declare("user")
	l.Declare("token")
	p, err := prepare(t, l, path)
	if err != nil {
		t.Fatal(err)
	}
	filled, err := l.Fill(p)
	if err != nil || filled.URL.Masked() != "https://api.example.test/{{user}}" || filled.Headers[0].Value.Masked() != "{{token}}" {
		t.Fatalf("Fill in a dry run = %v, %v", filled, err)
	}
	l.Forget("token", "a.http#login")
	if got := l.Lost(); !maps.Equal(got, map[string]string{"token": "a.http#login"}) {
		t.Errorf("Lost() = %v", got)
	}
	_, err = l.Fill(p)
	if e, ok := errors.AsType[*core.Error](err); !ok || !slices.Equal(e.Variables, []string{"token"}) ||
		!strings.HasSuffix(e.Msg, "not captured: token (a.http#login took no value)") {
		t.Errorf("Fill in a dry run after Forget = %v", err)
	}
}
