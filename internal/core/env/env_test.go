package env

import (
	"encoding/json"
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
	return v.Prepare(f.Requests[0])
}

func TestPrepare(t *testing.T) {
	t.Setenv("VEGTAM_TEST_KEY", processKey)
	path := tree(t, `POST {{scheme}}://{{host}}/items?n={{n}}&on={{on}}
Authorization: Bearer {{token}}
X-Key: {{ $env VEGTAM_TEST_KEY }}

{"token": "{{token}}"}`)
	l := NewLoader("dev")
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
	b, err := json.Marshal(p)
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
	p, err := prepare(t, NewLoader(""), tree(t, "POST https://example.com\n\n< ./payload.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Body.Masked(); got != `{"from": "file", "raw": "{{not-a-variable}}"}` {
		t.Errorf("body = %q, want the file as is", got)
	}
}

func TestPrepareErrors(t *testing.T) {
	tests := []struct {
		name, env, src string
		kind           core.Kind
		want           string
		vars           []string
	}{
		{"unresolved without -e", "", "GET {{host}}/x?a={{a}}&b={{a}}\nX-Key: {{$env VEGTAM_UNSET}}", core.KindVariable,
			"unresolved variables: host, a, $env VEGTAM_UNSET (no environment selected; use -e <name>)",
			[]string{"host", "a", "$env VEGTAM_UNSET"}},
		{"unresolved with -e", "prod", "GET https://{{host}}/{{token}}", core.KindVariable,
			"a.http:1: unresolved variables: token\n", []string{"token"}},
		{"$cmd", "", "GET https://example.com/{{$cmd TOKEN}}", core.KindVariable, "{{$cmd TOKEN}}: $cmd is not supported yet", nil},
		{"unknown dynamic variable", "", "GET https://example.com/{{$uuid}}", core.KindVariable,
			"{{$uuid}}: unknown dynamic variable $uuid (supported: $env)", nil},
		{"$env without a name", "", "GET https://example.com/{{$env}}", core.KindVariable, "want {{$env NAME}}", nil},
		{"missing body file", "", "POST https://example.com\n\n< ./nope.json", core.KindRequest, "body file: open", nil},
		{"unknown environment", "staging", "GET https://example.com", core.KindUsage,
			`environment "staging" is not defined in`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := prepare(t, NewLoader(tt.env), tree(t, tt.src))
			e, ok := err.(*core.Error)
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
		{"defined list", map[string]string{PublicFile: `{"$shared": {}, "b": {}}`, PrivateFile: `{"a": {}, "b": {}}`},
			core.KindUsage, "(defined: a, b)"},
		{"no files", nil, core.KindUsage, "no http-client.env.json or http-client.private.env.json in"},
		{"bad JSON", map[string]string{PublicFile: `{"dev": `}, core.KindParse, PublicFile + ": unexpected EOF"},
		{"object value", map[string]string{PrivateFile: `{"dev": {"auth": {"type": "x"}}}`}, core.KindParse,
			"dev.auth: value must be a string, number or boolean"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, tt.files)
			_, err := NewLoader("dev").For(filepath.Join(dir, "a.http"))
			if e, ok := err.(*core.Error); !ok || e.Kind != tt.kind || !strings.Contains(e.Error(), tt.want) {
				t.Errorf("error = %v; want %s error with %q", err, tt.kind, tt.want)
			}
		})
	}
}
