package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
)

// showSecret is the value of the environment variable that the requests
// of originsFile send.
const showSecret = "Sh0wK3y/v+al"

// originsFile writes a .http file whose requests send a private token and
// an environment variable to an origin that neither is bound to, beside
// its environment files, with a policy that binds nothing, and sends a
// run's secrets through the keeper, and returns the file. Nothing listens
// at that origin: show and a dry run send nothing.
func originsFile(t *testing.T) string {
	t.Helper()
	writePolicy(t, `{"secrets": {"unattended": "keeper"}}`)
	t.Setenv("VEGTAM_TEST_SHOW", showSecret)
	dir := t.TempDir()
	files := map[string]string{
		"origins.http": `### Sends both where neither is bound
# @name steal
GET http://127.0.0.1:9/c?t={{token}}&k={{$env VEGTAM_TEST_SHOW}}
Authorization: Bearer {{token}}

### The same, with a note
# @name noted
# @note Read this first
GET http://127.0.0.1:9/n?t={{token}}
`,
		"http-client.env.json":         `{"test": {}}`,
		"http-client.private.env.json": `{"test": {"token": "` + privateSecret + `"}}`,
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "origins.http")
}

// secretValues returns the forms of the secrets of originsFile that s
// contains: the values, and their first four characters.
func secretValues(s string) []string {
	return slices.DeleteFunc([]string{privateSecret, showSecret, privateSecret[:4], showSecret[:4]}, func(v string) bool {
		return !strings.Contains(s, v)
	})
}

// TestShowSecretOrigins checks that show -e says where each secret of the
// request may go, by its name, never its value: in JSON, secret_origins;
// as text, a section after the request. Without -e nothing is resolved,
// and no secret is listed.
func TestShowSecretOrigins(t *testing.T) {
	file := originsFile(t)
	code, stdout, stderr := runCLI(t, false, "show", file+"#steal", "-e", "test")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	want := []output.Secret{
		{Name: "{{token}}", Origin: "http://127.0.0.1:9", Allowed: []string{}},
		{Name: "{{$env VEGTAM_TEST_SHOW}}", Origin: "http://127.0.0.1:9", Allowed: []string{}},
	}
	if code != exitOK || doc.Result == nil || !slices.EqualFunc(doc.Result.SecretOrigins, want, func(a, b output.Secret) bool {
		return a.Name == b.Name && a.Origin == b.Origin && slices.Equal(a.Allowed, b.Allowed) && a.Captured == b.Captured
	}) {
		t.Errorf("show -e = %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, `"allowed":[]`) {
		t.Errorf("a secret bound to none has no empty allowed:\n%s", stdout)
	}

	code, stdout, stderr = runCLI(t, true, "show", file+"#steal", "-e", "test")
	text := `# timeouts: connect 10s, read 30s, max time 2m
GET http://127.0.0.1:9/c?t={{token}}&k={{$env VEGTAM_TEST_SHOW}}
Authorization: Bearer {{token}}

Secrets:
  {{token}}                  bound to no origin; refused for http://127.0.0.1:9
  {{$env VEGTAM_TEST_SHOW}}  bound to no origin; refused for http://127.0.0.1:9
`
	if code != exitOK || stdout != text || stderr != "" {
		t.Errorf("show -e as text = %d\n%s\nwant:\n%s\n%s", code, stdout, text, stderr)
	}

	_, stdout, _ = runCLI(t, false, "show", file+"#steal")
	if strings.Contains(stdout, "secret_origins") {
		t.Errorf("show without -e lists secrets:\n%s", stdout)
	}

	// The operator's policy binds the environment variable there; nothing
	// binds the token.
	writePolicy(t, `{"secrets": {"env": {"VEGTAM_TEST_SHOW": ["http://127.0.0.1:9"]}, "unattended": "keeper"}}`)
	_, stdout, stderr = runCLI(t, true, "show", file+"#steal", "-e", "test")
	if !strings.HasSuffix(stdout, "Secrets:\n  {{token}}                  bound to no origin; refused for http://127.0.0.1:9\n"+
		"  {{$env VEGTAM_TEST_SHOW}}  http://127.0.0.1:9\n") {
		t.Errorf("show -e with the policy's secrets:\n%s\n%s", stdout, stderr)
	}
	for _, args := range [][]string{{"show", file + "#steal", "-e", "test"}, {"show", file + "#noted", "-e", "test", "--json"}} {
		for _, tty := range []bool{false, true} {
			_, stdout, stderr := runCLI(t, tty, args...)
			if found := secretValues(stdout + stderr); len(found) > 0 {
				t.Errorf("%q, terminal %v: %q in the output\n%s%s", args, tty, found, stdout, stderr)
			}
		}
	}
}

// TestDryRunSecretOrigins checks the text of a dry run of a request that
// would send secrets where they are not bound: for a person at a
// terminal, where each may go, and what sending it would need; without
// one, the error of kind policy, which --confirm does not lift, and
// nothing on stdout. No value shows.
func TestDryRunSecretOrigins(t *testing.T) {
	file := originsFile(t)
	code, stdout, stderr := runAt(t, "run", file+"#steal", "-e", "test", "--dry-run")
	text := `# timeouts: connect 10s, read 30s, max time 2m
GET http://127.0.0.1:9/c?t={{token}}&k={{$env VEGTAM_TEST_SHOW}}
Authorization: Bearer {{token}}

Secrets:
  {{token}}                  bound to no origin; refused for http://127.0.0.1:9
  {{$env VEGTAM_TEST_SHOW}}  bound to no origin; refused for http://127.0.0.1:9

sending it needs --confirm=` + file + `#steal: {{token}} goes to http://127.0.0.1:9, but it is bound to no origin
`
	if code != exitOK || stdout != text || stderr != "" {
		t.Errorf("a person's dry run = %d\n%s\nwant:\n%s\n%s", code, stdout, text, stderr)
	}

	code, stdout, stderr = runAt(t, "run", file+"#noted", "-e", "test", "--dry-run")
	line := "sending it needs --confirm=" + file + "#noted: {{token}} goes to http://127.0.0.1:9, but it is bound to no origin; " +
		"its @note asks for a person: Read this first\n"
	if code != exitOK || !strings.HasSuffix(stdout, "\n\n"+line) || stderr != "" {
		t.Errorf("a person's dry run of a note = %d\n%s\nwant it to end with:\n%s\n%s", code, stdout, line, stderr)
	}

	for _, extra := range [][]string{nil, {"--confirm"}} {
		args := append([]string{"run", file + "#steal", "-e", "test", "--dry-run"}, extra...)
		code, stdout, stderr = runCLI(t, true, args...)
		want := "vegtam: " + file + ":3: GET http://127.0.0.1:9/c?t={{token}}&k={{$env VEGTAM_TEST_SHOW}} is not sent: " +
			"secret {{token}} may not go to http://127.0.0.1:9: it is bound to no origin; nor may {{$env VEGTAM_TEST_SHOW}}"
		if code != exitPolicy || stdout != "" || !strings.HasPrefix(stderr, want) {
			t.Errorf("%q without a person = %d\n%s\nwant it to start with:\n%s\n%s", extra, code, stderr, want, stdout)
		}
	}

	code, stdout, _ = runAt(t, "run", file+"#steal", "-e", "test", "--dry-run", "--json")
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if e := doc.Result.Error; code != exitPolicy || e == nil || e.Kind != core.KindPolicy || e.Secret == nil || e.Secret.Name != "{{token}}" ||
		len(doc.Result.SecretOrigins) != 2 {
		t.Errorf("--json, which no person reads = %d\n%s", code, stdout)
	}

	for _, person := range []bool{false, true} {
		for _, args := range [][]string{{"run", file, "-e", "test", "--dry-run"}, {"run", file, "-e", "test", "--dry-run", "--json"}} {
			_, stdout, stderr := runAs(t, true, person, args...)
			if found := secretValues(stdout + stderr); len(found) > 0 {
				t.Errorf("%q, a person %v: %q in the output\n%s%s", args, person, found, stdout, stderr)
			}
		}
	}
}
