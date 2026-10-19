package cli

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core/output"
)

// normalize replaces what changes from run to run: the test directory, the
// server address and timings.
func normalize(fx *fixture, s string) string {
	s = strings.ReplaceAll(s, fx.dir, "DIR")
	s = strings.ReplaceAll(s, fx.host, "HOST")
	s = regexp.MustCompile(`\((\d+(\.\d+)?(µs|ms|s))\)`).ReplaceAllString(s, "(TIME)")
	return regexp.MustCompile(`"total_ms": ?[0-9.]+`).ReplaceAllString(s, `"total_ms":0`)
}

func TestRunText(t *testing.T) {
	fx := newFixture(t)
	tests := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{"response", []string{"run", "api.http#fail"}, exitOK, `HTTP/1.1 500 Internal Server Error (TIME)

{
  "echo": {
    "api_key": "",
    "authorization": "Bearer ***",
    "body": "",
    "escaped": "key%3D***%26env%3D***",
    "key": "***",
    "query": "key=***\u0026env=***"
  },
  "php": {
    "api_key": "",
    "authorization": "Bearer ***",
    "body": "",
    "escaped": "key%3D***%26env%3D***",
    "key": "***",
    "query": "key=***\u0026env=***"
  },
  "dotnet": {
    "api_key": "",
    "authorization": "Bearer ***",
    "body": "",
    "escaped": "key%3D***%26env%3D***",
    "key": "***",
    "query": "key=***&env=***"
  }
}
`, ""},
		{"--verbose and control characters", []string{"run", "more/plain.http#1", "-v"}, exitOK, `GET HOST/plain
Accept: text/plain

HTTP/1.1 200 OK (TIME)
Content-Length: 20
Content-Type: text/plain
Date: Mon, 19 Oct 2026 00:00:00 GMT

plain\x1b]0;title\x07 text
`, ""},
		{"dry run", []string{"run", "api.http#echo", "--dry-run"}, exitOK, `POST HOST/echo?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
Authorization: Bearer {{token}}
X-Api-Key: {{$env VEGTAM_TEST_KEY}}
Content-Type: application/json

{"token": "{{token}}", "key": "{{$env VEGTAM_TEST_KEY}}"}
`, ""},
		{"several requests", []string{"run", "more", "--fail", "--max-body", "5"}, exitOK, `### more/plain.http#1
HTTP/1.1 200 OK (TIME)

plain
[truncated: the body is longer than --max-body]
`, ""},
		{"errors", []string{"run", "api.http", "--fail", "--timeout", "50ms", "--max-body", "0"}, exitStatus,
			"### api.http#echo\nHTTP/1.1 200 OK (TIME)\n[truncated: the body is longer than --max-body]\n\n" +
				"### api.http#fail\nHTTP/1.1 500 Internal Server Error (TIME)\n[truncated: the body is longer than --max-body]\n\n" +
				"### api.http#refused\n\n### api.http#slow\n\n" +
				"### api.http#binary\nHTTP/1.1 200 OK (TIME)\n[truncated: the body is longer than --max-body]\n\n" +
				"### api.http#big\nHTTP/1.1 200 OK (TIME)\n[truncated: the body is longer than --max-body]\n\n" +
				"### api.http#hidden\n",
			"vegtam: api.http:20: HTTP 500 Internal Server Error\n" +
				`vegtam: api.http:25: Get "http://127.0.0.1:PORT/?key={{token}}&env={{$env VEGTAM_TEST_KEY}}": dial tcp 127.0.0.1:PORT: connect: connection refused` + "\n" +
				`vegtam: api.http:29: no complete response within 50ms: Get "HOST/slow?key={{token}}&env={{$env VEGTAM_TEST_KEY}}": context deadline exceeded (Client.Timeout exceeded while awaiting headers)` + "\n" +
				`vegtam: api.http:41: Get "{{base}}/?key={{token}}": dial tcp LOCALHOST***: connect: connection refused` + "\n"},
		{"show as written", []string{"show", "api.http#2"}, exitOK, `GET {{host}}/fail?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
Authorization: Bearer {{token}}
`, ""},
		{"list", []string{"list", "."}, exitOK, `REF                METHOD  URL                                                         DIRECTIVES
api.http#echo      POST    {{host}}/echo?key={{token}}&env={{$env VEGTAM_TEST_KEY}}    1 @assert, @tag smoke
api.http#fail      GET     {{host}}/fail?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
api.http#refused   GET     {{closed}}/?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
api.http#slow      GET     {{host}}/slow?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
api.http#binary    GET     {{host}}/binary?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
api.http#big       GET     {{host}}/big?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
api.http#hidden    GET     {{base}}/?key={{token}}
more/plain.http#1  GET     {{host}}/plain
`, ""},
	}
	t.Chdir(fx.dir)
	// localhost may resolve to either address.
	port, localhost := regexp.MustCompile(`127\.0\.0\.1:\d+`), regexp.MustCompile(`(\[::1\]|127\.0\.0\.1)\*\*\*`)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			if args[0] == "run" {
				args = append(args, "-e", "test")
			}
			code, stdout, stderr := runCLI(t, true, args...)
			stderr = localhost.ReplaceAllString(port.ReplaceAllString(normalize(fx, stderr), "127.0.0.1:PORT"), "LOCALHOST***")
			stdout = normalize(fx, stdout)
			if code != tt.code || stdout != tt.stdout || stderr != tt.stderr {
				t.Errorf("exit code %d, want %d\nstdout:\n%s\nwant:\n%s\nstderr:\n%s\nwant:\n%s",
					code, tt.code, stdout, tt.stdout, stderr, tt.stderr)
			}
		})
	}
}

func TestRunJSON(t *testing.T) {
	fx := newFixture(t)
	if err := os.WriteFile(fx.path("more/broken.http"), []byte("GET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// One request: one result.
	code, stdout, _ := runCLI(t, false, "run", fx.path("api.http#echo"), "-e", "test")
	validateJSON(t, stdout)
	var one output.Document
	json.Unmarshal([]byte(stdout), &one)
	if r := one.Result; code != exitOK || r == nil || r.Ref != fx.path("api.http#echo") || r.Response.Status != 200 ||
		!r.Response.Untrusted || r.Request.URL != fx.host+"/echo?key={{token}}&env={{$env VEGTAM_TEST_KEY}}" || r.Timing == nil {
		t.Errorf("run file#ref = %d, %s", code, stdout)
	}

	// A directory without an environment: every request fails on its
	// variables, the broken file on parsing, and the rest is still run.
	code, stdout, stderr := runCLI(t, false, "run", fx.path("more"))
	validateJSON(t, stdout)
	want := `{"schema_version":1,"results":[{"ref":"DIR/more/broken.http","error":{"kind":"parse","message":"GET needs a URL",` +
		`"file":"DIR/more/broken.http","line":1}},{"ref":"DIR/more/plain.http#1","error":{"kind":"variable",` +
		`"message":"unresolved variables: host (no environment selected; use -e <name>)","file":"DIR/more/plain.http",` +
		`"line":3,"variables":["host"]}}]}` + "\n"
	if got := normalize(fx, stdout); code != exitUsage || got != want || strings.Count(stderr, "vegtam: ") != 2 {
		t.Errorf("run dir = %d\n%s\nwant\n%s\nstderr: %s", code, got, want, stderr)
	}

	// list reports the broken file and lists the rest.
	code, stdout, stderr = runCLI(t, false, "list", fx.path("more"))
	validateJSON(t, stdout)
	want = `{"schema_version":1,"error":{"kind":"parse","message":"GET needs a URL","file":"DIR/more/broken.http","line":1},` +
		`"requests":[{"ref":"DIR/more/plain.http#1","file":"DIR/more/plain.http","line":3,"index":1,"method":"GET",` +
		`"url":"{{host}}/plain","directives":[]}]}` + "\n"
	if got := normalize(fx, stdout); code != exitUsage || got != want || !strings.HasPrefix(stderr, "vegtam: ") {
		t.Errorf("list = %d\n%s\nwant\n%s\nstderr: %s", code, got, want, stderr)
	}
}

func TestRunUsageErrors(t *testing.T) {
	fx := newFixture(t)
	files := map[string]string{"ftp.http": "GET ftp://example.test/file\n", "a#b.http": "# @name one\nGET {{host}}/\n"}
	for name, src := range files {
		if err := os.WriteFile(fx.path(name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"run", fx.path("ftp.http"), "--dry-run"}, "URL ftp://example.test/file: want an http or https URL"},
		{[]string{"run", fx.path("api.http#nope")}, `api.http: no request "nope" (requests: echo, fail, refused, slow, binary, big, hidden)`},
		{[]string{"run", fx.path("api.http#")}, "api.http: name a request: "},
		{[]string{"run", fx.path("a#b.http#zzz")}, `a#b.http: no request "zzz" (requests: one)`},
		{[]string{"run", fx.path("more#1")}, "more: is a directory; #1 needs a .http file"},
		{[]string{"run", fx.path("none.http")}, "no such file or directory"},
		{[]string{"run", fx.dir, "--timeout", "-1s"}, "--timeout must not be negative"},
		{[]string{"run", fx.dir, "--max-body", "1KB2"}, "want bytes or a size such as 512KiB or 10MB"},
		{[]string{"run", fx.path("api.http#1"), "-e", "prod"}, `environment "prod" is not defined`},
		{[]string{"show", fx.path("api.http")}, "name a request: "},
		{[]string{"show", fx.path("api.http#echo"), "-e", "none"}, `environment "none" is not defined`},
		{[]string{"list", fx.path("none")}, "no such file or directory"},
	}
	for _, tt := range tests {
		code, stdout, stderr := runCLI(t, false, tt.args...)
		if code != exitUsage || !strings.Contains(stderr, tt.want) {
			t.Errorf("%q = %d, %q; want %d and %q", tt.args, code, stderr, exitUsage, tt.want)
		}
		validateJSON(t, stdout)
	}
}

func TestSchemaCommand(t *testing.T) {
	code, stdout, stderr := runCLI(t, true, "schema")
	if code != exitOK || stdout != output.Schema || stderr != "" || !json.Valid([]byte(stdout)) {
		t.Errorf("schema = %d, %d bytes, %q", code, len(stdout), stderr)
	}
}

func TestByteSize(t *testing.T) {
	for in, want := range map[string]string{"0": "0", "100": "100", "1024": "1KiB", "64KiB": "64KiB", "10MB": "10000000",
		"1mib": "1MiB", "2 GiB": "2GiB", "1kb": "1000"} {
		var s byteSize
		if err := s.Set(in); err != nil || s.String() != want {
			t.Errorf("Set(%q) = %v, %q; want %q", in, err, s.String(), want)
		}
	}
	for _, in := range []string{"", "-1", "1.5MiB", "1MiBs", "1TB", "99999999999GiB"} {
		var s byteSize
		if err := s.Set(in); err == nil {
			t.Errorf("Set(%q) = %d, want an error", in, s)
		}
	}
}

func TestPrintErrorEscapes(t *testing.T) {
	var out strings.Builder
	cfg := &Config{}
	cfg.errOut = masked{&out, cfg}
	cfg.printError(&output.Error{Message: "certificate is valid for evil\x1b]0;title\x07.example.test"})
	if want := `vegtam: certificate is valid for evil\x1b]0;title\x07.example.test` + "\n"; out.String() != want {
		t.Errorf("printError = %q, want %q", out.String(), want)
	}
}
