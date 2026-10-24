package cli

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core/output"
)

// normalize replaces what changes from run to run: the test directory, the
// server address and timings.
func normalize(fx *fixture, s string) string {
	s = strings.ReplaceAll(s, fx.dir, "DIR")
	s = strings.ReplaceAll(s, fx.host, "HOST")
	s = strings.ReplaceAll(s, strings.TrimPrefix(fx.host, "http://"), "ADDR")
	s = regexp.MustCompile(`\((\d+(\.\d+)?(µs|ms|s))\)`).ReplaceAllString(s, "(TIME)")
	times := regexp.MustCompile(`\b(dns|connect|tls|ttfb|total) \d+(\.\d+)?(µs|ms|s)`)
	s = regexp.MustCompile(`(?m)^\* .*$`).ReplaceAllStringFunc(s, func(line string) string { return times.ReplaceAllString(line, "$1 T") })
	return regexp.MustCompile(`"total_ms": ?[0-9.]+`).ReplaceAllString(s, `"total_ms":0`)
}

// allowedText returns the origins the fixture's secrets may go to as the
// text of a dry run lists them: sorted, those of the hidden hosts masked.
func (fx *fixture) allowedText() string {
	origins := slices.Compact(slices.Sorted(slices.Values(fx.origins)))
	for i, o := range origins {
		if o == "http://"+fx.hidden || o == "http://"+fx.live {
			origins[i] = "***"
		}
	}
	return strings.Join(origins, ", ")
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
		{"--verbose and control characters", []string{"run", "more/plain.http#1", "-v"}, exitOK, `# timeouts: connect 10s, read 30s, max time 2m
GET HOST/plain
Accept: text/plain

HTTP/1.1 200 OK (TIME)
Content-Length: 26
Content-Type: text/plain
Date: Mon, 19 Oct 2026 00:00:00 GMT
* connected to ADDR · connect T ttfb T total T

plain\x1b]0;title\x07 \u202etext\u200b
`, ""},
		{"--verbose and a timeout", []string{"run", "api.http#slow", "-v", "--read-timeout", "50ms"}, exitNetwork, `# timeouts: connect 10s, read 50ms, max time 2m
GET HOST/slow?key={{token}}&env={{$env VEGTAM_TEST_KEY}}

* connected to ADDR · connect T total T
`, `vegtam: api.http:29: Get "HOST/slow?key={{token}}&env={{$env VEGTAM_TEST_KEY}}": no data from the server for 50ms (read timeout)` + "\n"},
		{"dry run", []string{"run", "api.http#echo", "--dry-run"}, exitOK, `# timeouts: connect 10s, read 30s, max time 2m
POST HOST/echo?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
Authorization: Bearer {{token}}
X-Api-Key: {{$env VEGTAM_TEST_KEY}}
Content-Type: application/json

{"token": "{{token}}", "key": "{{$env VEGTAM_TEST_KEY}}"}

Secrets:
  {{token}}                 ORIGINS
  {{$env VEGTAM_TEST_KEY}}  ORIGINS
`, ""},
		{"several requests", []string{"run", "more", "--fail", "--max-body", "5"}, exitOK, `### more/plain.http#1
HTTP/1.1 200 OK (TIME)

plain
[truncated: the body is longer than --max-body]
`, ""},
		{
			"errors",
			[]string{"run", "api.http", "--fail", "--max-time", "50ms", "--max-body", "0"},
			exitStatus,
			"### api.http#echo\nHTTP/1.1 200 OK (TIME)\n[truncated: the body is longer than --max-body]\n\n✓ status == 200\n\n" +
				"### api.http#fail\nHTTP/1.1 500 Internal Server Error (TIME)\n[truncated: the body is longer than --max-body]\n\n" +
				"### api.http#refused\n\n### api.http#slow\n\n" +
				"### api.http#binary\nHTTP/1.1 200 OK (TIME)\n[truncated: the body is longer than --max-body]\n\n" +
				"### api.http#big\nHTTP/1.1 200 OK (TIME)\n[truncated: the body is longer than --max-body]\n\n" +
				"### api.http#hidden\n\n### api.http#hops\n",
			"vegtam: api.http:20: HTTP 500 Internal Server Error\n" +
				`vegtam: api.http:25: Get "http://127.0.0.1:PORT/?key={{token}}&env={{$env VEGTAM_TEST_KEY}}": dial tcp 127.0.0.1:PORT: connect: connection refused` + "\n" +
				`vegtam: api.http:29: Get "HOST/slow?key={{token}}&env={{$env VEGTAM_TEST_KEY}}": no complete response within 50ms (max time)` + "\n" +
				`vegtam: api.http:41: Get "{{base}}/?key={{token}}": dial tcp ***: connect: connection refused` + "\n" +
				`vegtam: api.http:45: Get "/hops/xxxxxxxxxxx?key=***&env=***": stopped after 10 redirects` + "\n",
		},
		{"show as written", []string{"show", "api.http#2"}, exitOK, `# timeouts: connect 10s, read 30s, max time 2m
GET {{host}}/fail?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
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
api.http#hops      GET     {{host}}/hops?key={{token}}&env={{$env VEGTAM_TEST_KEY}}
more/plain.http#1  GET     {{host}}/plain
`, ""},
	}
	t.Chdir(fx.dir)
	port := regexp.MustCompile(`127\.0\.0\.1:\d+`)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			if args[0] == "run" {
				args = append(args, "-e", "test", "--confirm")
			}
			code, stdout, stderr := runCLI(t, true, args...)
			stderr = port.ReplaceAllString(normalize(fx, stderr), "127.0.0.1:PORT")
			stdout = normalize(fx, strings.ReplaceAll(stdout, fx.allowedText(), "ORIGINS"))
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
	code, stdout, _ := runCLI(t, false, "run", fx.path("api.http#echo"), "-e", "test", "--confirm")
	validateJSON(t, stdout)
	var one output.Document
	decode(t, stdout, &one)
	if r := one.Result; code != exitOK || r == nil || r.Ref != fx.path("api.http#echo") || r.Response.Status != 200 ||
		!r.Response.Untrusted || r.Request.URL != fx.host+"/echo?key={{token}}&env={{$env VEGTAM_TEST_KEY}}" || r.Timing == nil {
		t.Errorf("run file#ref = %d, %s", code, stdout)
	}

	// A directory without an environment: every request fails on its
	// variables, the broken file on parsing, and the rest is still run.
	code, stdout, stderr := runCLI(t, false, "run", fx.path("more"))
	validateJSON(t, stdout)
	want := `{"schema_version":1,"results":[{"ref":"DIR/more/broken.http","error":{"kind":"parse","message":"GET needs a URL",` +
		`"file":"DIR/more/broken.http","line":1}},{"ref":"DIR/more/plain.http#1",` +
		`"transport":{"connect_timeout_ms":10000,"read_timeout_ms":30000,"max_time_ms":120000},"error":{"kind":"variable",` +
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

func TestRunAsserts(t *testing.T) {
	fx := newFixture(t)
	src := `# @name text
# @assert status == 200
# @assert status in 500..599
# @assert header Content-Type == "text/plain"
# @assert body contains "nope"
# @assert duration < 1h
GET {{host}}/plain

###
# @name echo
# @assert jsonpath $.echo.key == "nope"
# @assert jsonpath $.echo.authorization contains "Bearer"
# @assert header X-Echo exists
POST {{host}}/echo?key={{token}}
Authorization: Bearer {{token}}

###
# @name fail
# @assert status == 200
GET {{host}}/fail
`
	if err := os.WriteFile(fx.path("checks.http"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(fx.dir)

	// Text: the response, then a line per assertion.
	code, stdout, stderr := runCLI(t, true, "run", "checks.http#text", "-e", "test")
	want := `HTTP/1.1 200 OK (TIME)

plain\x1b]0;title\x07 \u202etext\u200b

✓ status == 200
✗ status in 500..599 (actual: 200)
✓ header Content-Type == "text/plain"
✗ body contains "nope" (actual: plain\x1b]0;title\x07 \u202etext\u200b)
✓ duration < 1h
`
	wantErr := `vegtam: checks.http:3: 2 of 5 assertions failed: status in 500..599; body contains "nope"` + "\n"
	if got := normalize(fx, stdout); code != exitAssert || got != want || stderr != wantErr {
		t.Errorf("run text = %d\n%s\nwant\n%s\nstderr: %q, want %q", code, got, want, stderr, wantErr)
	}

	// JSON: the outcomes next to the response, actual values masked.
	for _, mode := range [][]string{nil, {"--json"}, {"--json", "-v"}} {
		code, stdout, stderr = runCLI(t, len(mode) > 0, append([]string{"run", "checks.http#echo", "-e", "test", "--confirm"}, mode...)...)
		validateJSON(t, stdout)
		var doc output.Document
		decode(t, stdout, &doc)
		wantAsserts := []output.Assert{
			{Expression: `jsonpath $.echo.key == "nope"`, Actual: `"***"`},
			{Expression: `jsonpath $.echo.authorization contains "Bearer"`, Passed: true, Actual: `"Bearer ***"`},
			{Expression: "header X-Echo exists", Passed: true, Actual: "key=***"},
		}
		if r := doc.Result; code != exitAssert || r == nil || r.Response == nil || r.Error == nil || r.Error.Kind != "assert" ||
			!slices.Equal(r.Asserts, wantAsserts) {
			t.Errorf("run %v = %d\n%s", mode, code, stdout)
		}
		if found := fx.leaks(stdout + stderr); len(found) > 0 {
			t.Errorf("secret forms %q in the output\n%s\n%s", found, stdout, stderr)
		}
	}

	// The highest code wins: 4 for the status with --fail, over 1. A dry
	// run checks nothing.
	for _, tt := range []struct {
		args []string
		code int
	}{
		{[]string{"run", "checks.http", "-e", "test", "--confirm"}, exitAssert},
		{[]string{"run", "checks.http", "-e", "test", "--fail", "--confirm"}, exitStatus},
		{[]string{"run", "checks.http", "-e", "test", "--dry-run"}, exitOK},
	} {
		code, stdout, _ := runCLI(t, false, tt.args...)
		validateJSON(t, stdout)
		if code != tt.code || tt.code == exitOK && strings.Contains(stdout, `"asserts"`) {
			t.Errorf("%q = %d, want %d\n%s", tt.args, code, tt.code, stdout)
		}
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
		{[]string{"run", fx.path("api.http#nope")}, `api.http: no request "nope" (requests: echo, fail, refused, slow, binary, big, hidden, hops)`},
		{[]string{"run", fx.path("api.http#")}, "api.http: name a request: "},
		{[]string{"run", fx.path("a#b.http#zzz")}, `a#b.http: no request "zzz" (requests: one)`},
		{[]string{"run", fx.path("more#1")}, "more: is a directory; #1 needs a .http file"},
		{[]string{"run", fx.path("none.http")}, "no such file or directory"},
		{[]string{"run", fx.dir, "--max-time", "-1s"}, `invalid argument "-1s" for "--max-time" flag: want a time such as 30 (seconds)`},
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
	for in, want := range map[string]string{
		"0": "0", "100": "100", "1024": "1KiB", "64KiB": "64KiB", "10MB": "10000000",
		"1mib": "1MiB", "2 GiB": "2GiB", "1kb": "1000",
	} {
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

func TestDirectivesSummary(t *testing.T) {
	got := directives([]output.Directive{
		{Kind: "assert", Value: "status == 200"},
		{Kind: "tag", Value: "a"},
		{Kind: "no-log"},
		{Kind: "capture", Value: "t = $.t"},
		{Kind: "assert", Value: "duration < 1s"},
		{Kind: "tag", Value: "b"},
		{Kind: "note", Value: "Deletes the user, for good"},
	})
	if want := "2 @assert, 1 @capture, @tag a b, @no-log, @note Deletes the user, for good"; got != want {
		t.Errorf("directives = %q, want %q", got, want)
	}
	if got := directives([]output.Directive{{Kind: "note"}}); got != "@note" {
		t.Errorf("an empty note: %q", got)
	}
}
