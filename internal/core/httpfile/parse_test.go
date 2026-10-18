package httpfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
)

// summary renders the requests of f one per line, compactly.
func summary(f *core.File) string {
	var b strings.Builder
	for _, r := range f.Requests {
		fmt.Fprintf(&b, "%d %s %s", r.Source.Line, r.Method, r.URL)
		if r.Name != "" {
			fmt.Fprintf(&b, " #%s", r.Name)
		}
		if r.Version != "" {
			fmt.Fprintf(&b, " %s", r.Version)
		}
		for _, h := range r.Headers {
			fmt.Fprintf(&b, " [%s: %s]", h.Name, h.Value)
		}
		for _, d := range r.Directives {
			fmt.Fprintf(&b, " @%s(%s):%d", d.Kind, d.Value, d.Line)
		}
		if r.Body != "" {
			fmt.Fprintf(&b, " body=<<%s>>", strings.ReplaceAll(r.Body, "\n", `\n`))
		}
		if r.BodyFile != "" {
			fmt.Fprintf(&b, " <%s", r.BodyFile)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func TestParse(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"one request", "GET https://example.com/users\n", "1 GET https://example.com/users\n"},
		{"several requests", `### List users
# @name list
GET https://api.example.test/users HTTP/1.1
Accept: application/json

###
// @name create
POST https://api.example.test/users
Content-Type: application/json

{"name": "{{user}}"}

### no name, no body
DELETE {{host}}/users/1`,
			"3 GET https://api.example.test/users #list HTTP/1.1 [Accept: application/json]\n" +
				`8 POST https://api.example.test/users #create [Content-Type: application/json] body=<<{"name": "{{user}}"}>>` + "\n" +
				"14 DELETE {{host}}/users/1\n"},
		{"body kept verbatim, blank edges trimmed", "POST https://example.com/notes\n\n\nfirst\n# not a comment\n\nlast\n\n\n",
			`1 POST https://example.com/notes body=<<first\n# not a comment\n\nlast>>` + "\n"},
		{"body from file", "POST https://example.com/upload\nContent-Type: application/json\n\n< ./payload.json\n",
			"1 POST https://example.com/upload [Content-Type: application/json] <./payload.json\n"},
		{"CRLF and BOM", "\ufeff# @name crlf\r\nGET https://example.com\r\nAccept: */*\r\n\r\nbody\r\n",
			"2 GET https://example.com #crlf [Accept: */*] body=<<body>>\n"},
		{"comments and directives", `# a comment
// another comment
# @name check
#@tag smoke
GET https://example.com/health
# a comment among headers
// @assert status == 200
# @capture token = $.token
Accept: application/json`,
			"5 GET https://example.com/health #check [Accept: application/json] " +
				"@tag(smoke):4 @assert(status == 200):7 @capture(token = $.token):8\n"},
		{"placeholders with spaces", "GET {{ $env BASE_URL }}/items?q={{query}} HTTP/2\nAuthorization: Bearer {{$env TOKEN}}",
			"1 GET {{ $env BASE_URL }}/items?q={{query}} HTTP/2 [Authorization: Bearer {{$env TOKEN}}]\n"},
		{"empty file", "\n# only a comment\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Parse("x.http", []byte(tt.src))
			if err != nil {
				t.Fatal(err)
			}
			if got := summary(f); got != tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name, src string
		line      int
		want      string
	}{
		{"duplicate name", "# @name a\nGET https://example.com\n###\n# @name a\nGET https://example.com", 4,
			`duplicate request name "a" (first on line 1)`},
		{"header without colon", "POST https://example.com\nContent-Type: application/json\n{\"a\": 1}", 3,
			`expected a header "Name: value"`},
		{"unclosed placeholder in header", "GET https://example.com\nAuthorization: Bearer {{token\n", 2,
			`header Authorization: unclosed placeholder "{{token"`},
		{"invalid placeholder", "GET https://example.com/{{a b}}", 1, `URL: invalid placeholder "{{a b}}"`},
		{"unknown line", "hello world", 1, `expected a request line "METHOD URL", got "hello world"`},
		{"lowercase method", "get https://example.com", 1, "expected a request line"},
		{"no URL", "\nGET", 2, "GET needs a URL"},
		{"file variable", "@host = example.com", 1, "file variables"},
		{"unknown directive", "# @no-redirect\nGET https://example.com", 1, "unknown directive @no-redirect"},
		{"directive without value", "# @assert\nGET https://example.com", 1, "@assert needs a value"},
		{"orphan directive", "GET https://example.com\n###\n# @name lost\n", 3, "not followed by a request line"},
		{"numeric name", "# @name 2\nGET https://example.com", 1, "is a number"},
		{"bad name", "# @name a b\nGET https://example.com", 1, "invalid request name"},
		{"two names", "# @name a\n# @name b\nGET https://example.com", 2, `request already named "a"`},
		{"body file and more", "POST https://example.com\n\n< ./a.json\nmore", 4, "must be the whole body"},
		{"multipart body file", "POST https://example.com\n\n--b\n\n< ./a.json\n--b--", 5, "inside a body"},
		{"body file with variables", "POST https://example.com\n\n<@ ./a.json", 3, "(<@) are not supported yet"},
		{"response handler", "GET https://example.com\n\n> {% client.test() %}", 3, "response handlers"},
		{"missing separator", "GET https://example.com/a\n\nGET https://example.com/b", 3, "separate requests with ###"},
		{"directive in body", "POST https://example.com\n\n{}\n# @name b", 4, "separate requests with ###"},
		{"unclosed placeholder in body", "POST https://example.com\n\n{\"a\": \"{{x\"}", 3, "body: unclosed placeholder"},
		{"HTTP version", "GET https://example.com HTTP/3", 1, `unsupported HTTP version "HTTP/3"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("x.http", []byte(tt.src))
			want := fmt.Sprintf("x.http:%d: ", tt.line)
			if err == nil || !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v; want %q...%q", err, want, tt.want)
			}
			if e, ok := err.(*core.Error); !ok || e.Kind != core.KindParse {
				t.Errorf("error is %T %+v, want a parse *core.Error", err, err)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"b.http", "a/z.http", "a/y.txt", "c.http", ".hidden/x.http", "bad/bad.http"} {
		src := "GET https://example.com/" + name
		if name == "bad/bad.http" {
			src = "nonsense"
		}
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, errs := Load(dir, filepath.Join(dir, ".hidden/x.http"), filepath.Join(dir, "missing"), filepath.Join(dir, "a/y.txt"))
	var got []string
	for _, f := range c.Files {
		got = append(got, strings.TrimPrefix(f.Path, dir+"/"))
	}
	if want := "a/z.http b.http c.http .hidden/x.http a/y.txt"; strings.Join(got, " ") != want {
		t.Errorf("files = %q, want %q", got, want)
	}
	if len(errs) != 2 || !strings.Contains(errs[0].Error(), "bad.http:1: expected a request line") ||
		!strings.Contains(errs[1].Error(), "no such file") {
		t.Errorf("errors = %v, want bad.http parse error and missing file", errs)
	}
	if _, errs := Load(filepath.Join(dir, ".hidden")); len(errs) != 0 {
		t.Errorf("Load(.hidden) = %v; a dot directory named explicitly is searched", errs)
	}
	if _, errs := Load(filepath.Join(dir, "bad")); len(errs) != 1 {
		t.Errorf("Load(bad) errors = %v, want one", errs)
	}
	if _, errs := Load(t.TempDir()); len(errs) != 1 || !strings.Contains(errs[0].Error(), "no .http files in") {
		t.Errorf("Load(empty dir) errors = %v, want no .http files", errs)
	}
}

func TestFind(t *testing.T) {
	f, err := Parse("x.http", []byte("# @name first\nGET https://example.com/1\n###\nGET https://example.com/2"))
	if err != nil {
		t.Fatal(err)
	}
	for ref, want := range map[string]string{"first": "/1", "1": "/1", "2": "/2", "3": "", "0": "", "nope": ""} {
		r, ok := f.Find(ref)
		if ok != (want != "") || ok && !strings.HasSuffix(r.URL, want) {
			t.Errorf("Find(%q) = %v, %v; want %q", ref, r, ok, want)
		}
	}
}
