package curl

import (
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
)

func lit(s string) core.Segment { return core.Segment{Text: s} }

func secret(name string) core.Segment { return core.Segment{Secret: &core.Secret{Name: name}} }

func captured(name string) core.Segment {
	return core.Segment{Secret: &core.Secret{Name: name, Capture: true}}
}

func request(method string, url core.Text, headers []core.PreparedHeader, body core.Text) *core.Prepared {
	r := &core.Request{Method: method, Source: core.Source{File: "api/users.http", Line: 3}}
	return &core.Prepared{Request: r, Method: method, URL: url, Headers: headers, Body: body}
}

func TestCommand(t *testing.T) {
	withFile := request("PUT", core.Text{lit("https://x.test/up")}, nil, core.Text{lit("the file, read")})
	withFile.Request.BodyFile = "./data/it's.json"
	dash := request("POST", core.Text{lit("https://x.test/up")}, nil, core.Text{lit("{}")})
	dash.Request.BodyFile, dash.Request.Source.File = "-", "users.http"
	for _, tt := range []struct {
		name string
		p    *core.Prepared
		want string
	}{
		{
			"get", request("GET", core.Text{lit("https://x.test/a?b=1&c=it's")}, nil, nil),
			"curl --path-as-is 'https://x.test/a?b=1&c=it'\\''s'\n",
		},
		{
			"secrets everywhere", request("POST",
				core.Text{lit("https://x.test/u/"), secret("token"), lit("?k="), secret("$env API_KEY")},
				[]core.PreparedHeader{
					{Name: "Authorization", Value: core.Text{lit("Bearer "), secret("token")}},
					{Name: "X-Session", Value: core.Text{captured("session")}},
					{Name: "X-Cmd", Value: core.Text{secret("$cmd login")}},
				},
				core.Text{lit(`{"t": "`), secret("token"), lit(`"}`)}),
			`# Set first: token for {{token}}, API_KEY for {{$env API_KEY}}, session for {{session}} from an @capture, login for {{$cmd login}}
: "${token?}" "${API_KEY?}" "${session?}" "${login?}" && curl --globoff --path-as-is 'https://x.test/u/'"$token"'?k='"$API_KEY" \
  -H 'Authorization: Bearer '"$token" \
  -H 'X-Session: '"$session" \
  -H 'X-Cmd: '"$login" \
  -H 'Content-Type:' \
  --data-raw '{"t": "'"$token"'"}'
`,
		},
		{
			"methods and an empty header", request("DELETE", core.Text{lit("http://x.test/[1]/./a")},
				[]core.PreparedHeader{{Name: "X-Empty", Value: nil}, {Name: "Content-Type", Value: core.Text{lit("text/plain")}}},
				core.Text{lit("@not-a-file")}),
			"curl -X DELETE --globoff --path-as-is 'http://x.test/[1]/./a' \\\n  -H 'X-Empty;' \\\n" +
				"  -H 'Content-Type: text/plain' \\\n  --data-raw '@not-a-file'\n",
		},
		{"head", request("HEAD", core.Text{lit("http://x.test/")}, nil, core.Text{lit("")}), "curl --head --path-as-is 'http://x.test/'\n"},
		{
			"get with a body", request("GET", core.Text{lit("http://x.test/")}, nil, core.Text{lit("q")}),
			"curl -X GET --path-as-is 'http://x.test/' \\\n  -H 'Content-Type:' \\\n  --data-raw 'q'\n",
		},
		{
			"post without a body", request("POST", core.Text{lit("http://x.test/")}, nil, nil),
			"curl --path-as-is 'http://x.test/' \\\n  -H 'Content-Type:' \\\n  --data-raw ''\n",
		},
		{
			"patch without a body", request("PATCH", core.Text{lit("http://x.test/")}, nil, core.Text{lit("")}),
			"curl -X PATCH --path-as-is 'http://x.test/' \\\n  -H 'Content-Type:' \\\n  --data-raw ''\n",
		},
		{
			"delete without a body", request("DELETE", core.Text{lit("http://x.test/")}, nil, nil),
			"curl -X DELETE --path-as-is 'http://x.test/'\n",
		},
		{"odd method", request("M'X", core.Text{lit("http://x.test/")}, nil, nil), "curl -X 'M'\\''X' --path-as-is 'http://x.test/'\n"},
		{
			"body file", withFile,
			"curl -X PUT --path-as-is 'https://x.test/up' \\\n  -H 'Content-Type:' \\\n  --data-binary '@./api/data/it'\\''s.json'\n",
		},
		{"body file named -", dash, "curl --path-as-is 'https://x.test/up' \\\n  -H 'Content-Type:' \\\n  --data-binary '@./-'\n"},
		{
			"a large body", request("PUT", core.Text{lit("http://x.test/")}, nil, core.Text{lit(strings.Repeat("x", 1<<20+1))}),
			"curl -X PUT --path-as-is 'http://x.test/' \\\n  -H 'Content-Type:' \\\n  -H 'Expect:' \\\n  --data-raw '" +
				strings.Repeat("x", 1<<20+1) + "'\n",
		},
		{
			"control characters", request("POST", core.Text{lit("http://x.test/")}, nil,
				core.Text{lit("{\n\t\"a\": \"it's \\\\ \x1b[31m\u009b\xff\r\"\n}")}),
			`curl --path-as-is 'http://x.test/' \
  -H 'Content-Type:' \
  --data-raw $'{\n\t"a": "it\'s \\\\ \x1b[31m\xc2\x9b\xff\r"\n}'
`,
		},
		{
			"multi-line body", request("POST", core.Text{lit("http://x.test/")}, nil, core.Text{lit("a\nb\n")}),
			"curl --path-as-is 'http://x.test/' \\\n  -H 'Content-Type:' \\\n  --data-raw 'a\nb\n'\n",
		},
		{
			"names that clash", request("GET",
				core.Text{
					lit("http://x.test/"), secret("api.key"), secret("api_key"), secret("$env api_key"), secret("$cmd 9x"),
					secret("api.key"), secret("path"), secret("$env PATH"), captured("status"), secret("BASH_ENV"),
				}, nil, nil),
			"# Set first: api_key for {{api.key}}, api_key_2 for {{api_key}}, api_key_3 for {{$env api_key}}, _9x for {{$cmd 9x}}, " +
				"path_2 for {{path}}, PATH for {{$env PATH}}, status_2 for {{status}} from an @capture, BASH_ENV_2 for {{BASH_ENV}}\n" +
				`: "${api_key?}" "${api_key_2?}" "${api_key_3?}" "${_9x?}" "${path_2?}" "${PATH?}" "${status_2?}" "${BASH_ENV_2?}" && ` +
				`curl --globoff --path-as-is 'http://x.test/'"$api_key""$api_key_2""$api_key_3""$_9x""$api_key""$path_2""$PATH""$status_2""$BASH_ENV_2"` + "\n",
		},
	} {
		if got, err := Command(tt.p, nil); err != nil || got != tt.want {
			t.Errorf("%s: %v\n%s\nwant\n%s", tt.name, err, got, tt.want)
		}
	}
}

// TestCommandSecretInText checks that a secret value in the text of a
// request, outside a placeholder, stops the command wherever it is,
// however quoting would change it.
func TestCommandSecretInText(t *testing.T) {
	m := core.NewMasker([]string{"pa'ss\tW0rd"})
	for _, tt := range []struct {
		p     *core.Prepared
		where string
	}{
		{request("GET", core.Text{lit("http://x.test/?p=pa'ss\tW0rd")}, nil, nil), "the URL"},
		{request("GET", core.Text{lit("http://x.test/?p=pa%27ss%09W0rd")}, nil, nil), "the URL"},
		{request("GET", core.Text{lit("http://x.test/")}, []core.PreparedHeader{{Name: "X", Value: core.Text{lit("pa'ss"), lit("\tW0rd")}}}, nil), "header X"},
		{request("POST", core.Text{lit("http://x.test/")}, nil, core.Text{lit(`{"p": "pa'ss\tW0rd"}`)}), "the body"},
	} {
		if got, err := Command(tt.p, m); !errors.Is(err, ErrSecret) || got != "" || !strings.HasSuffix(err.Error(), ", in "+tt.where) {
			t.Errorf("%s: %q, %v; want ErrSecret, in %s", tt.p.URL.Masked(), got, err, tt.where)
		}
	}
	if _, err := Command(request("GET", core.Text{lit("http://x.test/"), secret("token")}, nil, nil), m); err != nil {
		t.Errorf("a secret in a placeholder: %v", err)
	}
}

// TestCommandInShell runs commands in bash, with a curl that prints its
// arguments, and the secrets in shell variables: curl gets what vegtam
// would send, with each value in its place, however odd.
func TestCommandInShell(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("the test needs bash: %v", err)
	}
	values := map[string]string{
		"token":   `t0k'en "$HOME" $(false) ` + "`x` \\ [1-2] {a,b} *",
		"API_KEY": "k+y/=",
		"session": "s\nid",
	}
	body := "{\n\t\"it's\": \"\x01\u009b\xff\", \"t\": \""
	p := request("PATCH",
		core.Text{lit("https://x.test/u/"), secret("token"), lit("?k="), secret("$env API_KEY"), lit("&a[]=1")},
		[]core.PreparedHeader{
			{Name: "Authorization", Value: core.Text{lit("Bearer "), secret("token")}},
			{Name: "X-Session", Value: core.Text{captured("session")}},
		},
		core.Text{lit(body), secret("token"), lit(`"}`)})
	want := []string{
		"-X", "PATCH", "--globoff", "--path-as-is", "https://x.test/u/" + values["token"] + "?k=k+y/=&a[]=1",
		"-H", "Authorization: Bearer " + values["token"], "-H", "X-Session: s\nid", "-H", "Content-Type:",
		"--data-raw", body + values["token"] + `"}`,
	}
	cmd, err := Command(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	script := "curl() { printf '%s\\0' \"$@\"; }\n" + cmd
	sh := exec.CommandContext(t.Context(), bash, "--noprofile", "--norc", "-c", script)
	for name, v := range values {
		sh.Env = append(sh.Env, name+"="+v)
	}
	out, err := sh.Output()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, cmd)
	}
	if got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00"); !slices.Equal(got, want) {
		t.Errorf("curl got\n%q\nwant\n%q\nfrom\n%s", got, want, cmd)
	}
	// Pasted with a variable left out, it stops before curl runs.
	sh = exec.CommandContext(t.Context(), bash, "--noprofile", "--norc", "-c", script)
	sh.Env = []string{"token=x", "API_KEY=y"}
	if out, err = sh.Output(); err == nil || len(out) > 0 {
		t.Errorf("without $session: %v, curl got %q", err, out)
	}
	for _, v := range values {
		if strings.Contains(cmd, v) {
			t.Errorf("the command holds the value %q:\n%s", v, cmd)
		}
	}
}
