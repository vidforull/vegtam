package output

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// jwt is shaped as a JWT: its header and payload are base64url JSON, its
// signature made up.
const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlLWZha2U"

// redacted returns res redacted, and checks that redacting it again
// changes nothing.
func redacted(t *testing.T, res *Result) *Result {
	t.Helper()
	res.Redact()
	once, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	res.Redact()
	if twice, _ := json.Marshal(res); string(twice) != string(once) {
		t.Errorf("Redact again:\n%s\nwant\n%s", twice, once)
	}
	return res
}

func TestRedact(t *testing.T) {
	res := redacted(t, &Result{
		Response: &Response{
			Headers: []Header{
				{"Authorization", "Bearer abc"},
				{"Content-Type", "application/json"},
				{"Location", "https://app.example/cb#access_token=abc&state=s"},
				{"Set-Cookie", "sid=***; Path=/"},
				{"Set-Cookie", "lang=***"},
				{"Www-Authenticate", ""},
				{"X-Request-Id", "42"},
				{"X-Token", jwt},
			},
			Body: `{"access_token": "abc", "user": {"name": "Ada", "id_token": "` + jwt + `"}}`,
		},
		Asserts: []Assert{
			{"status == 200", true, "200"},
			{"header Set-Cookie exists", true, "sid=***; Path=/, lang=***"},
			{`jsonpath $.access_token == "x"`, false, `"abc"`},
			{"jsonpath $.user exists", true, `{"name":"Ada","id_token":"` + jwt + `"}`},
			{`jsonpath $.user.name == "Ada"`, true, `"Ada"`},
			{`jsonpath $["refresh-token"] exists`, false, "(absent)"},
			{"jsonpath $.token|length == 3", true, "3"},
			{`header X-Token == "x"`, false, jwt},
			{`body contains "Ada"`, true, `{"access_token": "abc", "user": {"name": "Ada", "id_tok...`},
		},
		Redirects: []Redirect{
			{Status: 302, Location: "/next?code=1&session=s"},
			{Status: 302, Location: "/done"},
		},
	})
	wantHeaders := []Header{
		{"Authorization", "***"},
		{"Content-Type", "application/json"},
		{"Location", "https://app.example/cb#access_token=***&state=s"},
		{"Set-Cookie", "***"},
		{"Set-Cookie", "***"},
		{"Www-Authenticate", ""},
		{"X-Request-Id", "42"},
		{"X-Token", "***"},
	}
	if !slices.Equal(res.Response.Headers, wantHeaders) {
		t.Errorf("headers = %+v\nwant      %+v", res.Response.Headers, wantHeaders)
	}
	if want := `{"access_token": "***", "user": {"name": "Ada", "id_token": "***"}}`; res.Response.Body != want {
		t.Errorf("body = %s\nwant   %s", res.Response.Body, want)
	}
	var actual []string
	for _, a := range res.Asserts {
		actual = append(actual, a.Actual)
	}
	wantActual := []string{
		"200", "***", "***", `{"name":"Ada","id_token":"***"}`, `"Ada"`, "(absent)", "3", "***",
		`{"access_token": "***", "user": {"name": "Ada", "id_tok...`,
	}
	if !slices.Equal(actual, wantActual) {
		t.Errorf("actual values = %q\nwant            %q", actual, wantActual)
	}
	if want := []string{"/next?code=1&session=***", "/done"}; res.Redirects[0].Location != want[0] || res.Redirects[1].Location != want[1] {
		t.Errorf("redirects = %+v", res.Redirects)
	}
	want := []string{
		"header Authorization", "header Location", "header Set-Cookie", "header X-Token",
		"$.access_token", "$.user.id_token",
		"assert header Set-Cookie exists", `assert jsonpath $.access_token == "x"`, "assert jsonpath $.user exists",
		`assert header X-Token == "x"`, `assert body contains "Ada"`,
		"redirect 1 location",
	}
	if !slices.Equal(res.Redacted, want) {
		t.Errorf("Redacted = %q\nwant       %q", res.Redacted, want)
	}
}

// TestRedactBody checks each kind of body: a form, text, JSON cut off, and
// one that is not text.
func TestRedactBody(t *testing.T) {
	for _, tt := range []struct {
		name     string
		resp     Response
		body     string
		redacted []string
	}{
		{
			"form",
			Response{
				Headers: []Header{{"Content-Type", "Application/X-WWW-Form-Urlencoded; charset=utf-8"}},
				Body:    "access_token=abc&scope=read&Refresh-Token=def&state=" + jwt,
			},
			"access_token=***&scope=read&Refresh-Token=***&state=***",
			[]string{"form access_token", "form Refresh-Token", "form state"},
		},
		{
			"form as JSON",
			Response{Headers: []Header{{"Content-Type", "application/x-www-form-urlencoded"}}, Body: ` {"token": "a"}`},
			` {"token": "***"}`,
			[]string{"$.token"},
		},
		{
			"text",
			Response{Headers: []Header{{"Content-Type", "text/plain"}}, Body: "Your token is " + jwt + ".\ntoken=abc\n"},
			"Your token is ***.\ntoken=abc\n",
			[]string{"body"},
		},
		{"text without a token", Response{Body: "token=abc"}, "token=abc", nil},
		{"cut off", Response{Body: `[{"id": 1, "refresh_token": "abc`, Truncated: true}, `[{"id": 1, "refresh_token": "***"`, []string{"$[0].refresh_token"}},
		{"byte order mark", Response{Body: "\uFEFF{\"token\": 1}"}, "\uFEFF{\"token\": \"***\"}", []string{"$.token"}},
		{"not text", Response{Body: "eyJhbGciOiJIUzI1NiJ9", Encoding: "base64"}, "eyJhbGciOiJIUzI1NiJ9", nil},
		{"empty", Response{}, "", nil},
	} {
		res := redacted(t, &Result{Response: &tt.resp})
		if res.Response.Body != tt.body || !slices.Equal(res.Redacted, tt.redacted) {
			t.Errorf("%s: body %q, Redacted %q; want %q, %q", tt.name, res.Response.Body, res.Redacted, tt.body, tt.redacted)
		}
	}
}

// TestRedactAssertForm checks that the actual value of a body assertion
// is redacted as the body is.
func TestRedactAssertForm(t *testing.T) {
	res := redacted(t, &Result{
		Response: &Response{Headers: []Header{{"Content-Type", "application/x-www-form-urlencoded"}}, Body: "password=p&a=b"},
		Asserts:  []Assert{{`body contains "a=b"`, true, "password=p&a=b"}, {`header X contains "y"`, false, "password=p"}},
	})
	if res.Asserts[0].Actual != "password=***&a=b" || res.Asserts[1].Actual != "password=p" {
		t.Errorf("asserts = %+v", res.Asserts)
	}
}

// TestRedactNoResponse checks a result without a response, such as one
// whose redirect was refused, and one that has entries already.
func TestRedactNoResponse(t *testing.T) {
	(*Result)(nil).Redact()
	res := redacted(t, &Result{Redirects: []Redirect{{Status: 302, Location: "https://evil.example/#id_token=" + jwt}}})
	if res.Redirects[0].Location != "https://evil.example/#id_token=***" || !slices.Equal(res.Redacted, []string{"redirect 1 location"}) {
		t.Errorf("Redact without a response = %+v, %q", res.Redirects, res.Redacted)
	}

	res = redacted(t, &Result{
		Response: &Response{Headers: []Header{{"Set-Cookie", "a=***"}, {"Set-Cookie", "b=***"}}},
		Redacted: []string{"header Set-Cookie"},
	})
	if !slices.Equal(res.Redacted, []string{"header Set-Cookie"}) {
		t.Errorf("Redact of a result with entries: %q", res.Redacted)
	}
}

func TestPathThroughKey(t *testing.T) {
	for p, want := range map[string]bool{
		"$.access_token": true, "$.data.access_token": true, `$.data["access-token"]`: true, `$.data."Token"`: true,
		`$["token"]`: true, `$.a.["token"]`: true, "$.session.id": true, "$.items[0].password": true,
		"$.tokens[0]": false, "$.items[0].name": false, "$": false, "": false, `$["a.token"]`: false, `$["a`: false,
		"$.token_type": false, "$[0]": false,
	} {
		if got := pathThroughKey(p); got != want {
			t.Errorf("pathThroughKey(%q) = %v, want %v", p, got, want)
		}
	}
	for expr, want := range map[string]bool{
		"header set-cookie exists": true, "jsonpath $.token exists": true, "jsonpath $.token|length == 3": false,
		`body contains "token"`: false, "header X-Token exists": true, "header X-Request-Id exists": false, "status == 200": false,
	} {
		subject, rest := splitWord(expr)
		if got := secretPlace(subject, rest); got != want {
			t.Errorf("secretPlace(%q) = %v, want %v", expr, got, want)
		}
	}
}

func TestWriteResponseRedacted(t *testing.T) {
	res := &Result{
		Response: &Response{Proto: "HTTP/1.1", Status: 200, Reason: "OK", Body: "{}"},
		Redacted: []string{"header Set-Cookie", "$.access_token", "form a\nb"},
		Asserts:  []Assert{{"status == 200", true, "200"}},
	}
	var b strings.Builder
	WriteResponse(&b, res, false, 0)
	if want := "\n{}\nredacted (no person at a terminal): header Set-Cookie, $.access_token, form a\\nb\n\n✓ status == 200\n"; !strings.HasSuffix(b.String(), want) {
		t.Errorf("WriteResponse:\n%s\nwant it to end with\n%s", b.String(), want)
	}
	res.Redacted = nil
	b.Reset()
	WriteResponse(&b, res, false, 0)
	if strings.Contains(b.String(), "redacted") {
		t.Errorf("WriteResponse of a result not redacted:\n%s", b.String())
	}
}
