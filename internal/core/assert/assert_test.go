package assert

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/exec"
)

func response(status int, body string) *exec.Response {
	return &exec.Response{Status: status, Duration: 120 * time.Millisecond, Body: []byte(body),
		Header: http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"a=1", "sid=x9"}}}
}

const doc = `{"ok": true, "name": "Ada Lovelace", "deleted_at": null, "items": [{"id": 42}, {"id": 43.0}],
	"big": 12345678901234567890, "tags": ["a"], "token": "t-1", "first-name": "Ada"}`

func TestCheck(t *testing.T) {
	tests := []struct {
		expr   string
		passed bool
		actual string
	}{
		{"status == 200", true, "200"},
		{"status != 404", true, "200"},
		{"status < 300", true, "200"},
		{"status >= 201", false, "200"},
		{"status in 200..299", true, "200"},
		{"status in 300..399", false, "200"},
		{`header Content-Type == "application/json"`, true, "application/json"},
		{`header content-type contains "json"`, true, "application/json"},
		{`header Set-Cookie == "sid=x9"`, true, "a=1, sid=x9"},
		{`header Set-Cookie == "sid"`, false, "a=1, sid=x9"},
		{"header X-Request-Id exists", false, "(absent)"},
		{`body contains "\"ok\": true"`, true, doc},
		{`body contains "Grace"`, false, doc},
		{"jsonpath $.ok == true", true, "true"},
		{"jsonpath $.ok == false", false, "true"},
		{`jsonpath $.name == "Ada Lovelace"`, true, `"Ada Lovelace"`},
		{"jsonpath $.items[0].id == 42", true, "42"},
		{"jsonpath $.items[1].id == 43", true, "43.0"},
		{"jsonpath $.big == 12345678901234567890", true, "12345678901234567890"},
		{"jsonpath $.big == 12345678901234567891", false, "12345678901234567890"},
		{`jsonpath $.items[0] == {"id": 42}`, true, `{"id":42}`},
		{"jsonpath $.items|length == 2", true, "2"},
		{"jsonpath $.deleted_at exists", true, "null"},
		{"jsonpath $.deleted_at == null", true, "null"},
		{"jsonpath $.missing exists", false, "(absent)"},
		{"jsonpath $.missing == null", false, "(absent)"},
		{"jsonpath $.items[5] exists", false, "(absent)"},
		{"jsonpath $.items[-1].id exists", true, "43.0"},
		{"jsonpath $.ok.x exists", false, "(the path does not fit the body)"},
		{"jsonpath $.name[0] exists", false, "(the path does not fit the body)"},
		{`jsonpath $["first-name"] == "Ada"`, true, `"Ada"`},
		{`jsonpath $."first-name" exists`, true, `"Ada"`},
		{"jsonpath $.tags[0] == \"a\"", true, `"a"`},
		{"jsonpath $|length == 8", true, "8"},
		{"jsonpath $.name|length == 12", true, "12"},
		{`jsonpath $.name contains "Love"`, true, `"Ada Lovelace"`},
		{`jsonpath $.tags contains "a"`, false, `["a"]`},
		{"jsonpath $ exists", true, ""},
		{"duration < 500ms", true, "120ms"},
		{"duration <= 100ms", false, "120ms"},
	}
	r := &Response{Response: response(200, doc), ctx: context.Background()}
	for _, tt := range tests {
		a, err := Parse(tt.expr)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.expr, err)
			continue
		}
		passed, actual := a.check(r)
		if passed != tt.passed || tt.actual != "" && actual != tt.actual {
			t.Errorf("%s = %v, %q; want %v, %q", tt.expr, passed, actual, tt.passed, tt.actual)
		}
	}
}

func TestCheckBodies(t *testing.T) {
	tests := []struct {
		body      string
		truncated bool
		actual    string
	}{
		{"<html>", false, "(the body is not JSON)"},
		{`{"ok": true} {"ok": true}`, false, "(the body is not JSON)"},
		{`{"ok": true}`, true, "(the body was cut off at the size limit)"},
	}
	a, _ := Parse("jsonpath $.ok == true")
	for _, tt := range tests {
		resp := response(200, tt.body)
		resp.Truncated = tt.truncated
		if passed, actual := a.check(&Response{Response: resp, ctx: context.Background()}); passed || actual != tt.actual {
			t.Errorf("body %q = %v, %q; want a failure, %q", tt.body, passed, actual, tt.actual)
		}
	}
	// The form of an outcome says how to mask it.
	for expr, want := range map[string]Form{"status == 200": Text, `body contains "x"`: Body, "jsonpath $.ok exists": JSON,
		"header X exists": Text, "duration < 1s": Text} {
		r := Evaluate(context.Background(), request("assert "+expr), response(200, doc))
		if r.Outcomes[0].Form != want {
			t.Errorf("%s: form %v, want %v", expr, r.Outcomes[0].Form, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	tests := map[string]string{
		"status 200":                  "want status <op> <code>",
		"status == 2xx":               "want status <op> <code>",
		"status in 299..200":          "want status <op> <code>",
		"status in 200-299":           "want status <op> <code>",
		"header == \"x\"":             "want header <Name>",
		"header X-A exists 1":         "want header <Name>",
		"header X-A == x":             "want header <Name>",
		"header X-A ~= \"x\"":         "want header <Name>",
		"body == \"x\"":               "want body contains",
		"body contains ok":            "want body contains",
		"jsonpath .ok == true":        "want a path starting with $",
		"jsonpath $ok == true":        "want a path starting with $",
		"jsonpath $.ok == yes":        "want jsonpath <path> == <JSON value>",
		"jsonpath $.ok == true false": "want jsonpath <path> == <JSON value>",
		"jsonpath $.ok":               "want jsonpath <path> == <JSON value>",
		"jsonpath $.a[ == 1":          "path $.a[: unexpected EOF",
		"jsonpath $.a|$x == 1":        "want a plain path",
		"jsonpath $.a|input exists":   "want a plain path",
		// Nothing that computes a new value, which could be a secret in a
		// form masking does not know.
		"jsonpath $.a[1:] exists":            "want a plain path",
		"jsonpath $.a|ascii_downcase exists": "want a plain path",
		"jsonpath $.a|@base64 exists":        "want a plain path",
		"jsonpath $|env.HOME exists":         "want a plain path",
		"jsonpath $.a[] exists":              "want a plain path",
		"jsonpath $.a? exists":               "want a plain path",
		`jsonpath $["a\(1)"] exists`:         "want a plain path",
		"jsonpath $.a[.b] exists":            "want a plain path",
		"jsonpath $.a[1.5] exists":           "want a plain path",
		"jsonpath $.a|length|length == 1":    "want a plain path",
		"jsonpath $.a|.b exists":             "want a plain path",
		"duration < 500":                     "want duration <",
		"duration > 1s":                      "want duration <",
		"duration < -1s":                     "want duration <",
		"size < 10":                          `unknown check "size"`,
		`header X-A contains "unterminated`:  "want header <Name>",
	}
	for expr, want := range tests {
		if _, err := Parse(expr); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want an error with %q", expr, err, want)
		}
	}
}

func request(directives ...string) *core.Request {
	r := &core.Request{Method: "GET", URL: "https://example.test", Source: core.Source{File: "a.http", Line: 9}}
	for i, d := range directives {
		kind, value, _ := strings.Cut(d, " ")
		r.Directives = append(r.Directives, core.Directive{Kind: kind, Value: value, Line: i + 1})
	}
	return r
}

func TestEvaluate(t *testing.T) {
	ctx := context.Background()
	res := Evaluate(ctx, request("assert status == 200", "assert jsonpath $.ok == true"), response(200, doc))
	if res.Err != nil || len(res.Outcomes) != 2 || !res.Outcomes[0].Passed || !res.Outcomes[1].Passed {
		t.Errorf("all passing: %+v", res)
	}

	// Every assertion is checked; the error names the first failure.
	res = Evaluate(ctx, request("assert status == 200", "assert status == 201", "assert jsonpath $.ok == false"), response(200, doc))
	if e, ok := res.Err.(*core.Error); !ok || e.Kind != core.KindAssert || e.Source.Line != 2 ||
		e.Msg != "2 of 3 assertions failed: status == 201; jsonpath $.ok == false" || len(res.Outcomes) != 3 {
		t.Errorf("failing asserts: %+v, %v", res, res.Err)
	}
	res = Evaluate(ctx, request("assert status == 201"), response(200, doc))
	if res.Err == nil || res.Err.Error() != "a.http:1: assertion failed: status == 201" {
		t.Errorf("one failing assert: %v", res.Err)
	}
}

func TestCapture(t *testing.T) {
	tests := []struct {
		directive    string
		name, source string
		secret       bool
		value        string
	}{
		{"token = $.token", "token", "$.token", true, "t-1"},
		{"plain id = $.items[0].id", "id", "$.items[0].id", false, "42"},
		{"plain = $.ok", "plain", "$.ok", true, "true"},
		{"big=$.big", "big", "$.big", true, "12345678901234567890"},
		{"plain item = $.items[0]", "item", "$.items[0]", false, `{"id":42}`},
		{"plain tags = $.tags", "tags", "$.tags", false, `["a"]`},
		{"n = $.items|length", "n", "$.items|length", true, "2"},
		{"name = $.name", "name", "$.name", true, "Ada Lovelace"},
		{"cookie = header set-cookie", "cookie", "header set-cookie", true, "a=1"},
		{"plain code = status", "code", "status", false, "200"},
	}
	r := &Response{Response: response(200, doc), ctx: context.Background()}
	for _, tt := range tests {
		c, err := ParseCapture(tt.directive)
		if err != nil {
			t.Errorf("ParseCapture(%q): %v", tt.directive, err)
			continue
		}
		v, err := c.take(r)
		if c.Name != tt.name || c.Source != tt.source || c.Secret != tt.secret || err != nil || v != tt.value {
			t.Errorf("%s = %+v, %q, %v; want %s, %s, %v, %q", tt.directive, c, v, err, tt.name, tt.source, tt.secret, tt.value)
		}
	}
	for directive, want := range map[string]string{
		"missing = $.missing":        "the body has no such value",
		"deleted = $.deleted_at":     "the value is null",
		"x = $.ok.x":                 "the path does not fit the body",
		"x = $.name[0]":              "the path does not fit the body",
		"item = $.items[0]":          "a secret capture cannot mask",
		"tags = $.tags":              "a secret capture cannot mask",
		"session = header X-Session": "the response has no such header",
	} {
		c, err := ParseCapture(directive)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.take(r); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error with %q", directive, err, want)
		}
	}
	c, _ := ParseCapture("token = $.token")
	if _, err := c.take(&Response{Response: response(200, "<html>"), ctx: context.Background()}); err == nil ||
		err.Error() != "the body is not JSON" {
		t.Errorf("not JSON: %v", err)
	}
	cut := response(200, `{"token": "t-1"}`)
	cut.Truncated = true
	if _, err := c.take(&Response{Response: cut, ctx: context.Background()}); err == nil ||
		err.Error() != "the body was cut off at the size limit" {
		t.Errorf("cut off: %v", err)
	}
	// What a path does not fit is not quoted: it could be a secret.
	if _, err := c.take(&Response{Response: response(200, `{"token": "s3cret-value"}`), ctx: context.Background()}); err != nil {
		t.Fatal(err)
	}
	c, _ = ParseCapture("x = $.token.x")
	if _, err := c.take(&Response{Response: response(200, `{"token": "s3cret-value"}`), ctx: context.Background()}); err == nil ||
		strings.Contains(err.Error(), "s3cr") {
		t.Errorf("misfit: %v", err)
	}
}

func TestParseCaptureErrors(t *testing.T) {
	tests := map[string]string{
		"token $.token":           "want [plain] <name> = <source>",
		"token =":                 "want [plain] <name> = <source>",
		"= $.token":               "want [plain] <name> = <source>",
		"secret token = $.token":  "want [plain] <name> = <source>",
		"plain a b = $.token":     "want [plain] <name> = <source>",
		"$token = $.token":        `invalid variable name "$token"`,
		"1st = $.token":           `invalid variable name "1st"`,
		"token = .token":          "want a source",
		"token = body":            "want a source",
		"token = status 200":      "want a source",
		"token = header":          "want a source",
		"token = header X Y":      "want a source",
		"token = $token":          "want a path starting with $",
		"token = $.a[":            "path $.a[: unexpected EOF",
		"token = $.token | ascii": "want a source",
	}
	for directive, want := range tests {
		if _, err := ParseCapture(directive); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseCapture(%q) = %v, want an error with %q", directive, err, want)
		}
	}
}

func TestEvaluateCaptures(t *testing.T) {
	ctx := context.Background()
	res := Evaluate(ctx, request("capture token = $.token", "assert status == 201", "capture plain id = $.items[0].id"),
		response(200, doc))
	if res.Err == nil || res.Err.(*core.Error).Kind != core.KindAssert || len(res.Captured) != 2 ||
		res.Captured[0].Value != "t-1" || !res.Captured[0].Secret || res.Captured[1].Value != "42" || res.Captured[1].Secret {
		t.Errorf("captures with a failed assertion: %+v, %v", res, res.Err)
	}
	// A capture that takes nothing outranks failed assertions; the others
	// are still taken.
	res = Evaluate(ctx, request("assert status == 201", "capture a = $.a", "capture token = $.token", "capture b = header B"),
		response(200, doc))
	e, ok := res.Err.(*core.Error)
	if !ok || e.Kind != core.KindCapture || e.Source.Line != 2 || len(res.Captured) != 1 || len(res.Outcomes) != 1 ||
		e.Msg != "2 of 3 captures failed: a = $.a: the body has no such value; b = header B: the response has no such header" {
		t.Errorf("failed captures: %+v, %v", res, res.Err)
	}
	if _, _, err := Directives(request("capture a = $.a", "capture plain a = $.b")); err == nil ||
		err.Error() != "a.http:2: @capture plain a = $.b: a is captured on line 1 already" {
		t.Errorf("a variable captured twice: %v", err)
	}
	res = Evaluate(ctx, request("capture a = $.a"), response(200, doc))
	if res.Err == nil || res.Err.Error() != "a.http:1: capture failed: a = $.a: the body has no such value" {
		t.Errorf("one failed capture: %v", res.Err)
	}
}
