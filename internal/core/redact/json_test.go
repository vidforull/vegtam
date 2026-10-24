package redact

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// jsonCases are documents, what JSON makes of them, and the paths it
// lists. The fuzz test starts from them too.
var jsonCases = []struct {
	in, want string
	paths    []string
}{
	{
		`{"access_token": "abc", "token_type": "bearer", "expires_in": 3600}`,
		`{"access_token": "***", "token_type": "bearer", "expires_in": 3600}`,
		[]string{"$.access_token"},
	},
	// Case, '-' and '_' do not matter; values of every type are replaced.
	{
		`{"Access-Token": 1, "accessToken": true, "ACCESS_TOKEN": {"a": [1, {"b": null}]}, "id_token": [1, 2], "Secret": -1.5e3, "passwd": false}`,
		`{"Access-Token": "***", "accessToken": "***", "ACCESS_TOKEN": "***", "id_token": "***", "Secret": "***", "passwd": "***"}`,
		[]string{`$["Access-Token"]`, "$.accessToken", "$.ACCESS_TOKEN", "$.id_token", "$.Secret", "$.passwd"},
	},
	{
		`{"data": {"items": [{"id": 1, "token": "x"}, {"name": "n", "auth": {"password": "p", "session_id": 7}}]}}`,
		`{"data": {"items": [{"id": 1, "token": "***"}, {"name": "n", "auth": {"password": "***", "session_id": "***"}}]}}`,
		[]string{"$.data.items[0].token", "$.data.items[1].auth.password", "$.data.items[1].auth.session_id"},
	},
	// null and "" hold nothing; "***" is redacted already, however escaped.
	{`{"token": null, "secret": "", "password": "***", "cookie": "***"}`, `{"token": null, "secret": "", "password": "***", "cookie": "***"}`, nil},
	// A key is compared as JSON decodes it.
	{`{"\u0074oken": "x", "pass\u0077d": 1}`, `{"\u0074oken": "***", "pass\u0077d": "***"}`, []string{"$.token", "$.passwd"}},
	// A key that is not a name is quoted in the path.
	{
		`{"x-api": {"api-key": "k"}, "1a": {"token": 1}, "a\"b": [{"token": 2}], "": {"secret": 3}, "é": {"token": 4}}`,
		`{"x-api": {"api-key": "***"}, "1a": {"token": "***"}, "a\"b": [{"token": "***"}], "": {"secret": "***"}, "é": {"token": "***"}}`,
		[]string{`$["x-api"]["api-key"]`, `$["1a"].token`, `$["a\"b"][0].token`, `$[""].secret`, `$["é"].token`},
	},
	// A JWT-shaped token, alone or in a text, however escaped; not a key.
	{
		`{"jwt": "` + jwt + `", "msg": "Bearer ` + jwt + `.", "esc": "` + strings.Replace(jwt, ".", `\u002e`, 1) + `", "` + jwt + `": 1}`,
		`{"jwt": "***", "msg": "Bearer ***.", "esc": "***", "` + jwt + `": 1}`,
		[]string{"$.jwt", "$.msg", "$.esc"},
	},
	{`["` + jwt + `", "aaa.bbb.ccc", ["` + jwt + `"]]`, `["***", "aaa.bbb.ccc", ["***"]]`, []string{"$[0]", "$[2][0]"}},
	{`"` + jwt + `"`, `"***"`, []string{"$"}},
	// Only replaced values change: spacing, numbers and escapes stay.
	{
		"{ \"n\" : 1.50e+3 ,\n\t\"s\" : \"\\u00e9\\/\" , \"token\" : 7 }",
		"{ \"n\" : 1.50e+3 ,\n\t\"s\" : \"\\u00e9\\/\" , \"token\" : \"***\" }",
		[]string{"$.token"},
	},
	{`{"msg": "é ` + jwt + ` \/"}`, `{"msg": "é *** /"}`, []string{"$.msg"}},
	// Cut off at a size limit.
	{`{"user": {"name": "a", "session": {"id": "abc", "exp`, `{"user": {"name": "a", "session": "***"`, []string{"$.user.session"}},
	{`{"a": [1, 2], "token": "abcd`, `{"a": [1, 2], "token": "***"`, []string{"$.token"}},
	{`{"token": 12`, `{"token": "***"`, []string{"$.token"}},
	{`{"token": `, `{"token": `, nil},
	{`{"a": 1, "tok`, `{"a": 1, "tok`, nil},
	{`{"a": "` + jwt[:40], `{"a": "` + jwt[:40], nil},
	{`{"a": "x ` + jwt, `{"a": "x ***`, []string{"$.a"}},
	// Not JSON: as far as it makes sense.
	{`{"token": abc def, "b": 2}`, `{"token": "***", "b": 2}`, []string{"$.token"}},
	{`{token: 'x', password: "y"}`, `{token: "***", password: "***"}`, []string{"$.token", "$.password"}},
	{`{"a": 1 "token": "x"}`, `{"a": 1 "token": "***"}`, []string{"$.token"}},
	{`{"token" "x"}`, `{"token" "***"}`, []string{"$.token"}},
	{`}{"token": 1}]]`, `}{"token": "***"}]]`, []string{"$.token"}},
	{`{"a": [1}, "token": 2]`, `{"a": [1}, "token": "***"]`, []string{"$.token"}},
	{`[` + jwt + `, "x"]`, `[***, "x"]`, []string{"$[0]"}},
	{`{"s": "bad \x escape ` + jwt + `"}`, `{"s": "bad \x escape ***"}`, []string{"$.s"}},
	{"{\"s\": \"\xff " + jwt + "\"}", "{\"s\": \"\xff ***\"}", []string{"$.s"}},
	// JSON Lines, and a key given twice: each path once.
	{"{\"token\": \"a\"}\n{\"token\": \"b\"}\n", "{\"token\": \"***\"}\n{\"token\": \"***\"}\n", []string{"$.token"}},
	{`{"token": "a", "token": "b"}`, `{"token": "***", "token": "***"}`, []string{"$.token"}},
	{"", "", nil},
	{"[]", "[]", nil},
	{`{"a": {}, "b": [[]]}`, `{"a": {}, "b": [[]]}`, nil},
}

func TestJSON(t *testing.T) {
	for _, tt := range jsonCases {
		out, paths := JSON([]byte(tt.in))
		if string(out) != tt.want || !slices.Equal(paths, tt.paths) {
			t.Errorf("JSON(%s)\n = %s, %q\nwant %s, %q", tt.in, out, paths, tt.want, tt.paths)
		}
		if json.Valid([]byte(tt.in)) && !json.Valid(out) {
			t.Errorf("JSON(%s) = %s: not valid", tt.in, out)
		}
		if again, paths := JSON(out); string(again) != string(out) || paths != nil {
			t.Errorf("JSON(%s) = %s, %q; want it unchanged", out, again, paths)
		}
	}
}

// TestJSONLimits checks what JSON does past its limits: an object nested
// too deep is replaced whole, a long path is cut short, and paths past
// the hundredth are counted.
func TestJSONLimits(t *testing.T) {
	deep := strings.Repeat("[", maxDepth) + `{"a": 1}` + strings.Repeat("]", maxDepth)
	out, paths := JSON([]byte(deep))
	want := strings.Repeat("[", maxDepth) + `"***"` + strings.Repeat("]", maxDepth)
	if string(out) != want || len(paths) != 1 || !strings.HasSuffix(paths[0], "…") || len(paths[0]) > maxPath+len("…") {
		t.Errorf("JSON of %d levels: %d bytes, paths %q", maxDepth+1, len(out), paths)
	}
	if !json.Valid(out) {
		t.Error("JSON of an object nested too deep: not valid")
	}
	deep = strings.Repeat("[", maxDepth) + strings.Repeat("]", maxDepth)
	if out, paths = JSON([]byte(deep)); string(out) != deep || paths != nil {
		t.Errorf("JSON of %d levels: %q", maxDepth, paths)
	}

	long := strings.Repeat("k", 1000)
	out, paths = JSON([]byte(`{"` + long + `": {"token": 1}}`))
	if string(out) != `{"`+long+`": {"token": "***"}}` || len(paths) != 1 || paths[0] != "$."+long[:maxPath-2]+"…" {
		t.Errorf("JSON with a long key = %q", paths)
	}

	var b strings.Builder
	b.WriteString("[")
	for i := range maxPaths + 12 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"token": 1}`)
	}
	b.WriteString("]")
	out, paths = JSON([]byte(b.String()))
	if len(paths) != maxPaths+1 || paths[maxPaths-1] != "$["+strconv.Itoa(maxPaths-1)+"].token" || paths[maxPaths] != "and 12 more" {
		t.Errorf("JSON with %d tokens: %d paths, ending %q", maxPaths+12, len(paths), paths[len(paths)-2:])
	}
	if strings.Count(string(out), `"***"`) != maxPaths+12 {
		t.Errorf("JSON with %d tokens: %d replaced", maxPaths+12, strings.Count(string(out), `"***"`))
	}
}
