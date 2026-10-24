package redact

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
)

// FuzzJSON checks that JSON never fails, whatever it reads; lists a path
// exactly when it changes something; keeps valid JSON valid; changes
// nothing in its own output; and leaves in valid JSON no JWT-shaped
// string and no member whose key Key names with a value other than "***",
// null or "".
func FuzzJSON(f *testing.F) {
	for _, tt := range jsonCases {
		f.Add([]byte(tt.in))
	}
	for _, s := range []string{
		`{"a": {"b": [{"refresh_token": {"x": "}"}}, "` + jwt + `"]}, "c": "\"token\": 1"}`,
		`[{"Session-ID": [], "client_secret": {}}, {"private_key": "-----BEGIN-----\n"}]`,
		`{"token": "***", "secret": "\"***\"", "cookie": "**"}`,
		`{"token": "\ud800", "x": "😀 ` + jwt + `"}`,
		`{"token": [1, {"a": "b"`, `{"token": "a\`, `{"token": tr`, `{"a": "b\"`, `[[[{"token"`,
		`{"token": }`, `{"token":,"secret":]`, `{:"token": 1}`, `{"a" : : "b"}`, `{{"token": 1}}`, `[,{"token":1},]`,
		"\xef\xbb\xbf{\"token\": 1}", `{"a":1}{"b":2} [3] "` + jwt + `" x`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, doc []byte) {
		out, paths := JSON(doc)
		if changed := !bytes.Equal(out, doc); changed != (len(paths) > 0) {
			t.Fatalf("JSON(%q) = %q, paths %q: a change without a path, or a path without a change", doc, out, paths)
		}
		if again, more := JSON(out); !bytes.Equal(again, out) || more != nil {
			t.Fatalf("JSON(%q) = %q\nJSON of that = %q, paths %q", doc, out, again, more)
		}
		if !json.Valid(doc) {
			return
		}
		if !json.Valid(out) {
			t.Fatalf("JSON(%s) = %s: not valid", doc, out)
		}
		dec := json.NewDecoder(bytes.NewReader(out))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("JSON(%s) = %s: %v", doc, out, err)
		}
		if where := shown(v, "$"); where != "" {
			t.Fatalf("JSON(%s) = %s: %s is shown", doc, out, where)
		}
	})
}

// shown returns where in v, decoded JSON at path, a value that JSON
// should have replaced is: a JWT-shaped string, or the value of a member
// whose key Key names; "" if there is none.
func shown(v any, path string) string {
	switch v := v.(type) {
	case string:
		if _, ok := Text(v); ok {
			return path
		}
	case []any:
		for i, x := range v {
			if where := shown(x, path+"["+strconv.Itoa(i)+"]"); where != "" {
				return where
			}
		}
	case map[string]any:
		for k, x := range v {
			if Key(k) && x != nil && x != "" && x != "***" {
				return path + "." + k
			}
			if where := shown(x, path+"."+k); where != "" {
				return where
			}
		}
	}
	return ""
}

// TestShown checks the check of the fuzz test.
func TestShown(t *testing.T) {
	for s, want := range map[string]string{
		`{"a": [{"Token": 1}]}`:          "$.a[0].Token",
		`["x ` + jwt + `"]`:              "$[0]",
		`{"b": {"password": ["***"]}}`:   "$.b.password",
		`{"token": "***", "id": null}`:   "",
		`{"secret": "", "x": [null, 1]}`: "",
	} {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Fatal(err)
		}
		if got := shown(v, "$"); got != want {
			t.Errorf("shown(%s) = %q, want %q", s, got, want)
		}
	}
}
