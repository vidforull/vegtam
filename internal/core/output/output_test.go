package output

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/exec"
)

var masker = core.NewMasker([]string{"t0ken/x"})

func secret(name string) core.Segment { return core.Segment{Secret: &core.Secret{Name: name}} }

func TestSent(t *testing.T) {
	p := &core.Prepared{Method: "POST",
		URL:     core.Text{{Text: "https://api.example.test/?key="}, secret("token")},
		Headers: []core.PreparedHeader{{Name: "Authorization", Value: core.Text{{Text: "Bearer "}, secret("$env KEY")}}},
		Body:    core.Text{{Text: `{"copied": "t0ken/x"}`}},
	}
	got, _ := json.Marshal(Sent(p, masker))
	want := `{"method":"POST","url":"https://api.example.test/?key={{token}}",` +
		`"headers":[{"name":"Authorization","value":"Bearer {{$env KEY}}"}],"body":"{\"copied\": \"***\"}"}`
	if string(got) != want {
		t.Errorf("Sent = %s\nwant   %s", got, want)
	}
	binary := &core.Prepared{Method: "PUT", URL: core.Text{{Text: "https://x.test/"}}, Body: core.Text{{Text: "\xff\x00t0ken/x"}}}
	if r := Sent(binary, masker); r.Body != "/wAqKio=" || r.Encoding != "base64" {
		t.Errorf("binary body = %q, %q; want the masked bytes, base64-encoded", r.Body, r.Encoding)
	}
}

func TestWritten(t *testing.T) {
	r := &core.Request{Method: "POST", URL: "{{host}}/up", Headers: []core.Header{{Name: "X", Value: "{{$env K}}"}},
		BodyFile: "./payload.json"}
	got, _ := json.Marshal(Written(r))
	want := `{"method":"POST","url":"{{host}}/up","headers":[{"name":"X","value":"{{$env K}}"}],"body_file":"./payload.json"}`
	if string(got) != want {
		t.Errorf("Written = %s\nwant      %s", got, want)
	}
}

func TestNewResponse(t *testing.T) {
	r := &exec.Response{Proto: "HTTP/1.1", Status: 200, Reason: "OK", Duration: 1234567 * time.Nanosecond,
		Header: http.Header{"X-B": {"2", "t0ken%2Fx"}, "X-A": {"1"}},
		Body:   []byte(`{"echo": "t0ken\/x", "raw": "t0ken/x"}`)}
	resp, timing := NewResponse(r, masker)
	got, _ := json.Marshal(Document{SchemaVersion: 1, Result: &Result{Response: resp, Timing: timing}})
	want := `{"schema_version":1,"response":{"proto":"HTTP/1.1","status":200,"reason":"OK","headers":` +
		`[{"name":"X-A","value":"1"},{"name":"X-B","value":"2"},{"name":"X-B","value":"***"}],` +
		`"body":"{\"echo\": \"***\", \"raw\": \"***\"}","truncated":false,"untrusted":true},"timing":{"total_ms":1.234}}`
	if string(got) != want {
		t.Errorf("NewResponse = %s\nwant          %s", got, want)
	}

	cut := &exec.Response{Body: []byte("id=t0ke"), Truncated: true, Header: http.Header{}}
	if resp, _ := NewResponse(cut, masker); resp.Body != "id=***" || !resp.Truncated {
		t.Errorf("truncated body = %q, %v; want the cut value masked", resp.Body, resp.Truncated)
	}
	escaped := &exec.Response{Body: []byte(`{"net": "t0ken\u002Fx", "py": "\u043a\u043b\u044e\u0447", "k": "\u006b"}`),
		Header: http.Header{}}
	m := core.NewMasker([]string{"t0ken/x", "ключ"})
	if resp, _ := NewResponse(escaped, m); resp.Body != `{"net": "***", "py": "***", "k": "\u006b"}` {
		t.Errorf("escaped JSON body = %s; want every escaping of a value masked, the rest as sent", resp.Body)
	}
	split := &exec.Response{Body: []byte("ключ")[:7], Truncated: true, Header: http.Header{}}
	if resp, _ := NewResponse(split, nil); resp.Body != "клю" || resp.Encoding != "" {
		t.Errorf("text cut inside a character = %q, %q; want the whole characters as text", resp.Body, resp.Encoding)
	}
	binary := &exec.Response{Body: []byte("\xfft0ken/x"), Header: http.Header{}}
	if resp, _ := NewResponse(binary, masker); resp.Body != "/yoqKg==" || resp.Encoding != "base64" {
		t.Errorf("binary body = %q, %q; want the masked bytes, base64-encoded", resp.Body, resp.Encoding)
	}
}

func TestNewError(t *testing.T) {
	e := core.Errorf(core.KindVariable, core.Source{File: "a.http", Line: 3}, "x t0ken/x y")
	e.Variables = []string{"host"}
	got, _ := json.Marshal(NewError(e, masker))
	if want := `{"kind":"variable","message":"x *** y","file":"a.http","line":3,"variables":["host"]}`; string(got) != want {
		t.Errorf("NewError = %s, want %s", got, want)
	}
	if got := NewError(errors.New("bad flag t0ken/x"), masker); got.Kind != core.KindUsage || got.Message != "bad flag ***" {
		t.Errorf("NewError(plain error) = %+v", got)
	}
}

func TestList(t *testing.T) {
	f := &core.File{Path: "dir/a.http", Requests: []*core.Request{
		{Name: "list", Method: "GET", URL: "{{host}}/u", Source: core.Source{Line: 3},
			Directives: []core.Directive{{Kind: "tag", Value: "smoke", Line: 2}}},
		{Method: "POST", URL: "{{host}}/u", Source: core.Source{Line: 7}},
	}}
	got, _ := json.Marshal(List(f))
	want := `[{"ref":"dir/a.http#list","file":"dir/a.http","line":3,"index":1,"name":"list","method":"GET",` +
		`"url":"{{host}}/u","directives":[{"kind":"tag","value":"smoke"}]},` +
		`{"ref":"dir/a.http#2","file":"dir/a.http","line":7,"index":2,"method":"POST","url":"{{host}}/u","directives":[]}]`
	if string(got) != want {
		t.Errorf("List = %s\nwant   %s", got, want)
	}
	if got, _ := json.Marshal(Document{SchemaVersion: 1, Requests: []*Listed{}}); string(got) != `{"schema_version":1,"requests":[]}` {
		t.Errorf("empty listing = %s", got)
	}
}

// TestSchemaMatchesTypes checks the schema against the Go types: every
// JSON field is a property and every property a field, and the fields
// that are always present are exactly the required ones.
func TestSchemaMatchesTypes(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal([]byte(Schema), &root); err != nil {
		t.Fatal(err)
	}
	defs := root["$defs"].(map[string]any)
	resolve := func(node map[string]any) map[string]any {
		for {
			ref, ok := node["$ref"].(string)
			if !ok {
				return node
			}
			node = defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
		}
	}
	var check func(path string, typ reflect.Type, node map[string]any)
	check = func(path string, typ reflect.Type, node map[string]any) {
		node = resolve(node)
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
			if items, ok := node["items"].(map[string]any); ok {
				node = resolve(items)
			}
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		props, _ := node["properties"].(map[string]any)
		var fields, required []string
		var walk func(reflect.Type)
		walk = func(typ reflect.Type) {
			for i := range typ.NumField() {
				f := typ.Field(i)
				if f.Anonymous {
					walk(f.Type.Elem())
					continue
				}
				name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
				fields = append(fields, name)
				if opts == "" {
					required = append(required, name)
				}
				if prop, ok := props[name].(map[string]any); !ok {
					t.Errorf("%s.%s: not in the schema", path, name)
				} else {
					check(path+"."+name, f.Type, prop)
				}
			}
		}
		walk(typ)
		for name := range props {
			if !slices.Contains(fields, name) {
				t.Errorf("%s.%s: in the schema but not in %s", path, name, typ)
			}
		}
		var want []string
		req, _ := node["required"].([]any)
		for _, r := range req {
			want = append(want, r.(string))
		}
		slices.Sort(required)
		slices.Sort(want)
		if !slices.Equal(required, want) {
			t.Errorf("%s: required %v, but %v are always present", path, want, required)
		}
	}
	check("Document", reflect.TypeFor[Document](), root)
}
