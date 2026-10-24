package postman

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/httpfile"
)

var update = flag.Bool("update", false, "rewrite testdata/postman/golden")

const (
	export = "../../../testdata/postman/export"
	golden = "../../../testdata/postman/golden"
)

// TestImport converts the synthetic export and compares every file and
// the report with testdata/postman/golden. Golden files end in .golden,
// so that no tool takes them for the real thing.
func TestImport(t *testing.T) {
	res, err := Import(export, "out")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range res.Files {
		got[f.Path+".golden"] = string(f.Data)
	}
	report, _ := json.MarshalIndent(res.Report, "", "  ")
	got["report.json.golden"] = string(report) + "\n"

	if *update {
		if err = os.RemoveAll(golden); err != nil {
			t.Fatal(err)
		}
		for name, data := range got {
			p := filepath.Join(golden, filepath.FromSlash(name))
			if err = os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(p, []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	want := map[string]string{}
	err = filepath.WalkDir(golden, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		rel, _ := filepath.Rel(golden, p)
		want[filepath.ToSlash(rel)] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range got {
		if w, ok := want[name]; !ok {
			t.Errorf("%s: not in the golden files (go test -update to add it)", name)
		} else if data != w {
			t.Errorf("%s:\n%s\nwant:\n%s", name, data, w)
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("%s: golden file not produced", name)
		}
	}
}

// TestImportOutput checks what the files promise: every .http file parses
// to the requests the report counts as imported, and no secret value of
// the export, all of which start with "fake-", is outside the private
// environment files.
func TestImportOutput(t *testing.T) {
	res, err := Import(export, "out")
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	for _, f := range res.Files {
		private := path.Base(f.Path) == env.PrivateFile
		if f.Private != private {
			t.Errorf("%s: Private = %v", f.Path, f.Private)
		}
		if !private && strings.Contains(string(f.Data), "fake-") {
			t.Errorf("%s holds a secret value:\n%s", f.Path, f.Data)
		}
		if path.Ext(f.Path) == ".http" {
			hf, err := httpfile.Parse(f.Path, f.Data)
			if err != nil {
				t.Errorf("%s does not parse: %v", f.Path, err)
				continue
			}
			requests += len(hf.Requests)
		}
		if strings.HasSuffix(f.Path, ".json") && !json.Valid(f.Data) {
			t.Errorf("%s is not valid JSON", f.Path)
		}
	}
	if requests != res.Report.Imported || res.Report.Imported >= res.Report.Requests {
		t.Errorf("%d requests parse, report: %d of %d imported", requests, res.Report.Imported, res.Report.Requests)
	}
}

func TestImportFile(t *testing.T) {
	res, err := Import(filepath.Join(export, "collection", "11111111-aaaa-4aaa-8aaa-000000000002.json"), "out")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Report.Environments, []string{"default"}) {
		t.Errorf("environments = %q, want default for an export without any", res.Report.Environments)
	}
	for _, f := range res.Files {
		if f.Path == "crm/"+env.PublicFile && string(f.Data) != "{\n  \"default\": {}\n}\n" {
			t.Errorf("%s:\n%s", f.Path, f.Data)
		}
	}
}

func TestImportErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		src  string
		kind core.Kind
		msg  string
	}{
		{filepath.Join(dir, "missing.json"), core.KindUsage, "no such file"},
		{write("env/dev.json", `{"name": "dev", "values": []}`), core.KindImport, "not a Postman collection"},
		{write("bad.json", `{"info": `), core.KindImport, "not JSON"},
		{write("shape.json", `{"info": {"name": "x"}, "item": {"name": "not a list"}}`), core.KindImport, "collection: json"},
		{filepath.Join(dir, "env"), core.KindImport, "no Postman collections"},
	}
	for _, tt := range tests {
		_, err := Import(tt.src, "out")
		e, ok := errors.AsType[*core.Error](err)
		if !ok || e.Kind != tt.kind || !strings.Contains(e.Msg, tt.msg) {
			t.Errorf("Import(%s) = %v; want a %s error with %q", tt.src, err, tt.kind, tt.msg)
		}
	}
}

// TestImportAllow checks the $allow of the private file: a secret whose
// requests go to one origin is bound to it, in $shared if every
// environment gives the same one; a secret whose requests go to several,
// or to one the import cannot know, is bound to none, and the report says
// to declare it.
func TestImportAllow(t *testing.T) {
	// The collection's auth sends {{token}} with every request; each
	// environment is {"name": ..., "values": ...} with values as given.
	const bearer = `"auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]}`
	envFile := func(name string, values ...string) string {
		return `{"name": "` + name + `", "values": [` + strings.Join(values, ", ") + `]}`
	}
	token := `{"key": "token", "value": "fake-token", "type": "secret"}`
	base := func(url string) string { return `{"key": "baseUrl", "value": "` + url + `"}` }
	tests := []struct {
		name     string
		items    string   // the collection's items: requests given as their URLs
		vars     string   // the collection's variables
		envs     []string // environment files
		allow    map[string]map[string][]string
		declares []string // the reasons the report gives for secrets bound to none
	}{
		{
			name:  "one origin",
			items: `{"name": "a", "request": "{{baseUrl}}/users"}, {"name": "b", "request": "{{baseUrl}}/orders?page=2"}`,
			envs:  []string{envFile("Dev", base("https://API.example.com:443/v1"), token)},
			allow: map[string]map[string][]string{"$shared": {"token": {"https://api.example.com"}}},
		},
		{
			name:  "one origin in each environment",
			items: `{"name": "a", "request": "{{baseUrl}}/users"}`,
			envs: []string{
				envFile("Dev", base("http://127.0.0.1:8080/v1"), token),
				envFile("Prod", base("https://api.example.com/v1"), token),
			},
			allow: map[string]map[string][]string{
				"dev":  {"token": {"http://127.0.0.1:8080"}},
				"prod": {"token": {"https://api.example.com"}},
			},
		},
		{
			name:  "a collection variable, no environment",
			items: `{"name": "a", "request": "{{baseUrl}}/users"}`,
			vars:  base("https://api.example.com/v1") + `, ` + token,
			allow: map[string]map[string][]string{"$shared": {"token": {"https://api.example.com"}}},
		},
		{
			name:  "two origins",
			items: `{"name": "a", "request": "{{baseUrl}}/users"}, {"name": "b", "request": "https://auth.example.com/refresh"}`,
			envs:  []string{envFile("Dev", base("https://api.example.com/v1"), token)},
			allow: map[string]map[string][]string{},
			declares: []string{
				"declare $allow for {{token}}: its requests go to more than one origin (https://api.example.com, https://auth.example.com)",
			},
		},
		{
			name:  "two origins in one environment",
			items: `{"name": "a", "request": "{{baseUrl}}/users"}, {"name": "b", "request": "https://api.example.com/health"}`,
			envs: []string{
				envFile("Dev", base("https://dev.example.com"), token),
				envFile("Prod", base("https://api.example.com"), token),
			},
			allow: map[string]map[string][]string{"prod": {"token": {"https://api.example.com"}}},
			declares: []string{
				"declare $allow for {{token}} in dev: its requests go to more than one origin (https://api.example.com, https://dev.example.com)",
			},
		},
		{
			name:  "the host from a secret",
			items: `{"name": "a", "request": "{{host}}/users"}`,
			envs:  []string{envFile("Dev", `{"key": "host", "value": "https://api.example.com", "type": "secret"}`, token)},
			allow: map[string]map[string][]string{},
			declares: []string{
				"declare $allow for {{host}}: the origin of its requests is not known",
				"declare $allow for {{token}}: the origin of its requests is not known",
			},
		},
		{
			name:  "the host from a variable without a value",
			items: `{"name": "a", "request": "https://{{tenant}}.example.com/users"}`,
			envs:  []string{envFile("Dev", token)},
			allow: map[string]map[string][]string{},
			declares: []string{
				"declare $allow for {{token}}: the origin of its requests is not known",
			},
		},
		{
			name: "a secret without a value",
			items: `{"name": "a", "request": "{{baseUrl}}/users"}, ` +
				`{"name": "b", "request": {"method": "GET", "url": "{{baseUrl}}/keys", "header": [{"key": "X-Api-Key", "value": "{{api_key}}"}]}}`,
			envs: []string{
				envFile("Dev", base("https://dev.example.com"), token),
				envFile("Prod", base("https://api.example.com")),
			},
			allow: map[string]map[string][]string{"dev": {"token": {"https://dev.example.com"}}},
		},
		{
			name: "a request written commented out",
			items: `{"name": "a", "request": "{{baseUrl}}/users"}, ` +
				`{"name": "b", "request": {"method": "PROPFIND", "url": "https://files.example.com/"}}`,
			envs:  []string{envFile("Dev", base("https://api.example.com/v1"), token)},
			allow: map[string]map[string][]string{"$shared": {"token": {"https://api.example.com"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			vars := ""
			if tt.vars != "" {
				vars = `, "variable": [` + tt.vars + `]`
			}
			files := map[string]string{"api.json": `{"info": {"name": "API"}, ` + bearer + vars + `, "item": [` + tt.items + `]}`}
			for i, e := range tt.envs {
				files[fmt.Sprintf("env-%d.json", i)] = e
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			res, err := Import(dir, "out")
			if err != nil {
				t.Fatal(err)
			}
			var private map[string]map[string]json.RawMessage
			for _, f := range res.Files {
				if f.Path == "api/"+env.PrivateFile {
					if err := json.Unmarshal(f.Data, &private); err != nil {
						t.Fatalf("%s: %v\n%s", f.Path, err, f.Data)
					}
				}
			}
			allow := map[string]map[string][]string{}
			for e, entries := range private {
				if raw, ok := entries["$allow"]; ok {
					var a map[string][]string
					if err := json.Unmarshal(raw, &a); err != nil {
						t.Fatalf("%s.$allow: %v", e, err)
					}
					allow[e] = a
				}
			}
			if !reflect.DeepEqual(allow, tt.allow) {
				t.Errorf("$allow = %v, want %v", allow, tt.allow)
			}
			for _, a := range allow {
				for name, origins := range a {
					for _, o := range origins {
						if p, err := core.ParseOrigin(o); err != nil || p != o {
							t.Errorf("$allow of %s: %q reads back as %q, %v", name, o, p, err)
						}
					}
				}
			}
			var declares []string
			for _, s := range res.Report.Skipped {
				if strings.HasPrefix(s.Reason, "declare $allow") {
					declares = append(declares, s.Reason)
					if s.Category != "variable" || s.Where != filepath.Join("out", "api", env.PrivateFile) {
						t.Errorf("%+v: want category variable at the private file", s)
					}
				}
			}
			if !slices.Equal(declares, tt.declares) {
				t.Errorf("the report says\n%q\nwant\n%q", declares, tt.declares)
			}
		})
	}
}

// TestImportLoads checks that vegtam reads the environment files of the
// synthetic export as the import means them: every environment loads,
// without a warning about $allow, and binds the secrets it names.
func TestImportLoads(t *testing.T) {
	res, err := Import(export, "out")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	var dirs []string
	for _, f := range res.Files {
		p := filepath.Join(out, filepath.FromSlash(f.Path))
		if err = os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(p, f.Data, 0o600); err != nil {
			t.Fatal(err)
		}
		if path.Base(f.Path) == env.PrivateFile {
			dirs = append(dirs, filepath.Dir(p))
		}
	}
	for _, e := range res.Report.Environments {
		for _, dir := range dirs {
			v, lerr := env.NewLoader(env.Options{Env: e}).For(filepath.Join(dir, "requests.http"))
			if lerr != nil {
				t.Fatalf("-e %s in %s: %v", e, dir, lerr)
			}
			for _, w := range v.Warnings() {
				if strings.Contains(w.Msg, "$allow") {
					t.Errorf("-e %s in %s: %s", e, dir, w.Msg)
				}
			}
		}
	}
	v, err := env.NewLoader(env.Options{Env: "dev"}).For(filepath.Join(out, "crm", "contacts.http"))
	if err != nil {
		t.Fatal(err)
	}
	if got := v.SecretOrigins(core.Secret{Name: "crm_token"}); !slices.Equal(got, []string{"https://dev.crm.example.test"}) {
		t.Errorf("crm_token may go to %q in dev, want the CRM of dev", got)
	}
}

func TestURLOrigin(t *testing.T) {
	vars := map[string]string{
		"base": "https://API.Example.com:443/v1", "local": "http://127.0.0.1:8080", "nested": "{{base}}/v2",
		"bare": "api.example.com", "ftp": "ftp://files.example.com", "wild": "https://*.example.com", "port": "8443",
	}
	tests := []struct {
		url, want string
		known     bool
	}{
		{"{{base}}/users", "https://api.example.com", true},
		{"{{ base }}/users?page={{page}}", "https://api.example.com", true},
		{"{{local}}/health", "http://127.0.0.1:8080", true},
		{"http://shop.example.test:8080/status", "http://shop.example.test:8080", true},
		{"https://api.example.com/{{token}}", "https://api.example.com", true},
		{"https://api.example.com?key={{token}}", "https://api.example.com", true},
		{"https://api.example.com:{{port}}/x", "https://api.example.com:8443", true},
		{"https://api.example.com:{{secret_port}}/x", "", false},
		{"{{token}}/users", "", false},
		{"https://{{tenant}}.example.com/", "", false},
		{"{{nested}}/users", "", false},
		{"{{bare}}/users", "", false},
		{"{{ftp}}/file", "", false},
		{"{{wild}}/users", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		if got, known := urlOrigin(tt.url, vars); got != tt.want || known != tt.known {
			t.Errorf("urlOrigin(%q) = %q, %v; want %q, %v", tt.url, got, known, tt.want, tt.known)
		}
	}
}

func TestSlug(t *testing.T) {
	tests := map[string]string{
		"Shop API":                "shop-api",
		"Заказы и Щука, Ёж":       "zakazy-i-shchuka-ezh",
		"../../etc/passwd":        "etc-passwd",
		"  --  ":                  "x",
		"日本":                      "x",
		strings.Repeat("ab-", 40): strings.TrimRight(strings.Repeat("ab-", 20), "-"),
	}
	for in, want := range tests {
		if got := slug(in, "x"); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVariable(t *testing.T) {
	tests := map[string]string{
		"host": "host", "a.b-c_d": "a.b-c_d", "api key": "api_key", "1st": "_1st",
		"Токен": "Token", "-x": "_-x",
	}
	for in, want := range tests {
		if got := variable(in); got != want {
			t.Errorf("variable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStatusTest(t *testing.T) {
	tests := map[string]string{
		`pm.test("ok", function () { pm.response.to.have.status(201); });`:         "201",
		`pm.expect(pm.response.code).to.eql(204)`:                                  "204",
		`tests["Status code is 200"] = responseCode.code === 200;`:                 "200",
		`pm.response.to.be.ok;`:                                                    "200",
		`pm.response.to.have.status(200); pm.response.to.have.status(200)`:         "200",
		`pm.response.to.have.status(200); pm.expect(pm.response.code).to.eql(404)`: "",
		`pm.expect(pm.response.code).to.be.oneOf([200, 201])`:                      "",
	}
	for js, want := range tests {
		if got := statusTest(js); got != want {
			t.Errorf("statusTest(%q) = %q, want %q", js, got, want)
		}
	}
}

func TestOneLine(t *testing.T) {
	if got, want := oneLine("a\r\nb\nc\x1b]0;x\x07\td"), "a b c ]0;x  d"; got != want {
		t.Errorf("oneLine = %q, want %q", got, want)
	}
}
