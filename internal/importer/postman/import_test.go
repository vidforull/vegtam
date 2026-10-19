package postman

import (
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path"
	"path/filepath"
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
		if err := os.RemoveAll(golden); err != nil {
			t.Fatal(err)
		}
		for name, data := range got {
			p := filepath.Join(golden, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
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
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
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
	tests := map[string]string{"host": "host", "a.b-c_d": "a.b-c_d", "api key": "api_key", "1st": "_1st",
		"Токен": "Token", "-x": "_-x"}
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
