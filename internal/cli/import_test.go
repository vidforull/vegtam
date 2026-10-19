package cli

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core/output"
)

const postmanExport = "../../testdata/postman/export"

func TestImportPostman(t *testing.T) {
	out := filepath.Join(t.TempDir(), "imported")
	code, stdout, stderr := runCLI(t, false, "import", "postman", postmanExport, "-o", out)
	if code != exitOK || stderr != "" {
		t.Fatalf("import = %d, %q", code, stderr)
	}
	validateJSON(t, stdout)
	var doc output.Document
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil || doc.Import == nil {
		t.Fatalf("import printed %s", stdout)
	}
	for _, dir := range []string{out, filepath.Join(out, "crm"), filepath.Join(out, "shop-api", "products")} {
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v, want a directory with mode 0700", dir, err)
		}
	}
	for _, f := range doc.Import.Files {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o644)
		if filepath.Base(f) == "http-client.private.env.json" {
			want = 0o600
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", f, fi.Mode().Perm(), want)
		}
	}

	// Each environment checks out but for the requests the report names:
	// a Postman dynamic variable, and variables without a value.
	for _, env := range doc.Import.Environments {
		code, stdout, _ := runCLI(t, false, "run", out, "--dry-run", "-e", env)
		validateJSON(t, stdout)
		var run output.Document
		decode(t, stdout, &run)
		var failed []string
		for _, r := range run.Results {
			if r.Error != nil {
				failed = append(failed, strings.TrimPrefix(r.Ref, out+string(filepath.Separator)))
			}
		}
		want := []string{
			"crm/contacts.http#find-contact", "shop-api/edge-cases.http#loose-json",
			"shop-api/edge-cases.http#mixed-basic", "shop-api/edge-cases.http#cookie",
			"shop-api/products/admin.http#delete-product", "shop-api/shop-api.http#ping",
			"shop-api/zakazy.http#log-in-as-user",
		}
		if code != exitUsage || len(run.Results) != doc.Import.Imported || !slices.Equal(failed, want) {
			t.Errorf("run --dry-run -e %s = %d, %d results, failed %q; want %d, %d results, failed %q",
				env, code, len(run.Results), failed, exitUsage, doc.Import.Imported, want)
		}
	}
}

func TestImportPostmanText(t *testing.T) {
	out := filepath.Join(t.TempDir(), "my export")
	code, stdout, stderr := runCLI(t, true, "import", "postman", postmanExport, "-o", out)
	if code != exitOK || stderr != "" {
		t.Fatalf("import = %d, %q", code, stderr)
	}
	for _, want := range []string{
		"Imported 25 of 30 requests from 2 collections into " + out + ", with 2 environments: dev, prod-eu.\n",
		"\nrequest: 5 requests written commented out\n  " + filepath.Join(out, "shop-api", "shop-api.http") +
			"#properties: method PROPFIND is not supported\n",
		"\n  id (unset): it has no value; set it in " + filepath.Join(out, "shop-api", "http-client.env.json") + "\n",
		"\nKeep the http-client.private.env.json files out of version control: they hold the secrets.\n",
		"\nCheck the requests without sending them: vegtam run '" + out + "' --dry-run -e dev\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("import printed\n%s\nwant it to contain\n%s", stdout, want)
		}
	}
}

func TestImportPostmanExisting(t *testing.T) {
	out := t.TempDir()
	if code, _, stderr := runCLI(t, false, "import", "postman", postmanExport, "-o", out); code != exitOK {
		t.Fatalf("import = %d, %q", code, stderr)
	}
	edited := filepath.Join(out, "crm", "contacts.http")
	if err := os.WriteFile(edited, []byte("# mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, false, "import", "postman", postmanExport, "-o", out)
	if code != exitUsage || !strings.Contains(stderr, "11 files exist (use --force to overwrite them): "+edited+", ") {
		t.Errorf("import into a full directory = %d, %q; want %d and the files listed", code, stderr, exitUsage)
	}
	validateJSON(t, stdout)
	if b, _ := os.ReadFile(edited); string(b) != "# mine\n" {
		t.Errorf("import without --force overwrote %s", edited)
	}
	private := filepath.Join(out, "crm", "http-client.private.env.json")
	if err := os.Chmod(private, 0o644); err != nil {
		t.Fatal(err)
	}
	// A second name for the old file: a file rewritten in place would
	// change under it too, one replaced by a rename does not.
	kept := filepath.Join(t.TempDir(), "kept")
	if err := os.Link(edited, kept); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, false, "import", "postman", postmanExport, "-o", out, "--force"); code != exitOK {
		t.Errorf("import --force = %d, %q", code, stderr)
	}
	if fi, err := os.Stat(private); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("import --force left %s readable by others (%v)", private, err)
	}
	if b, _ := os.ReadFile(edited); !strings.HasPrefix(string(b), "### List contacts\n") {
		t.Errorf("import --force left %s as %q", edited, b)
	}
	if b, _ := os.ReadFile(kept); string(b) != "# mine\n" {
		t.Errorf("import --force rewrote %s in place: %q", edited, b)
	}
	err := filepath.WalkDir(out, func(path string, _ fs.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".tmp") {
			t.Errorf("import left %s behind", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestImportPostmanStaysInside checks that a symbolic link in the output
// directory cannot lead the import outside it.
func TestImportPostmanStaysInside(t *testing.T) {
	out, elsewhere := t.TempDir(), t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(out, "crm")); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, false, "import", "postman", postmanExport, "-o", out, "--force")
	if code != exitUsage || !strings.Contains(stderr, "escapes") {
		t.Errorf("import = %d, %q; want %d and an error", code, stderr, exitUsage)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) > 0 {
		t.Errorf("import wrote %v outside the output directory", entries)
	}
}

func TestImportPostmanErrors(t *testing.T) {
	dir := t.TempDir()
	notCollection := filepath.Join(dir, "env.json")
	if err := os.WriteFile(notCollection, []byte(`{"name": "dev", "values": []}`), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		args []string
		kind string
		want string
	}{
		{[]string{"import", "postman", postmanExport}, "usage", `required flag(s) "output" not set`},
		{[]string{"import", "postman", "-o", dir}, "usage", "accepts 1 arg(s), received 0"},
		{[]string{"import", "bruno"}, "usage", `unknown command "bruno" for "vegtam import"`},
		{[]string{"import", "postman", filepath.Join(dir, "none"), "-o", dir}, "usage", "no such file or directory"},
		{[]string{"import", "postman", notCollection, "-o", dir}, "import", "env.json: not a Postman collection"},
	}
	for _, tt := range tests {
		code, stdout, stderr := runCLI(t, false, tt.args...)
		validateJSON(t, stdout)
		var doc output.Document
		decode(t, stdout, &doc)
		if code != exitUsage || doc.Result == nil || string(doc.Error.Kind) != tt.kind || !strings.Contains(stderr, tt.want) {
			t.Errorf("%q = %d, %s, %q; want %d, kind %s and %q", tt.args, code, stdout, stderr, exitUsage, tt.kind, tt.want)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("failed imports wrote %v", entries)
	}
}
