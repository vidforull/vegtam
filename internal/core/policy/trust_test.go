package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
)

func TestStore(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "config", "vegtam", "trust.json"))
	file, sum := "/collections/api/http-client.cmd.json", Sum([]byte(`{"TOKEN": {"argv": ["op"]}}`))
	check := func(want Status, sum string) {
		t.Helper()
		if got, err := s.Check(file, sum); got != want || err != nil {
			t.Errorf("Check = %s, %v; want %s", got, err, want)
		}
	}
	check(Untrusted, sum) // no store yet
	if err := s.Trust(file, sum); err != nil {
		t.Fatal(err)
	}
	check(Trusted, sum)
	check(Changed, Sum(nil))
	if m, err := s.List(); err != nil || len(m) != 1 || m[file] != sum {
		t.Errorf("List = %v, %v", m, err)
	}
	// Private to its owner, and written whole.
	for path, want := range map[string]os.FileMode{s.Path(): 0o600, filepath.Dir(s.Path()): 0o700} {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, %v; want %v", path, fi.Mode().Perm(), err, want)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(s.Path()), ".trust-*")); len(left) > 0 {
		t.Errorf("temporary files left: %q", left)
	}
	if was, err := s.Revoke(file); !was || err != nil {
		t.Errorf("Revoke = %v, %v", was, err)
	}
	check(Untrusted, sum)
	if was, err := s.Revoke(file); was || err != nil {
		t.Errorf("Revoke again = %v, %v", was, err)
	}
}

func TestStoreRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	for _, tt := range []struct {
		name, src     string
		mode, dirMode os.FileMode
		want          string
	}{
		{"writable by others", `{"trusted": {}}`, 0o666, 0o700, "others can write it, so it trusts nothing"},
		{"writable by the group", `{"trusted": {}}`, 0o620, 0o700, "others can write it"},
		{"directory writable by others", `{"trusted": {}}`, 0o600, 0o777, "others can write its directory, so it trusts nothing"},
		{"not JSON", `{"trusted": `, 0o600, 0o700, "unexpected EOF"},
		{"unknown field", `{"trusted": {}, "all": true}`, 0o600, 0o700, `unknown field "all"`},
		{"data after it", `{"trusted": {}} {"trusted": {"/a": "x"}}`, 0o600, 0o700, "data after the record"},
	} {
		if err := os.WriteFile(path, []byte(tt.src), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, tt.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, tt.dirMode); err != nil {
			t.Fatal(err)
		}
		_, err := NewStore(path).Check("/a/http-client.cmd.json", "")
		if e, ok := err.(*core.Error); !ok || e.Kind != core.KindPolicy || !strings.Contains(e.Error(), tt.want) {
			t.Errorf("%s: %v, want a policy error with %q", tt.name, err, tt.want)
		}
	}
	if err := (&Store{err: os.ErrNotExist}).Trust("/a", ""); err == nil {
		t.Error("a store without a path: want an error")
	}
}

func TestDefaultStore(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if got := DefaultStore().Path(); got != "/xdg/vegtam/trust.json" {
		t.Errorf("with XDG_CONFIG_HOME: %s", got)
	}
	// A relative XDG_CONFIG_HOME is ignored, as the specification says.
	t.Setenv("XDG_CONFIG_HOME", "rel")
	t.Setenv("HOME", "/home/ada")
	if got := DefaultStore().Path(); got != "/home/ada/.config/vegtam/trust.json" {
		t.Errorf("without XDG_CONFIG_HOME: %s", got)
	}
}

func TestCanonical(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	file := filepath.Join(dir, "real", "http-client.cmd.json")
	os.MkdirAll(filepath.Dir(file), 0o755)
	os.WriteFile(file, nil, 0o644)
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link")); err != nil {
		t.Skip(err)
	}
	t.Chdir(dir)
	for _, in := range []string{file, "link/http-client.cmd.json", "real/../real/http-client.cmd.json"} {
		if got, err := Canonical(in); got != file || err != nil {
			t.Errorf("Canonical(%q) = %q, %v; want %q", in, got, err, file)
		}
	}
	// A link to a command file is a file of its own.
	if err := os.Symlink(file, filepath.Join(dir, "http-client.cmd.json")); err != nil {
		t.Fatal(err)
	}
	if got, _ := Canonical("http-client.cmd.json"); got != filepath.Join(dir, "http-client.cmd.json") {
		t.Errorf("Canonical of a link = %q", got)
	}
	if got, _ := Canonical("gone/x.json"); got != filepath.Join(dir, "gone", "x.json") {
		t.Errorf("Canonical of a missing file = %q", got)
	}
}
