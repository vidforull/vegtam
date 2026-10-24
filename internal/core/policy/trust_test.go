package policy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
		if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != core.KindPolicy || !strings.Contains(e.Error(), tt.want) {
			t.Errorf("%s: %v, want a policy error with %q", tt.name, err, tt.want)
		}
	}
	if err := (&Store{err: os.ErrNotExist}).Trust("/a", ""); err == nil {
		t.Error("a store without a path: want an error")
	}

	// A store that is a link to a file elsewhere trusts nothing: the
	// directory checked would not be the one the file is in.
	elsewhere := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(elsewhere, []byte(`{"trusted": {"/a/http-client.cmd.json": ""}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Fatal(err)
	}
	if got, err := NewStore(path).Check("/a/http-client.cmd.json", ""); got != Untrusted || err == nil {
		t.Errorf("a link to a store elsewhere: %s, %v", got, err)
	}
}

func TestHistoryDir(t *testing.T) {
	t.Setenv("VEGTAM_NO_HISTORY", "")
	t.Setenv("XDG_DATA_HOME", "/xdg")
	if got, err := HistoryDir(); got != "/xdg/vegtam" || err != nil {
		t.Errorf("with XDG_DATA_HOME: %s, %v", got, err)
	}
	t.Setenv("XDG_DATA_HOME", "rel")
	t.Setenv("HOME", "/home/ada")
	if got, err := HistoryDir(); got != "/home/ada/.local/share/vegtam" || err != nil {
		t.Errorf("without XDG_DATA_HOME: %s, %v", got, err)
	}
	t.Setenv("HOME", "")
	if got, err := HistoryDir(); err == nil || !strings.Contains(err.Error(), "set XDG_DATA_HOME or HOME") {
		t.Errorf("without HOME: %q, %v", got, err)
	}
	t.Setenv("VEGTAM_NO_HISTORY", "1")
	if got, err := HistoryDir(); got != "" || err != nil {
		t.Errorf("with VEGTAM_NO_HISTORY: %q, %v", got, err)
	}
}

func TestKeeperSocket(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "/home/ada")
	if got, err := KeeperSocket(); got != "/run/user/1000/vegtam/keeper.sock" || err != nil {
		t.Errorf("with XDG_RUNTIME_DIR: %s, %v", got, err)
	}
	// A relative XDG_RUNTIME_DIR is ignored, as the specification says:
	// the socket goes in vegtam's directory of the user's cache.
	cache := "/home/ada/.cache/vegtam/keeper.sock"
	if runtime.GOOS == "darwin" {
		cache = "/home/ada/Library/Caches/vegtam/keeper.sock"
	}
	for _, dir := range []string{"", "rel"} {
		t.Setenv("XDG_RUNTIME_DIR", dir)
		if got, err := KeeperSocket(); got != cache || err != nil {
			t.Errorf("with XDG_RUNTIME_DIR %q: %s, %v", dir, got, err)
		}
	}
	if runtime.GOOS != "darwin" {
		t.Setenv("XDG_CACHE_HOME", "/cache")
		if got, err := KeeperSocket(); got != "/cache/vegtam/keeper.sock" || err != nil {
			t.Errorf("with XDG_CACHE_HOME: %s, %v", got, err)
		}
		t.Setenv("XDG_CACHE_HOME", "")
	}
	t.Setenv("HOME", "")
	if got, err := KeeperSocket(); err == nil || !strings.HasSuffix(err.Error(), "; set XDG_RUNTIME_DIR") {
		t.Errorf("without HOME: %q, %v", got, err)
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
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
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
