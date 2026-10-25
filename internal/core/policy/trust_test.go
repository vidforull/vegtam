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
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(s.Path()), ".trust.json.*")); len(left) > 0 {
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

// TestSnapshot checks that a snapshot trusts no more than the file held
// when it was taken, whatever is trusted after, and no more than the file
// holds now: a trust taken back, or given to other contents, applies at
// once. It changes nothing, and one of a store that could not be read, or
// that cannot be read now, trusts nothing.
func TestSnapshot(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "vegtam", "trust.json"))
	const a, b = "/w/a/http-client.cmd.json", "/w/b/http-client.cmd.json"
	do := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	do(s.Trust(a, "aa"))
	snap := s.Snapshot()
	check := func(file, sum string, want Status) {
		t.Helper()
		if got, err := snap.Check(file, sum); got != want || err != nil {
			t.Errorf("snapshot: %s %s = %s, %v; want %s", file, sum, got, err, want)
		}
	}
	check(a, "aa", Trusted)
	check(a, "a2", Changed)
	check(b, "bb", Untrusted)
	do(s.Trust(b, "bb"))
	check(b, "bb", Since)
	do(s.Trust(a, "a2"))
	check(a, "a2", Since)
	check(a, "aa", Changed)
	_, err := s.Revoke(a)
	do(err)
	check(a, "aa", Untrusted)
	if m, lerr := snap.List(); lerr != nil || len(m) != 1 || m[a] != "aa" || snap.Path() != s.Path() {
		t.Errorf("snapshot: List = %v, %v", m, lerr)
	} else {
		m[b] = "bb" // the map given is a copy
	}
	before, err := os.ReadFile(s.Path())
	do(err)
	if err := snap.Trust(b, "x"); err == nil {
		t.Error("a snapshot trusted a file")
	}
	if _, err := snap.Revoke(a); err == nil {
		t.Error("a snapshot revoked a file")
	}
	if after, err := os.ReadFile(s.Path()); err != nil || string(after) != string(before) {
		t.Errorf("a snapshot wrote the store: %s, %v", after, err)
	}
	if m, err := snap.List(); err != nil || len(m) != 1 {
		t.Errorf("snapshot after: %v, %v", m, err)
	}

	// Others can write the file: a snapshot taken then trusts nothing, nor
	// one taken before, while it lasts.
	do(s.Trust(a, "aa"))
	good := s.Snapshot()
	do(os.Chmod(s.Path(), 0o666))
	bad := s.Snapshot()
	for name, snap := range map[string]*Store{"before": good, "while": bad} {
		if got, err := snap.Check(a, "aa"); got != Untrusted || err == nil || !strings.Contains(err.Error(), "others can write it") {
			t.Errorf("a snapshot taken %s others could write the store: %s, %v", name, got, err)
		}
	}
	do(os.Chmod(s.Path(), 0o600))
	if got, err := bad.Check(a, "aa"); got != Untrusted || err == nil {
		t.Errorf("a snapshot of a store others could write, once private again: %s, %v", got, err)
	}
	if got, err := good.Check(a, "aa"); got != Trusted || err != nil {
		t.Errorf("a snapshot, once the store is private again: %s, %v", got, err)
	}
}

// TestStoreTooLarge checks that a store larger than any a person keeps
// trusts nothing, rather than be read whole.
func TestStoreTooLarge(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "vegtam", "trust.json"))
	if err := os.Mkdir(filepath.Dir(s.Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	big := `{"trusted": {"/a/http-client.cmd.json": "` + strings.Repeat("x", maxStore) + `"}}`
	if err := os.WriteFile(s.Path(), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Check("/a/http-client.cmd.json", strings.Repeat("x", maxStore)); got != Untrusted || err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("a store too large: %s, %v", got, err)
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
