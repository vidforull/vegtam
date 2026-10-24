package store

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// fast makes Argon2id as cheap as it can be for the test, lowering the
// bounds to let it: the suite stays fast, and files are still checked.
func fast(tb testing.TB) {
	tb.Helper()
	saved := argon
	argon.defaults = kdf{Name: kdfName, Time: 1, MemoryKiB: 8, Threads: 1}
	argon.least = kdf{Time: 1, MemoryKiB: 8, Threads: 1}
	tb.Cleanup(func() { argon = saved })
}

// privateDir returns a new directory that its owner alone can write, as
// the store wants: the umask may let the group write those of t.TempDir.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vegtam")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// mustCreate returns the store made at path, closed when the test ends.
func mustCreate(t *testing.T, path, password string) *Store {
	t.Helper()
	s, err := Create(path, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// mustOpen returns the store at path, closed when the test ends.
func mustOpen(t *testing.T, path, password string) *Store {
	t.Helper()
	s, err := Open(path, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// newStore returns a store made in a new directory, with a secret.
func newStore(t *testing.T, password string) *Store {
	t.Helper()
	fast(t)
	s := mustCreate(t, filepath.Join(t.TempDir(), "vegtam", FileName), password)
	if err := s.Set("token", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := s.Allow("token", "https://api.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	return s
}

// fileOf returns the file at path, decoded but not checked.
func fileOf(t *testing.T, path string) *file {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

// rewrite writes f to the file at path.
func rewrite(t *testing.T, path string, f *file) {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// mustAEAD returns the cipher of the store's files with key.
func mustAEAD(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func TestRoundTrip(t *testing.T) {
	fast(t)
	dir := filepath.Join(t.TempDir(), "vegtam")
	path := filepath.Join(dir, FileName)
	if ok, err := Exists(path); ok || err != nil {
		t.Fatalf("Exists before Create = %v, %v", ok, err)
	}
	s := mustCreate(t, path, "correct horse")
	for _, err := range []error{
		s.Set("token", "s3cret \"quoted\" <&> ünï"),
		s.Allow("token", "https://API.example.com/", "http://127.0.0.1:8080", "https://api.example.com"),
		s.Set("b.key-2", ""),
		s.Set("unbound", "x"),
		s.Allow("b.key-2", "https://b.example"),
		s.Save(),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := Exists(path); !ok || err != nil {
		t.Errorf("Exists = %v, %v", ok, err)
	}
	if _, err := Create(path, []byte("other")); !errors.Is(err, ErrExists) {
		t.Errorf("Create again: %v, want ErrExists", err)
	}
	want := []string{"b.key-2", "token", "unbound"}
	if names, err := Names(path); err != nil || !slices.Equal(names, want) {
		t.Errorf("Names = %q, %v; want %q", names, err, want)
	}
	// Where each may go is known without the password too.
	if origins, err := Origins(path); err != nil || len(origins) != 3 || len(origins["unbound"]) != 0 ||
		!slices.Equal(origins["token"], []string{"http://127.0.0.1:8080", "https://api.example.com"}) ||
		!slices.Equal(origins["b.key-2"], []string{"https://b.example"}) {
		t.Errorf("Origins = %q, %v", origins, err)
	}
	// Private to its owner, and written whole.
	for p, mode := range map[string]os.FileMode{path: 0o600, dir: 0o700} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != mode {
			t.Errorf("%s: mode %v, %v; want %v", p, fi.Mode().Perm(), err, mode)
		}
	}
	before := fileOf(t, path)

	o := mustOpen(t, path, "correct horse")
	if names := o.Names(); !slices.Equal(names, want) {
		t.Errorf("Names = %q, want %q", names, want)
	}
	sec, ok := o.Get("token")
	if !ok || sec.Value != "s3cret \"quoted\" <&> ünï" ||
		!slices.Equal(sec.Origins, []string{"http://127.0.0.1:8080", "https://api.example.com"}) {
		t.Errorf("Get(token) = %q, %v", sec, ok)
	}
	if unbound, ok := o.Get("unbound"); !ok || unbound.Value != "x" || unbound.Origins == nil || len(unbound.Origins) != 0 {
		t.Errorf("Get(unbound) = %#v, %v", unbound, ok)
	}
	if _, ok := o.Get("missing"); ok {
		t.Error("Get(missing) found it")
	}
	// What Get returns is a copy.
	sec.Origins[0] = "https://evil.example"
	if again, _ := o.Get("token"); again.Origins[0] != "http://127.0.0.1:8080" {
		t.Errorf("Get shares its origins: %q", again.Origins)
	}

	// Changed and saved: a new nonce, the same salt and parameters.
	if err := o.Deny("token", "http://127.0.0.1:8080", "https://not.there.example"); err != nil {
		t.Fatal(err)
	}
	if err := o.Set("token", "new"); err != nil {
		t.Fatal(err)
	}
	if was, err := o.Remove("b.key-2"); !was || err != nil {
		t.Errorf("Remove = %v, %v", was, err)
	}
	if was, err := o.Remove("b.key-2"); was || err != nil {
		t.Errorf("Remove again = %v, %v", was, err)
	}
	if err := o.Save(); err != nil {
		t.Fatal(err)
	}
	after := fileOf(t, path)
	if !bytes.Equal(after.KDF.Salt, before.KDF.Salt) || after.KDF.Time != before.KDF.Time ||
		after.KDF.MemoryKiB != before.KDF.MemoryKiB || after.KDF.Threads != before.KDF.Threads {
		t.Errorf("kdf changed on save: %+v, then %+v", before.KDF, after.KDF)
	}
	if bytes.Equal(after.Nonce, before.Nonce) {
		t.Error("the nonce was used again")
	}
	r := mustOpen(t, path, "correct horse")
	if sec, ok := r.Get("token"); !ok || sec.Value != "new" || !slices.Equal(sec.Origins, []string{"https://api.example.com"}) {
		t.Errorf("Get(token) after save = %q, %v", sec, ok)
	}
	if names := r.Names(); !slices.Equal(names, []string{"token", "unbound"}) {
		t.Errorf("Names after save = %q", names)
	}
	// Each save left the store's file alone in its directory.
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 || entries[0].Name() != FileName {
		t.Errorf("the directory holds %v, %v", entries, err)
	}
}

func TestEmpty(t *testing.T) {
	fast(t)
	path := filepath.Join(privateDir(t), FileName)
	mustCreate(t, path, "pw").Close()
	if names, err := Names(path); err != nil || names == nil || len(names) != 0 {
		t.Errorf("Names = %#v, %v", names, err)
	}
	o := mustOpen(t, path, "pw")
	if err := o.Set("a", "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(filepath.Join(privateDir(t), FileName), nil); err == nil {
		t.Error("Create with no password")
	}
}

func TestNoStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vegtam", FileName)
	if _, err := Open(path, []byte("pw")); !errors.Is(err, ErrNoStore) {
		t.Errorf("Open without a directory: %v, want ErrNoStore", err)
	}
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Names(path); !errors.Is(err, ErrNoStore) {
		t.Errorf("Names without a file: %v, want ErrNoStore", err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Dir(filepath.Dir(path)))
	if got, err := Path(); got != path || err != nil {
		t.Errorf("Path = %q, %v; want %q", got, err, path)
	}
}

func TestWrongPassword(t *testing.T) {
	s := newStore(t, "right")
	_, err := Open(s.path, []byte("wrong"))
	if !errors.Is(err, ErrPassword) || !strings.Contains(err.Error(), "wrong password, or the file was changed") {
		t.Errorf("Open = %v, want ErrPassword", err)
	}
	if _, err := Open(s.path, nil); !errors.Is(err, ErrPassword) {
		t.Errorf("Open with no password = %v, want ErrPassword", err)
	}
}

// TestTampered checks that a change to any field of the file fails: one
// that the header's checks let through fails as a wrong password does.
func TestTampered(t *testing.T) {
	s := newStore(t, "pw")
	if err := s.Set("zeta", "z"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(b []byte) []byte { c := slices.Clone(b); c[len(c)/2] ^= 1; return c }
	for _, tt := range []struct {
		name   string
		change func(*file)
		want   error
	}{
		{"version", func(f *file) { f.Version = 2 }, ErrVersion},
		{"version 0", func(f *file) { f.Version = 0 }, ErrCorrupt},
		{"kdf", func(f *file) { f.KDF.Name = "scrypt" }, ErrVersion},
		{"aead", func(f *file) { f.AEAD = "aes-256-gcm" }, ErrVersion},
		{"no aead", func(f *file) { f.AEAD = "" }, ErrCorrupt},
		{"time", func(f *file) { f.KDF.Time++ }, ErrPassword},
		{"memory", func(f *file) { f.KDF.MemoryKiB *= 2 }, ErrPassword},
		{"threads", func(f *file) { f.KDF.Threads++ }, ErrPassword},
		{"salt", func(f *file) { f.KDF.Salt = flip(f.KDF.Salt) }, ErrPassword},
		{"short salt", func(f *file) { f.KDF.Salt = f.KDF.Salt[1:] }, ErrCorrupt},
		{"name added", func(f *file) { f.Names = append(f.Names, "zz") }, ErrPassword},
		{"name added first", func(f *file) { f.Names = append([]string{"a"}, f.Names...) }, ErrPassword},
		{"name removed", func(f *file) { f.Names = f.Names[:1] }, ErrPassword},
		{"names reordered", func(f *file) { slices.Reverse(f.Names) }, ErrCorrupt},
		{"name twice", func(f *file) { f.Names = append(f.Names, f.Names[1]) }, ErrCorrupt},
		{"name renamed", func(f *file) { f.Names[0] = "tokem" }, ErrPassword},
		{"not a name", func(f *file) { f.Names[0] = "{{x}}" }, ErrCorrupt},
		{"no names", func(f *file) { f.Names = nil }, ErrCorrupt},
		{"origin added", func(f *file) { f.Origins["zeta"] = []string{"https://exfil.example"} }, ErrPassword},
		{"origins dropped", func(f *file) { f.Origins = nil }, ErrPassword},
		{"origin not one", func(f *file) { f.Origins["zeta"] = []string{"https://*.example"} }, ErrCorrupt},
		{"nonce", func(f *file) { f.Nonce = flip(f.Nonce) }, ErrPassword},
		{"short nonce", func(f *file) { f.Nonce = f.Nonce[:12] }, ErrCorrupt},
		{"data flipped", func(f *file) { f.Data = flip(f.Data) }, ErrPassword},
		{"data truncated", func(f *file) { f.Data = f.Data[:len(f.Data)-1] }, ErrPassword},
		{"data cut short", func(f *file) { f.Data = f.Data[:15] }, ErrCorrupt},
		{"data extended", func(f *file) { f.Data = append(f.Data, 0) }, ErrPassword},
	} {
		var f file
		if err := json.Unmarshal(good, &f); err != nil {
			t.Fatal(err)
		}
		tt.change(&f)
		rewrite(t, s.path, &f)
		if _, err := Open(s.path, []byte("pw")); !errors.Is(err, tt.want) {
			t.Errorf("%s: Open = %v, want %v", tt.name, err, tt.want)
		}
		if _, err := Names(s.path); !errors.Is(tt.want, ErrPassword) && !errors.Is(err, tt.want) {
			t.Errorf("%s: Names = %v, want %v", tt.name, err, tt.want)
		}
	}
	// Origins of a name that the header does not have are not sealed, and
	// nothing reads them.
	var f file
	if err := json.Unmarshal(good, &f); err != nil {
		t.Fatal(err)
	}
	f.Origins["other"] = []string{"https://exfil.example"}
	rewrite(t, s.path, &f)
	if _, err := Open(s.path, []byte("pw")); err != nil {
		t.Errorf("origins of no name: Open = %v", err)
	}
	if origins, err := Origins(s.path); err != nil || origins["other"] != nil || len(origins) != 2 {
		t.Errorf("origins of no name: Origins = %q, %v", origins, err)
	}
	for _, tt := range []struct{ name, src string }{
		{"empty", ""},
		{"not JSON", "secrets"},
		{"cut short", string(good[:len(good)/2])},
		{"data after it", string(good) + "{}"},
		{"not an object", "[1]"},
		{"no version", `{"kdf": {}}`},
		{"unknown field", strings.Replace(string(good), `"aead"`, `"extra": 1, "aead"`, 1)},
		{"threads not a byte", strings.Replace(string(good), `"threads": 1`, `"threads": 300`, 1)},
		{"salt not base64", strings.Replace(string(good), `"salt": "`, `"salt": "!`, 1)},
	} {
		if err := os.WriteFile(s.path, []byte(tt.src), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(s.path, []byte("pw")); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: Open = %v, want ErrCorrupt", tt.name, err)
		}
	}
}

// TestCorruptData checks the data that opens but is not what vegtam
// writes: it is refused, and the error says nothing of it but names and
// origins.
func TestCorruptData(t *testing.T) {
	s := newStore(t, "pw")
	for _, tt := range []struct {
		name, plain string
		names       []string
	}{
		{"not JSON", `{"secrets": {"token": {"value": "marker-1`, []string{"token"}},
		{"names differ", `{"secrets": {"token": {"value": "marker-1"}}}`, []string{"other"}},
		{"a name too few", `{"secrets": {}}`, []string{"token"}},
		{"a name too many", `{"secrets": {"a": {}, "token": {}}}`, []string{"token"}},
		{"not an origin", `{"secrets": {"token": {"value": "marker-1", "origins": ["https://*.example"]}}}`, []string{"token"}},
		{"not as written", `{"secrets": {"token": {"value": "marker-1", "origins": ["https://API.example"]}}}`, []string{"token"}},
		{"a value not a string", `{"secrets": {"token": {"value": 1234}}}`, []string{"token"}},
	} {
		f := &file{Version: version, KDF: s.kdf, AEAD: aeadName, Names: tt.names, Nonce: make([]byte, 24)}
		aead := mustAEAD(t, s.key)
		f.Data = aead.Seal(nil, f.Nonce, []byte(tt.plain), f.associated())
		rewrite(t, s.path, f)
		_, err := Open(s.path, []byte("pw"))
		if !errors.Is(err, ErrCorrupt) || strings.Contains(err.Error(), "marker") || strings.Contains(err.Error(), "1234") {
			t.Errorf("%s: Open = %v, want ErrCorrupt without the value", tt.name, err)
		}
	}
}

// TestBounds checks that parameters out of bounds are refused before
// anything is derived: with memory_kib at 4 TiB, deriving would not end.
func TestBounds(t *testing.T) {
	path := filepath.Join(privateDir(t), FileName)
	ok := argon.defaults
	ok.Salt = make([]byte, saltSize)
	f := &file{Version: version, KDF: ok, AEAD: aeadName, Names: []string{}, Nonce: make([]byte, 24), Data: make([]byte, 16)}
	if err := f.check(); err != nil {
		t.Errorf("the default parameters: %v", err)
	}
	for _, tt := range []struct {
		name   string
		change func(*kdf)
	}{
		{"time 0", func(k *kdf) { k.Time = 0 }},
		{"time 11", func(k *kdf) { k.Time = 11 }},
		{"time most", func(k *kdf) { k.Time = 1<<32 - 1 }},
		{"memory 8 MiB less 1 KiB", func(k *kdf) { k.MemoryKiB = 8<<10 - 1 }},
		{"memory 1 GiB and 1 KiB", func(k *kdf) { k.MemoryKiB = 1<<20 + 1 }},
		{"memory most", func(k *kdf) { k.MemoryKiB = 1<<32 - 1 }},
		{"threads 0", func(k *kdf) { k.Threads = 0 }},
		{"threads 17", func(k *kdf) { k.Threads = 17 }},
		{"threads most", func(k *kdf) { k.Threads = 255 }},
	} {
		f.KDF = ok
		tt.change(&f.KDF)
		rewrite(t, path, f)
		if _, err := Names(path); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: Names = %v, want ErrCorrupt", tt.name, err)
		}
		if _, err := Open(path, []byte("pw")); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "is not from") {
			t.Errorf("%s: Open = %v, want ErrCorrupt", tt.name, err)
		}
	}
}

func TestPermissions(t *testing.T) {
	s := newStore(t, "pw")
	dir := filepath.Dir(s.path)
	check := func(what, want string) {
		t.Helper()
		if _, err := Names(s.path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: Names = %v, want %q", what, err, want)
		}
		if _, err := Open(s.path, []byte("pw")); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: Open = %v, want %q", what, err, want)
		}
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o620, 0o604} {
		if err := os.Chmod(s.path, mode); err != nil {
			t.Fatal(err)
		}
		check(mode.String(), "others can read or write it, so it is not used; make it private: chmod 600 "+s.path)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	check("directory 0777", "others can write its directory, so it is not used; make it private: chmod 700 "+dir)
	if err := s.Save(); err == nil || !strings.Contains(err.Error(), "others can write its directory") {
		t.Errorf("Save into a directory others can write: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(s.path, []byte("pw")); err != nil {
		t.Errorf("a directory others can read: %v", err)
	}

	// A symbolic link, even to a store beside it, is refused.
	if err := os.Rename(s.path, filepath.Join(dir, "real.enc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.enc", s.path); err != nil {
		t.Fatal(err)
	}
	check("symbolic link", "a symbolic link")
	if err := os.Remove(s.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.path, 0o700); err != nil {
		t.Fatal(err)
	}
	check("directory", "not a regular file")
}

func TestTooLarge(t *testing.T) {
	s := newStore(t, "pw")
	if err := s.Set("big", strings.Repeat("a", maxSize*3/4)); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err == nil || !strings.Contains(err.Error(), "larger than 16 MiB") {
		t.Errorf("Save = %v", err)
	}
	if err := os.WriteFile(s.path, bytes.Repeat([]byte(" "), maxSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Names(s.path); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "larger than 16 MiB") {
		t.Errorf("Names of a file too large = %v", err)
	}
}

func TestChecks(t *testing.T) {
	s := newStore(t, "pw")
	for _, name := range []string{"", "1st", "-a", ".a", "a b", "{{a}}", "$env", "a\x1b"} {
		if err := s.Set(name, "v"); err == nil {
			t.Errorf("Set(%q) took it", name)
		}
	}
	if err := s.Set("token", "a\xffb"); err == nil || !strings.Contains(err.Error(), "not UTF-8 text") {
		t.Errorf("Set of a value not UTF-8: %v", err)
	}
	for _, o := range []string{"https://*.example.com", "ftp://example.com", "https://example.com/path", "https://u:p@example.com", "example.com"} {
		if err := s.Allow("token", "https://ok.example", o); err == nil {
			t.Errorf("Allow(%q) took it", o)
		}
		if err := s.Deny("token", o); err == nil {
			t.Errorf("Deny(%q) took it", o)
		}
	}
	if sec, _ := s.Get("token"); !slices.Equal(sec.Origins, []string{"https://api.example.com"}) {
		t.Errorf("an Allow that failed changed the origins: %q", sec.Origins)
	}
	if err := s.Allow("missing", "https://api.example.com"); !errors.Is(err, ErrNoSecret) {
		t.Errorf("Allow(missing) = %v, want ErrNoSecret", err)
	}
	if err := s.Deny("missing", "https://api.example.com"); !errors.Is(err, ErrNoSecret) {
		t.Errorf("Deny(missing) = %v, want ErrNoSecret", err)
	}
}

func TestChangePassword(t *testing.T) {
	s := newStore(t, "old")
	salt := slices.Clone(s.kdf.Salt)
	key := s.key
	if err := s.ChangePassword(nil); err == nil {
		t.Error("ChangePassword to no password")
	}
	if err := s.ChangePassword([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s.kdf.Salt, salt) {
		t.Error("the salt stayed")
	}
	if !slices.Equal(key, make([]byte, len(key))) {
		t.Error("the old key was not zeroed")
	}
	if _, err := Open(s.path, []byte("old")); !errors.Is(err, ErrPassword) {
		t.Errorf("Open with the old password = %v", err)
	}
	o, err := Open(s.path, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if sec, ok := o.Get("token"); !ok || sec.Value != "s3cret" {
		t.Errorf("Get = %q, %v", sec, ok)
	}

	// A save that fails keeps the old password.
	if err := os.Chmod(filepath.Dir(s.path), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword([]byte("newer")); err == nil {
		t.Error("ChangePassword saved into a directory others can write")
	}
	if err := os.Chmod(filepath.Dir(s.path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(s.path, []byte("new")); err != nil {
		t.Errorf("Open after a failed change: %v", err)
	}
}

func TestClose(t *testing.T) {
	s := newStore(t, "pw")
	key := s.key
	if len(key) != 32 || slices.Equal(key, make([]byte, 32)) {
		t.Fatalf("key = %x", key)
	}
	s.Close()
	if !slices.Equal(key, make([]byte, 32)) {
		t.Errorf("Close left the key: %x", key)
	}
	if _, ok := s.Get("token"); ok {
		t.Error("Get after Close found it")
	}
	if names := s.Names(); len(names) != 0 {
		t.Errorf("Names after Close = %q", names)
	}
	for what, err := range map[string]error{
		"Set":            s.Set("token", "v"),
		"Allow":          s.Allow("token", "https://api.example.com"),
		"Deny":           s.Deny("token", "https://api.example.com"),
		"Save":           s.Save(),
		"ChangePassword": s.ChangePassword([]byte("pw")),
	} {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("%s after Close = %v, want ErrClosed", what, err)
		}
	}
	if _, err := s.Remove("token"); !errors.Is(err, ErrClosed) {
		t.Errorf("Remove after Close = %v, want ErrClosed", err)
	}
	s.Close() // again: nothing
}

// TestCanary checks that a value and the password are in no byte of the
// file, in no form, and in no error.
func TestCanary(t *testing.T) {
	fast(t)
	value, password := "value-"+rand.Text(), "password-"+rand.Text()
	path := filepath.Join(privateDir(t), FileName)
	s, err := Create(path, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, err := range []error{s.Set("token", value), s.Allow("token", "https://api.example.com"), s.Set("other", value), s.Save()} {
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{value, password} {
		for _, form := range []string{marker, base64.StdEncoding.EncodeToString([]byte(marker)), base64.RawURLEncoding.EncodeToString([]byte(marker))} {
			if bytes.Contains(b, []byte(form)) {
				t.Errorf("the file holds %q", form)
			}
		}
	}
	// Every way the store fails, with the value at hand.
	_, wrong := Open(path, []byte(value))
	errs := []error{
		s.Set("", value),
		s.Set("a b", value),
		s.Set("token", value+"\xff"),
		s.Allow("token", "ftp://api.example.com"),
		s.Deny("missing", "https://api.example.com"),
		wrong,
	}
	f := fileOf(t, path)
	f.KDF.Time = 99
	rewrite(t, path, f)
	_, err = Open(path, []byte(password))
	errs = append(errs, err)
	f.KDF.Time = 2
	rewrite(t, path, f)
	_, err = Open(path, []byte(password))
	errs = append(errs, err)
	for i, err := range errs {
		switch {
		case err == nil:
			t.Errorf("%d: no error", i)
		case strings.Contains(err.Error(), value), strings.Contains(err.Error(), password):
			t.Errorf("%d: the error holds the value or the password: %v", i, err)
		}
	}
}
