// Package policy holds what a person allows vegtam to do on its own:
// running the commands of a command file, http-client.cmd.json, only once
// a person has trusted the file with "vegtam trust", and only as long as
// it has not changed since, as direnv does with .envrc files; and what the
// operator's policy file allows and limits (see Policy).
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"

	"github.com/vidforull/vegtam/internal/core"
)

// Status is what the trust store says of a command file.
type Status string

const (
	Untrusted Status = "untrusted" // never trusted, or trust revoked
	Changed   Status = "changed"   // trusted, but its contents have changed since
	Trusted   Status = "trusted"
	Missing   Status = "missing" // trusted, but the file is gone
	// Since is what a snapshot says of a file trusted since it was taken:
	// it runs once the keeper that took it starts again.
	Since Status = "trusted since"
)

// Store is the record of trusted command files: a JSON file mapping the
// path of each to a SHA-256 of what it runs, readable by its owner only.
type Store struct {
	path string
	err  error // why there is no store
	// frozen, if set, is what the file held when Snapshot read it: the
	// store trusts no more than it, and cannot be changed.
	frozen *snapshot
}

// snapshot is what a store's file held, or why it could not be read.
type snapshot struct {
	trusted map[string]string
	err     error
}

// Snapshot returns the store as its file is now, read once: it trusts a
// file only if what it read trusts it, and the file still does, with the
// same sum; it cannot be changed. A keeper runs the commands of the files
// trusted when it started, as long as they are: a program of the same
// user can write the file while it runs, and a trust taken back applies
// at once.
func (s *Store) Snapshot() *Store {
	m, err := s.load()
	return &Store{path: s.path, frozen: &snapshot{trusted: m, err: err}}
}

// NewStore returns the store kept in the file at path.
func NewStore(path string) *Store { return &Store{path: path} }

// DefaultStore returns the store in $XDG_CONFIG_HOME/vegtam/trust.json,
// or in ~/.config/vegtam/trust.json if XDG_CONFIG_HOME is not set. If
// neither can be found, the store trusts nothing and cannot be changed.
func DefaultStore() *Store {
	dir, err := ConfigDir()
	if err != nil {
		return &Store{err: fmt.Errorf("no trust store: %w", err)}
	}
	return NewStore(filepath.Join(dir, "trust.json"))
}

// ConfigDir returns vegtam's configuration directory, that of the trust
// store and the policy: $XDG_CONFIG_HOME/vegtam, or ~/.config/vegtam if
// XDG_CONFIG_HOME is not set.
func ConfigDir() (string, error) { return xdgDir("XDG_CONFIG_HOME", ".config") }

// HistoryDir returns the directory of the history of runs,
// $XDG_DATA_HOME/vegtam, or ~/.local/share/vegtam if XDG_DATA_HOME is not
// set; or "" if the operator keeps no history: VEGTAM_NO_HISTORY is set
// to anything but "". The process environment is read here, for
// {{$env NAME}} and the credentials of the proxy (see env.Lookup), for
// the proxy of the environment, and for whether a variable holds a value,
// which vegtam doctor says (see env.Has), and nowhere else.
func HistoryDir() (string, error) {
	if os.Getenv("VEGTAM_NO_HISTORY") != "" {
		return "", nil
	}
	return xdgDir("XDG_DATA_HOME", filepath.Join(".local", "share"))
}

// keeperSocket is the name of the keeper's socket.
const keeperSocket = "keeper.sock"

// KeeperSocket returns the path of the unix socket that the keeper
// listens on: $XDG_RUNTIME_DIR/vegtam/keeper.sock, in the directory that
// is the user's alone and goes when they log out; or, if XDG_RUNTIME_DIR
// is not set to an absolute path, keeper.sock in vegtam's directory of
// the user's cache, ~/.cache/vegtam or ~/Library/Caches/vegtam on macOS.
func KeeperSocket() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(dir) {
		cache, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("%w; set XDG_RUNTIME_DIR", err)
		}
		dir = cache
	}
	return filepath.Join(dir, "vegtam", keeperSocket), nil
}

// xdgDir returns vegtam's directory in the base directory that the
// environment variable name gives, as the XDG Base Directory
// Specification has it, or in fallback in the home directory if name is
// not set to an absolute path.
func xdgDir(name, fallback string) (string, error) {
	dir := os.Getenv(name)
	if !filepath.IsAbs(dir) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("%w; set %s or HOME", err, name)
		}
		dir = filepath.Join(home, fallback)
	}
	return filepath.Join(dir, "vegtam"), nil
}

// Path returns the file the store is kept in.
func (s *Store) Path() string { return s.path }

// Sum returns the SHA-256 of b in hex, as the store records it.
func Sum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Canonical returns the absolute path of file with the symbolic links of
// its directory resolved, so that one file has one entry however its
// directory is reached. The name itself stays as it is: a symbolic link
// named like a command file is an entry of its own, so that a link to a
// trusted file elsewhere does not borrow its trust.
func Canonical(file string) (string, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	dir, name := filepath.Split(abs)
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Join(resolved, name), nil
	}
	return abs, nil
}

// Check returns what the store says of the command file at file, a
// canonical path, whose commands have the SHA-256 sum. A snapshot asks
// its file too: Trusted only if both trust it; Since if only the file
// does.
func (s *Store) Check(file, sum string) (Status, error) {
	st, err := s.check(file, sum)
	if s.frozen == nil || err != nil {
		return st, err
	}
	now, err := NewStore(s.path).check(file, sum)
	switch {
	case err != nil:
		return Untrusted, err
	case st == Trusted:
		return now, nil
	case now == Trusted:
		return Since, nil
	}
	return st, nil
}

// check returns what the store, or a snapshot, holds of file with sum.
func (s *Store) check(file, sum string) (Status, error) {
	m, err := s.load()
	if err != nil {
		return Untrusted, err
	}
	switch recorded, ok := m[file]; {
	case !ok:
		return Untrusted, nil
	case recorded != sum:
		return Changed, nil
	}
	return Trusted, nil
}

// Trust records the command file at file, a canonical path, as trusted
// with the SHA-256 sum of its commands.
func (s *Store) Trust(file, sum string) error {
	m, err := s.load()
	if err != nil {
		return err
	}
	m[file] = sum
	return s.save(m)
}

// Revoke removes the command file at file, a canonical path, from the
// store, and reports whether it was there.
func (s *Store) Revoke(file string) (bool, error) {
	m, err := s.load()
	if err != nil {
		return false, err
	}
	if _, ok := m[file]; !ok {
		return false, nil
	}
	delete(m, file)
	return true, s.save(m)
}

// List returns the recorded files with their SHA-256 sums.
func (s *Store) List() (map[string]string, error) { return s.load() }

// maxStore is the most bytes of the store's file that are read: some
// thousands of files.
const maxStore = 1 << 20

// record is the layout of the store's file.
type record struct {
	Trusted map[string]string `json:"trusted"` // canonical path -> SHA-256, hex
}

func (s *Store) load() (map[string]string, error) {
	if s.frozen != nil {
		return maps.Clone(s.frozen.trusted), s.frozen.err
	}
	if s.err != nil {
		return nil, core.Errorf(core.KindPolicy, core.Source{}, "%v", s.err)
	}
	fail := func(format string, args ...any) error {
		return core.Errorf(core.KindPolicy, core.Source{File: s.path}, format, args...)
	}
	// Opened through an os.Root of its directory, which refuses a
	// symbolic link that leads out of it: the directory checked below
	// must be the one the store is in.
	dir, name := filepath.Split(s.path)
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	} else if err != nil {
		return nil, fail("%v", err)
	}
	defer root.Close()
	// Whoever can write the store, or replace it in its directory, can
	// trust any command. The directory first: whoever can write it could
	// put anything in the store's place between the checks and the open.
	if derr := checkDir(root, filepath.Dir(s.path), "it trusts nothing", fail); derr != nil {
		return nil, derr
	}
	// A named pipe would block the open until something writes to it; one
	// put in its place after the check is opened without waiting, and
	// refused then.
	if fi, serr := root.Stat(name); errors.Is(serr, fs.ErrNotExist) {
		return map[string]string{}, nil
	} else if serr != nil {
		return nil, fail("%v", serr)
	} else if !fi.Mode().IsRegular() {
		return nil, fail("not a regular file")
	}
	f, err := openFile(root, name)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	} else if err != nil {
		return nil, fail("%v", err)
	}
	m, err := s.read(f, fail)
	if cerr := f.Close(); err == nil && cerr != nil {
		return nil, fail("%v", cerr)
	}
	return m, err
}

// read reads the store from f, whose directory is checked.
func (s *Store) read(f *os.File, fail func(string, ...any) error) (map[string]string, error) {
	fi, err := f.Stat()
	switch {
	case err != nil:
		return nil, fail("%v", err)
	case !fi.Mode().IsRegular(): // put in its place after the check of its name
		return nil, fail("not a regular file")
	case !OwnedByUser(fi):
		return nil, fail("it belongs to another user, so it trusts nothing")
	case fi.Mode().Perm()&0o022 != 0:
		return nil, fail("others can write it, so it trusts nothing; make it private: chmod 600 %s", s.path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxStore+1))
	switch {
	case err != nil:
		return nil, fail("%v", err)
	case len(b) > maxStore:
		return nil, fail("larger than %d bytes, so it trusts nothing", maxStore)
	}
	var r record
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fail("%v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fail("data after the record")
	}
	if r.Trusted == nil {
		r.Trusted = map[string]string{}
	}
	return r.Trusted, nil
}

// save writes m to the store's file, as WriteFile does, so that a reader
// never sees half of it.
func (s *Store) save(m map[string]string) error {
	fail := func(err error) error { return core.Errorf(core.KindPolicy, core.Source{File: s.path}, "%v", err) }
	if s.frozen != nil {
		return fail(errors.New("the trust store as it was read is not changed"))
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(record{m}) // a map of strings always encodes
	if b.Len() > maxStore {
		return fail(fmt.Errorf("it would be larger than %d bytes, and then trust nothing", maxStore))
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fail(err)
	}
	defer root.Close()
	if err := WriteFile(root, filepath.Base(s.path), b.Bytes()); err != nil {
		return fail(err)
	}
	return nil
}
