// Package store keeps a person's secrets in a file of their own, encrypted
// under a password: for each, by name, its value and the origins it may go
// to. The keeper and a person's own runs read them from it; a program that
// the keeper sends requests for never sees them.
//
// The file is secrets.enc in vegtam's configuration directory, readable by
// its owner only. It is a JSON document:
//
//	{
//	  "vegtam_secrets": 1,
//	  "kdf": {"name": "argon2id", "time": 3, "memory_kib": 65536, "threads": 4, "salt": "<base64, 16 bytes>"},
//	  "aead": "xchacha20-poly1305",
//	  "names": ["token"],
//	  "origins": {"token": ["https://api.example.com"]},
//	  "nonce": "<base64, 24 bytes>",
//	  "data": "<base64>"
//	}
//
// The names are in the clear, sorted, each once, and so are the origins
// each may go to, sorted, each once: they are no secret, as .http files
// hold the names and private environment files the origins, and a run
// without a person can tell which of its placeholders the store holds and
// where each may go, without its password. The values are in data alone,
// sealed with XChaCha20-Poly1305 under a key that Argon2id derives from
// the password and the salt. Opened, data is
//
//	{"secrets": {"token": {"value": "...", "origins": ["https://api.example.com"]}}}
//
// The additional data of the seal is every field but data, each as a
// netstring ("<length>:<bytes>,", numbers in decimal), in this order:
// "vegtam_secrets", the version, the kdf's name, time, memory_kib, threads
// and salt, the aead, the number of names, each name, for each name the
// number of its origins and each origin, and the nonce. The origins in data
// must be those of the header.
// Changing any of them fails as a wrong password does. Each save draws a
// new nonce; the salt and the parameters change with the password alone.
//
// Go strings cannot be wiped: while a store is open, its values are in
// memory as strings, until the memory is reused. The key is a []byte that
// Close zeroes; the password is the caller's, and the store keeps no copy.
package store

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/policy"
)

const (
	// FileName is the name of the store's file in vegtam's configuration
	// directory.
	FileName = "secrets.enc"
	// version is the format of the file that this vegtam reads and writes.
	version  = 1
	kdfName  = "argon2id"
	aeadName = "xchacha20-poly1305"
	saltSize = 16
	// maxSize is the most bytes of the file that are read, and that a save
	// writes.
	maxSize = 16 << 20
)

var (
	// ErrNoStore is the error of a store whose file does not exist.
	ErrNoStore = errors.New("no store of secrets")
	// ErrExists is the error of Create where a store's file exists.
	ErrExists = errors.New("a store of secrets is there already")
	// ErrPassword is the error of a store that its password does not open:
	// the password is wrong, or the file was changed since vegtam wrote
	// it, which cannot be told apart.
	ErrPassword = errors.New("wrong password, or the file was changed")
	// ErrCorrupt is the error of a file that is not a store as vegtam
	// writes it, or asks for parameters out of bounds.
	ErrCorrupt = errors.New("not a store of secrets that vegtam can read")
	// ErrVersion is the error of a file in a format, or with a cipher,
	// that this vegtam does not know.
	ErrVersion = errors.New("written by a newer vegtam")
	// ErrNoSecret is the error of a name that the store holds no secret of.
	ErrNoSecret = errors.New("no such secret")
	// ErrClosed is the error of a store used after Close.
	ErrClosed = errors.New("the store is closed")
)

// Secret is a value and the origins it may go to, as core.Origin writes
// them.
type Secret struct {
	Value   string   `json:"value"`
	Origins []string `json:"origins"`
}

// Store is an open store of secrets. It is not safe for concurrent use.
type Store struct {
	path    string
	kdf     kdf
	key     []byte // derived from the password; zeroed by Close
	secrets map[string]Secret
}

// file is the layout of the store's file.
type file struct {
	Version uint32              `json:"vegtam_secrets"`
	KDF     kdf                 `json:"kdf"`
	AEAD    string              `json:"aead"`
	Names   []string            `json:"names"`
	Origins map[string][]string `json:"origins"`
	Nonce   []byte              `json:"nonce"`
	Data    []byte              `json:"data"`
}

// kdf is how the key is derived from the password: Argon2id, its
// parameters and the salt.
type kdf struct {
	Name      string `json:"name"`
	Time      uint32 `json:"time"` // passes over the memory
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Salt      []byte `json:"salt"`
}

// contents is the layout of the data, opened.
type contents struct {
	Secrets map[string]Secret `json:"secrets"`
}

// argon holds the parameters of Argon2id that a new store gets, RFC 9106's
// second recommendation, as 2 GiB is too much to ask of every machine; and
// the bounds of those a file may ask for, checked before anything is
// derived: a file made up must not make vegtam work for minutes or
// allocate gigabytes. Tests lower them.
var argon = struct{ defaults, least, most kdf }{
	defaults: kdf{Name: kdfName, Time: 3, MemoryKiB: 64 << 10, Threads: 4},
	least:    kdf{Time: 1, MemoryKiB: 8 << 10, Threads: 1},
	most:     kdf{Time: 10, MemoryKiB: 1 << 20, Threads: 16},
}

// Path returns the store's file: secrets.enc in vegtam's configuration
// directory (see policy.ConfigDir).
func Path() (string, error) {
	dir, err := policy.ConfigDir()
	if err != nil {
		return "", fmt.Errorf("no place for a store of secrets: %w", err)
	}
	return filepath.Join(dir, FileName), nil
}

// Exists reports whether there is anything at path, the store's file.
func Exists(path string) (bool, error) {
	switch _, err := os.Lstat(path); {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// Names returns the names of the secrets of the store at path, from its
// header alone, without its password; the header is checked as Open
// checks it. Only the password proves the names: Open fails if they were
// changed.
func Names(path string) ([]string, error) {
	f, err := read(path)
	if err != nil {
		return nil, err
	}
	return f.Names, nil
}

// Origins returns the secrets of the store at path, by name, each with the
// origins it may go to, from its header alone, as Names does.
func Origins(path string) (map[string][]string, error) {
	f, err := read(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(f.Names))
	for _, name := range f.Names {
		out[name] = slices.Clone(f.Origins[name])
	}
	return out, nil
}

// Create makes a new, empty store at path, with its directory if need be,
// under password, and writes it. It refuses to replace anything at path.
func Create(path string, password []byte) (*Store, error) {
	switch ok, err := Exists(path); {
	case err != nil:
		return nil, err
	case ok:
		return nil, fmt.Errorf("%s: %w", path, ErrExists)
	}
	k, key, err := newKey(password)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, kdf: k, key: key, secrets: map[string]Secret{}}
	if err = s.Save(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Open opens the store at path with password.
func Open(path string, password []byte) (*Store, error) {
	f, err := read(path)
	if err != nil {
		return nil, err
	}
	return unlock(path, f, password)
}

// newKey derives a key from password with a new salt and the parameters a
// new store gets.
func newKey(password []byte) (kdf, []byte, error) {
	if len(password) == 0 {
		return kdf{}, nil, errors.New("a store of secrets needs a password")
	}
	k := argon.defaults
	k.Salt = make([]byte, saltSize)
	if _, err := rand.Read(k.Salt); err != nil {
		return kdf{}, nil, err
	}
	return k, derive(password, k), nil
}

// derive derives the key from password as k says.
func derive(password []byte, k kdf) []byte {
	return argon2.IDKey(password, k.Salt, k.Time, k.MemoryKiB, k.Threads, chacha20poly1305.KeySize)
}

// read reads the store's file at path through an os.Root of its directory
// and checks its header. A file that others can read is refused, as they
// could try passwords on a copy; so is one that others can change, or
// replace in its directory, as they could put an older store back.
func read(path string) (*file, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", path, ErrNoStore)
	} else if err != nil {
		return nil, err
	}
	defer root.Close()
	// The directory first: whoever can write it could put anything in the
	// file's place between the checks below and the open.
	if err = checkDir(root, dir); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Not a symbolic link, which the open would follow, and not a named
	// pipe, which would block it.
	li, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s: %w", path, ErrNoStore)
	case err != nil:
		return nil, err
	case li.Mode()&fs.ModeSymlink != 0:
		return nil, fmt.Errorf("%s: a symbolic link; the store is a file of its own", path)
	case !li.Mode().IsRegular():
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	b, err := readFile(f, li, path)
	if cerr := f.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return parse(path, b)
}

// checkDir refuses dir, opened as root, if it belongs to another user or
// others can write it.
func checkDir(root *os.Root, dir string) error {
	di, err := root.Stat(".")
	switch {
	case err != nil:
		return err
	case !policy.OwnedByUser(di):
		return errors.New("its directory belongs to another user, so it is not used")
	case di.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("others can write its directory, so it is not used; make it private: chmod 700 %s", dir)
	}
	return nil
}

// readFile reads f, the file at path that li describes, once its owner and
// mode are checked.
func readFile(f *os.File, li fs.FileInfo, path string) ([]byte, error) {
	fi, err := f.Stat()
	switch {
	case err != nil:
		return nil, err
	case !os.SameFile(li, fi):
		return nil, fmt.Errorf("%s: replaced while it was opened", path)
	case !policy.OwnedByUser(fi):
		return nil, fmt.Errorf("%s: it belongs to another user, so it is not used", path)
	case fi.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("%s: others can read or write it, so it is not used; make it private: chmod 600 %s", path, path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	switch {
	case err != nil:
		return nil, err
	case len(b) > maxSize:
		return nil, fmt.Errorf("%s: %w: larger than %d MiB", path, ErrCorrupt, maxSize>>20)
	}
	return b, nil
}

// parse parses b, the store's file at path, and checks its header.
func parse(path string, b []byte) (*file, error) {
	corrupt := func(format string, args ...any) error {
		return fmt.Errorf("%s: %w: %s", path, ErrCorrupt, fmt.Sprintf(format, args...))
	}
	newer := func(format string, args ...any) error {
		return fmt.Errorf("%s: %w: %s; update vegtam", path, ErrVersion, fmt.Sprintf(format, args...))
	}
	// The format and the ciphers first: a newer format may have other
	// fields.
	var probe struct {
		Version *uint32 `json:"vegtam_secrets"`
		KDF     struct {
			Name string `json:"name"`
		} `json:"kdf"`
		AEAD string `json:"aead"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, corrupt("%v", err)
	}
	switch v := probe.Version; {
	case v == nil:
		return nil, corrupt("no vegtam_secrets")
	case *v > version:
		return nil, newer("format %d, where this one reads format %d", *v, version)
	case *v != version:
		return nil, corrupt("format %d", *v)
	case probe.KDF.Name == "" || probe.AEAD == "":
		return nil, corrupt("no kdf or no aead")
	case probe.KDF.Name != kdfName:
		return nil, newer("key derivation %q, where this one knows %s", probe.KDF.Name, kdfName)
	case probe.AEAD != aeadName:
		return nil, newer("cipher %q, where this one knows %s", probe.AEAD, aeadName)
	}
	var f file
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, corrupt("%v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, corrupt("data after the document")
	}
	if err := f.check(); err != nil {
		return nil, corrupt("%v", err)
	}
	return &f, nil
}

// check refuses a header with parameters outside the bounds of argon, or
// not of the form that vegtam writes.
func (f *file) check() error {
	lo, hi := argon.least, argon.most
	switch k := f.KDF; {
	case k.Time < lo.Time || k.Time > hi.Time:
		return fmt.Errorf("kdf time %d is not from %d to %d", k.Time, lo.Time, hi.Time)
	case k.MemoryKiB < lo.MemoryKiB || k.MemoryKiB > hi.MemoryKiB:
		return fmt.Errorf("kdf memory_kib %d is not from %d to %d", k.MemoryKiB, lo.MemoryKiB, hi.MemoryKiB)
	case k.Threads < lo.Threads || k.Threads > hi.Threads:
		return fmt.Errorf("kdf threads %d is not from %d to %d", k.Threads, lo.Threads, hi.Threads)
	case len(k.Salt) != saltSize:
		return fmt.Errorf("the salt is %d bytes, not %d", len(k.Salt), saltSize)
	case len(f.Nonce) != chacha20poly1305.NonceSizeX:
		return fmt.Errorf("the nonce is %d bytes, not %d", len(f.Nonce), chacha20poly1305.NonceSizeX)
	case len(f.Data) < chacha20poly1305.Overhead:
		return errors.New("the data is cut short")
	case f.Names == nil:
		return errors.New("no names")
	}
	for i, name := range f.Names {
		if !core.IsVarName(name) {
			return fmt.Errorf("%q is not a name", name)
		}
		if i > 0 && f.Names[i-1] >= name {
			return errors.New("the names are not sorted, each once")
		}
	}
	// The origins of a name that the header does not have are not sealed,
	// and nothing reads them.
	for name, origins := range f.Origins {
		for i, o := range origins {
			if p, err := core.ParseOrigin(o); err != nil || p != o || i > 0 && origins[i-1] >= o {
				return fmt.Errorf("the origins of %s are not origins, sorted, each once", name)
			}
		}
	}
	return nil
}

// associated returns the additional data of the seal: the header, all but
// the data, as the package says. Not JSON: every vegtam must write it the
// same, byte for byte.
func (f *file) associated() []byte {
	b := netstring(nil, "vegtam_secrets")
	b = netstring(b, strconv.FormatUint(uint64(f.Version), 10))
	b = netstring(b, f.KDF.Name)
	b = netstring(b, strconv.FormatUint(uint64(f.KDF.Time), 10))
	b = netstring(b, strconv.FormatUint(uint64(f.KDF.MemoryKiB), 10))
	b = netstring(b, strconv.FormatUint(uint64(f.KDF.Threads), 10))
	b = netstring(b, string(f.KDF.Salt))
	b = netstring(b, f.AEAD)
	b = netstring(b, strconv.Itoa(len(f.Names)))
	for _, name := range f.Names {
		b = netstring(b, name)
	}
	for _, name := range f.Names {
		b = netstring(b, strconv.Itoa(len(f.Origins[name])))
		for _, o := range f.Origins[name] {
			b = netstring(b, o)
		}
	}
	return netstring(b, string(f.Nonce))
}

// netstring appends s to b as a netstring: its length in decimal, ":",
// s and ",".
func netstring(b []byte, s string) []byte {
	b = strconv.AppendInt(b, int64(len(s)), 10)
	b = append(b, ':')
	b = append(b, s...)
	return append(b, ',')
}

// unlock derives the key of f, the store's file at path, from password,
// and opens its data.
func unlock(path string, f *file, password []byte) (*Store, error) {
	key := derive(password, f.KDF)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		clear(key)
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	plain, err := aead.Open(nil, f.Nonce, f.Data, f.associated())
	if err != nil {
		clear(key)
		return nil, fmt.Errorf("%s: %w", path, ErrPassword)
	}
	defer clear(plain)
	secrets, err := decode(plain, f.Names)
	for name, s := range secrets {
		if err == nil && !slices.Equal(s.Origins, f.Origins[name]) && (len(s.Origins) > 0 || len(f.Origins[name]) > 0) {
			err = fmt.Errorf("secret %s: its origins are not those of the header", name)
		}
	}
	if err != nil {
		clear(key)
		return nil, fmt.Errorf("%s: %w: %w", path, ErrCorrupt, err)
	}
	return &Store{path: path, kdf: f.KDF, key: key, secrets: secrets}, nil
}

// decode decodes plain, the data opened, whose secrets must be those that
// names, the header's, name. Its errors hold no part of plain but names
// and origins.
func decode(plain []byte, names []string) (map[string]Secret, error) {
	var c contents
	if json.Unmarshal(plain, &c) != nil {
		return nil, errors.New("its secrets do not decode")
	}
	if len(c.Secrets) != len(names) {
		return nil, errors.New("its names are not those of its secrets")
	}
	for _, name := range names {
		s, ok := c.Secrets[name]
		if !ok {
			return nil, errors.New("its names are not those of its secrets")
		}
		for _, o := range s.Origins {
			if p, err := core.ParseOrigin(o); err != nil || p != o {
				return nil, fmt.Errorf("secret %s: %q is not an origin", name, o)
			}
		}
		s.Origins = sortOrigins(s.Origins)
		c.Secrets[name] = s
	}
	if c.Secrets == nil {
		c.Secrets = map[string]Secret{}
	}
	return c.Secrets, nil
}

// sortOrigins returns origins sorted, each once, in a new slice.
func sortOrigins(origins []string) []string {
	sorted := append([]string{}, origins...)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}

// Names returns the names of the store's secrets, sorted.
func (s *Store) Names() []string {
	names := make([]string, 0, len(s.secrets))
	for name := range s.secrets {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Get returns the secret name.
func (s *Store) Get(name string) (Secret, bool) {
	sec, ok := s.secrets[name]
	if !ok {
		return Secret{}, false
	}
	sec.Origins = slices.Clone(sec.Origins)
	return sec, true
}

// Set sets the value of the secret name, adding it bound to no origin if
// the store does not hold it. The value must be UTF-8 text, which JSON
// keeps as is.
func (s *Store) Set(name, value string) error {
	switch {
	case s.key == nil:
		return ErrClosed
	case !core.IsVarName(name):
		return fmt.Errorf("%q cannot name a secret: a name is letters, digits, _, . and -, and does not start with a digit, . or -", name)
	case !utf8.ValidString(value):
		return fmt.Errorf("the value of %s is not UTF-8 text", name)
	}
	sec, ok := s.secrets[name]
	if !ok {
		sec.Origins = []string{}
	}
	sec.Value = value
	s.secrets[name] = sec
	return nil
}

// Allow lets the secret name go to origins too, each as a person writes
// one (see core.ParseOrigin).
func (s *Store) Allow(name string, origins ...string) error {
	sec, add, err := s.change(name, origins)
	if err != nil {
		return err
	}
	sec.Origins = sortOrigins(append(sec.Origins, add...))
	s.secrets[name] = sec
	return nil
}

// Deny stops the secret name from going to origins, each as a person
// writes one.
func (s *Store) Deny(name string, origins ...string) error {
	sec, drop, err := s.change(name, origins)
	if err != nil {
		return err
	}
	sec.Origins = slices.DeleteFunc(sec.Origins, func(o string) bool { return slices.Contains(drop, o) })
	s.secrets[name] = sec
	return nil
}

// change returns the secret name and origins as core.Origin writes them,
// for Allow and Deny.
func (s *Store) change(name string, origins []string) (Secret, []string, error) {
	if s.key == nil {
		return Secret{}, nil, ErrClosed
	}
	sec, ok := s.secrets[name]
	if !ok {
		return Secret{}, nil, fmt.Errorf("%w: %q", ErrNoSecret, name)
	}
	parsed := make([]string, 0, len(origins))
	for _, o := range origins {
		p, err := core.ParseOrigin(o)
		if err != nil {
			return Secret{}, nil, err
		}
		parsed = append(parsed, p)
	}
	return sec, parsed, nil
}

// Remove removes the secret name, and reports whether the store held it.
func (s *Store) Remove(name string) (bool, error) {
	if s.key == nil {
		return false, ErrClosed
	}
	_, ok := s.secrets[name]
	delete(s.secrets, name)
	return ok, nil
}

// ChangePassword makes password the store's and saves it, with a new salt
// and the parameters a new store gets. If the save fails, the password
// stays what it was.
func (s *Store) ChangePassword(password []byte) error {
	if s.key == nil {
		return ErrClosed
	}
	k, key, err := newKey(password)
	if err != nil {
		return err
	}
	oldKDF, oldKey := s.kdf, s.key
	s.kdf, s.key = k, key
	if err = s.Save(); err != nil {
		clear(key)
		s.kdf, s.key = oldKDF, oldKey
		return err
	}
	clear(oldKey)
	return nil
}

// Save writes the store to its file, sealed with a new nonce.
func (s *Store) Save() error {
	b, err := s.encode()
	if err != nil {
		return err
	}
	return write(s.path, b)
}

// write writes b to the store's file at path as policy.WriteFile does,
// through an os.Root of its directory, which it makes if need be, and
// which only its owner may write.
func write(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = checkDir(root, dir); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return policy.WriteFile(root, filepath.Base(path), b)
}

// encode returns the store's file, sealed with a new nonce.
func (s *Store) encode() ([]byte, error) {
	if s.key == nil {
		return nil, ErrClosed
	}
	plain, err := json.Marshal(contents{s.secrets})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	f := &file{Version: version, KDF: s.kdf, AEAD: aeadName, Names: s.Names(), Origins: map[string][]string{}, Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	for name, sec := range s.secrets {
		f.Origins[name] = sortOrigins(sec.Origins)
	}
	if _, err = rand.Read(f.Nonce); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		return nil, err
	}
	f.Data = aead.Seal(nil, f.Nonce, plain, f.associated())
	b, err := json.MarshalIndent(f, "", "  ")
	switch {
	case err != nil:
		return nil, err
	case len(b) >= maxSize:
		return nil, fmt.Errorf("%s: the store would be larger than %d MiB", s.path, maxSize>>20)
	}
	return append(b, '\n'), nil
}

// Lock lets lock act on the memory of the store's key, which the store
// keeps until Close: a keeper locks it in memory (mlock), so that it is
// never written to swap.
func (s *Store) Lock(lock func([]byte) error) error {
	if s.key == nil {
		return ErrClosed
	}
	return lock(s.key)
}

// Close zeroes the store's key and drops its secrets; their values, which
// are strings, stay in memory until the memory is reused.
func (s *Store) Close() {
	clear(s.key)
	s.key, s.secrets = nil, nil
}
