package store

import (
	"maps"
	"path/filepath"
	"slices"
	"testing"
)

// FuzzOpen checks that a file of any bytes, opened with a fixed password,
// fails, or opens to a store that saves and opens again to the same; and
// that a file never gets past the bounds, lowered here so that each run
// derives its key in microseconds.
func FuzzOpen(f *testing.F) {
	fast(f)
	argon.most = kdf{Time: 2, MemoryKiB: 64, Threads: 2}
	password := []byte("fuzz")
	s, err := Create(filepath.Join(f.TempDir(), "vegtam", FileName), password)
	if err != nil {
		f.Fatal(err)
	}
	defer s.Close()
	empty, err := s.encode()
	if err != nil {
		f.Fatal(err)
	}
	for _, err := range []error{
		s.Set("token", "s3cret"),
		s.Allow("token", "https://api.example.com", "http://127.0.0.1:8080"),
		s.Set("b", "\x00\"\\</script>\u00e9"),
	} {
		if err != nil {
			f.Fatal(err)
		}
	}
	full, err := s.encode()
	if err != nil {
		f.Fatal(err)
	}
	// The seeds that open, open here too.
	for _, b := range [][]byte{empty, full} {
		h, err := parse("seed", b)
		if err == nil {
			_, err = unlock("seed", h, password)
		}
		if err != nil {
			f.Fatal(err)
		}
	}
	for _, seed := range []string{
		string(empty), string(full), "", "{}", "null", `{"vegtam_secrets": 2}`, `{"vegtam_secrets": 1}`,
		`{"vegtam_secrets": 1, "kdf": {"name": "argon2id", "time": 1, "memory_kib": 4294967295, "threads": 1, "salt": "AAAAAAAAAAAAAAAAAAAAAA=="}, "aead": "xchacha20-poly1305", "names": [], "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "data": "AAAAAAAAAAAAAAAAAAAAAA=="}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := parse("fuzz", b)
		if err != nil {
			return
		}
		if k := h.KDF; k.Time > argon.most.Time || k.MemoryKiB > argon.most.MemoryKiB || k.Threads > argon.most.Threads {
			t.Fatalf("parameters past the bounds: %+v", k)
		}
		s, err := unlock("fuzz", h, password)
		if err != nil {
			return
		}
		defer s.Close()
		again, err := s.encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		h2, err := parse("fuzz", again)
		if err != nil {
			t.Fatalf("parse of %q: %v", again, err)
		}
		s2, err := unlock("fuzz", h2, password)
		if err != nil {
			t.Fatalf("unlock of %q: %v", again, err)
		}
		defer s2.Close()
		if !slices.Equal(h2.Names, h.Names) || !maps.EqualFunc(s2.secrets, s.secrets, func(a, b Secret) bool {
			return a.Value == b.Value && slices.Equal(a.Origins, b.Origins)
		}) {
			t.Fatalf("%q opens to %q, saved as %q to %q", b, s.secrets, again, s2.secrets)
		}
	})
}
