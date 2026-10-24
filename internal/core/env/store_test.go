package env

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/httpfile"
)

// fakeStore is a store of secrets that counts the values it hands out.
type fakeStore struct {
	values  map[string]string
	origins map[string][]string
	asked   []string
	err     error // what Value gives, if not nil
}

func (s *fakeStore) Origins() map[string][]string { return s.origins }

func (s *fakeStore) Value(name string) (string, error) {
	s.asked = append(s.asked, name)
	if s.err != nil {
		return "", s.err
	}
	return s.values[name], nil
}

const storedKey = "St0red/k3y+v"

func newFakeStore() *fakeStore {
	return &fakeStore{
		values:  map[string]string{"key": storedKey, "token": "st0re-t0ken"},
		origins: map[string][]string{"key": {"https://api.example.test"}, "token": {"https://other.example.test"}},
	}
}

// storeRequest prepares, with opts, a request of tree that sends {{key}},
// which only the store holds, and {{token}}, which the private file holds.
func storeRequest(t *testing.T, opts Options) (*Vars, *core.Prepared) {
	t.Helper()
	path := tree(t, "GET https://api.example.test/?k={{key}}&t={{token}}\n")
	f, err := httpfile.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewLoader(opts).For(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := v.Prepare(t.Context(), f.Requests[0])
	if err != nil {
		t.Fatal(err)
	}
	return v, p
}

// TestStore checks that a person's run takes a secret from the store when
// the private environment file does not give it, with the store's origins,
// after the file, and says when both hold one; and masks it.
func TestStore(t *testing.T) {
	s := newFakeStore()
	v, p := storeRequest(t, Options{Env: "dev", Store: s})
	key, token := p.URL[1].Secret, p.URL[3].Secret
	if key == nil || token == nil || key.Name != "key" || token.Name != "token" {
		t.Fatalf("URL %+v", p.URL)
	}
	if got, err := v.SecretValue(*key); err != nil || got != storedKey {
		t.Errorf("{{key}} = %q, %v", got, err)
	}
	if got, err := v.SecretValue(*token); err != nil || got != privateToken {
		t.Errorf("{{token}} = %q, %v; want the private file's", got, err)
	}
	if !slices.Equal(v.SecretOrigins(*key), []string{"https://api.example.test"}) || len(v.SecretOrigins(*token)) != 0 {
		t.Errorf("origins %q, %q", v.SecretOrigins(*key), v.SecretOrigins(*token))
	}
	if !slices.Equal(s.asked, []string{"key"}) {
		t.Errorf("the store was asked for %q", s.asked)
	}
	if m := v.loader.Masker(); m.Mask(storedKey) != "***" {
		t.Error("the value of the store is not masked")
	}
	if !slices.ContainsFunc(v.Warnings(), func(w core.Warning) bool {
		return strings.Contains(w.Msg, "{{token}} is in this file and in the store of secrets: the file's value is used")
	}) {
		t.Errorf("warnings %v", v.Warnings())
	}
	// A store that cannot give the value: the error, never another value.
	s.err = errors.New("wrong password")
	v, p = storeRequest(t, Options{Env: "dev", Store: s})
	if _, err := v.SecretValue(*p.URL[1].Secret); err == nil || err.Error() != "wrong password" {
		t.Errorf("{{key}} with a store that fails = %v", err)
	}
}

// TestStoreHeld checks that a run without a person knows the store's
// secrets by name, with their origins, and asks it for no value.
func TestStoreHeld(t *testing.T) {
	s := newFakeStore()
	v, p := storeRequest(t, Options{Env: "dev", Store: s, Held: true})
	key := p.URL[1].Secret
	if key == nil || key.Name != "key" {
		t.Fatalf("URL %+v", p.URL)
	}
	if _, err := v.SecretValue(*key); !errors.Is(err, core.ErrHeld) {
		t.Errorf("{{key}}: %v", err)
	}
	if !slices.Equal(v.SecretOrigins(*key), []string{"https://api.example.test"}) || len(s.asked) != 0 {
		t.Errorf("origins %q; the store was asked for %q", v.SecretOrigins(*key), s.asked)
	}
}

// TestStoreKeeper checks that a keeper reads no private environment file:
// its secrets come from the store alone, whatever a file near the request
// says.
func TestStoreKeeper(t *testing.T) {
	s := newFakeStore()
	v, p := storeRequest(t, Options{Store: s, NoPrivate: true})
	if got, err := v.SecretValue(*p.URL[3].Secret); err != nil || got != "st0re-t0ken" {
		t.Errorf("{{token}} = %q, %v; want the store's", got, err)
	}
	if !slices.Equal(v.SecretOrigins(*p.URL[3].Secret), []string{"https://other.example.test"}) {
		t.Errorf("origins %q", v.SecretOrigins(*p.URL[3].Secret))
	}
	if m := v.loader.Masker(); m.Mask(privateToken) != privateToken {
		t.Error("the keeper read the private file")
	}
}
