package cli

import (
	"fmt"
	"slices"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/store"
)

// personStore is the person's store of secrets as a run reads it: what it
// holds and where each may go, from the header of its file, which needs
// no password; and a value, which asks for the password at the terminal
// the first time one is needed, once for the run.
type personStore struct {
	cfg     *Config
	path    string
	origins map[string][]string
	// none, if set, is what Value gives for every value: core.ErrHeld for
	// a run without a person, core.ErrLate for a dry run, which asks for
	// no password.
	none error
	open *store.Store
	err  error // why the store did not open, once it failed
}

// personStore returns the person's store of secrets for a run, with none
// as personStore.none; nil if there is none. A store that cannot be read
// is a warning, and the run goes on without it.
func (c *Config) personStore(none error) env.Store {
	path, err := store.Path()
	if err != nil {
		return nil
	}
	if ok, xerr := store.Exists(path); xerr != nil || !ok {
		return nil
	}
	origins, err := store.Origins(path)
	if err != nil {
		fmt.Fprintf(c.errOut, "vegtam: warning: the store of secrets is not read: %s\n", c.text(err.Error()))
		return nil
	}
	return &personStore{cfg: c, path: path, origins: origins, none: none}
}

func (s *personStore) Origins() map[string][]string { return s.origins }

func (s *personStore) Value(name string) (string, error) {
	switch {
	case s.none != nil:
		return "", s.none
	case s.err != nil:
		return "", s.err
	case s.open == nil:
		if s.err = s.unlock(); s.err != nil {
			return "", s.err
		}
	}
	sec, ok := s.open.Get(name)
	if !ok {
		return "", fmt.Errorf("the store of secrets holds no secret %s", name)
	}
	return sec.Value, nil
}

// unlockOrSkip asks for the store's password before the terminal
// interface starts, which owns the terminal once it runs; an empty answer
// goes without the store, whose values the requests then do not get.
func (s *personStore) unlockOrSkip() {
	pw, err := s.cfg.readSecret("password of the store of secrets (" + s.path + "), or enter to go without it: ")
	defer clear(pw)
	switch {
	case err != nil:
		s.err = core.Errorf(core.KindUsage, core.Source{}, "the store of secrets: %v", err)
	case len(pw) == 0:
		s.err = core.Errorf(core.KindUsage, core.Source{}, "the store of secrets is locked: no password was given when vegtam tui started")
	default:
		if s.err = s.opened(pw); s.err != nil {
			fmt.Fprintf(s.cfg.errOut, "vegtam: warning: %s\n", s.cfg.text(s.err.Error()))
		}
	}
}

// unlock opens the store with its password, typed at the terminal.
func (s *personStore) unlock() error {
	pw, err := s.cfg.readSecret("password of the store of secrets (" + s.path + "): ")
	defer clear(pw)
	if err != nil {
		return core.Errorf(core.KindUsage, core.Source{}, "the store of secrets: %v", err)
	}
	return s.opened(pw)
}

// opened opens the store with pw, and refuses it unless it holds the very
// secrets and origins that its header gave when the run began: the run
// checked where each may go by those, and the header is proved only by
// the password. A file changed in between, while the person typed, is
// refused.
func (s *personStore) opened(pw []byte) error {
	st, err := store.Open(s.path, pw)
	if err != nil {
		return storeError(err)
	}
	names := st.Names()
	same := len(names) == len(s.origins)
	for _, name := range names {
		sec, _ := st.Get(name)
		header, ok := s.origins[name]
		if !ok || !slices.Equal(sec.Origins, header) && (len(sec.Origins) > 0 || len(header) > 0) {
			same = false
			break
		}
	}
	if !same {
		st.Close()
		return core.Errorf(core.KindPolicy, core.Source{}, "the store of secrets at %s changed since this run read where its secrets may go: run it again", s.path)
	}
	s.open = st
	return nil
}

// closeStore closes st, a store personStore returned, if it opened.
func closeStore(st env.Store) {
	if s, ok := st.(*personStore); ok && s.open != nil {
		s.open.Close()
	}
}
