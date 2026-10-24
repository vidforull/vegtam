package session

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/vidforull/vegtam/internal/core"
)

// Confirm says which of the requests that need a confirmation a session
// sends. A request needs one when it has an @note, whose author asks for
// a person, and when its method is not GET, HEAD or OPTIONS, and so may
// change something on the server, unless Mutations is set. The zero value
// is the strict one: such a request is not sent, and none is confirmed,
// so that a caller that forgets to set it sends nothing it should not.
type Confirm struct {
	// Mutations sends a request whose method may change something without
	// a confirmation, unless it has an @note: a person at a terminal runs
	// it, or the operator's policy lets a run without one do so.
	Mutations bool
	// Person is set when a person at a terminal runs the session. A
	// request that would send a secret to an origin the secret is not
	// bound to then needs their confirmation; without a person, nothing
	// confirms it, and it is an error of kind policy: whoever wrote the
	// file leads a program, and a confirmation would come from them too.
	Person   bool
	All      bool     // every request is confirmed
	Requests []string // the requests confirmed, each as Key names it
}

// safe are the methods that need no confirmation. Any other does, one
// that vegtam does not know too.
var safe = []string{"GET", "HEAD", "OPTIONS"}

// Needs returns why r needs a confirmation before it is sent, given c:
// core.ReasonNote, core.ReasonMethod, or "" for none.
func (c Confirm) Needs(r *core.Request) string {
	if _, ok := r.Note(); ok {
		return core.ReasonNote
	}
	if !c.Mutations && !slices.Contains(safe, r.Method) {
		return core.ReasonMethod
	}
	return ""
}

// Key returns how Confirm.Requests names the i-th request of the file at
// path, counting from 0: the file as an absolute, clean path, "#" and
// the position of the request, from 1. However a file is named, ./api.http
// or api.http, its requests have one key each.
func Key(path string, i int) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return abs + "#" + strconv.Itoa(i+1), nil
}

// ConfirmOnce confirms the i-th request of f for the next time it is
// prepared, as a person who has just been asked: the terminal interface
// asks before each request that needs it.
func (s *Session) ConfirmOnce(f *core.File, i int) {
	if key, err := Key(f.Path, i); err == nil {
		s.once[key] = true
	}
}

// confirmed reports whether the i-th request of f has a confirmation, of
// the run or of ConfirmOnce, which is used up; and whether the
// confirmation names it: one of --confirm=<ref> or of ConfirmOnce. Only
// such a one lets a secret go where it is not bound: --confirm alone is
// given for a run, before its requests are seen, whose files someone
// else may have named, with a comma that --confirm=<ref> cannot hold.
func (s *Session) confirmed(f *core.File, i int) (confirmed, named bool) {
	c := s.opts.Confirm
	key, err := Key(f.Path, i)
	once := err == nil && s.once[key]
	delete(s.once, key)
	named = once || err == nil && slices.Contains(c.Requests, key)
	return named || c.All, named
}

// ask returns what the i-th request of f, whose ref is ref, needs before
// it is sent, or nil if it needs no confirmation or confirmed says it has
// one.
func (s *Session) ask(f *core.File, i int, ref string, confirmed bool) *core.Confirmation {
	r := f.Requests[i]
	reason := s.opts.Confirm.Needs(r)
	if reason == "" || confirmed {
		return nil
	}
	return confirmation(r, ref, reason)
}

// confirmation returns what r, whose ref is ref, asks for, for reason.
func confirmation(r *core.Request, ref, reason string) *core.Confirmation {
	// The ref as the run names it; --confirm splits its value at commas.
	flag := "--confirm=" + ref
	if strings.Contains(ref, ",") {
		flag = "--confirm"
	}
	ask := &core.Confirmation{Reason: reason, Method: r.Method, URL: r.URL, Flag: flag}
	if note, ok := r.Note(); ok {
		ask.Note = &note
	}
	return ask
}

// refused returns the error of r, which asks for c and has not got it.
// The text of an @note comes whole, after the colon: it is masked and
// made fit for a terminal as the message is, and quoting it would hide
// a secret value in it from the masker.
func refused(r *core.Request, c *core.Confirmation) error {
	var e *core.Error
	switch {
	case c.Reason != core.ReasonNote:
		e = core.Errorf(core.KindConfirm, r.Source, "%s %s is not sent without a confirmation, and no person is at a terminal: %s sends it",
			c.Method, c.URL, c.Flag)
	case *c.Note == "":
		e = core.Errorf(core.KindConfirm, r.Source, "%s %s is not sent without a confirmation, which its @note asks for: %s sends it",
			c.Method, c.URL, c.Flag)
	default:
		e = core.Errorf(core.KindConfirm, r.Source, "%s %s is not sent without a confirmation, which its @note asks for (%s sends it): %s",
			c.Method, c.URL, c.Flag, *c.Note)
	}
	e.Confirm = c
	return e
}

// unbound returns the error of the request of j, which would send the
// secrets refused to an origin they are not bound to: with a person at a
// terminal, of kind confirm, which --confirm=<ref> gives; without one, of
// kind policy, which nothing but binding them lifts.
func (s *Session) unbound(j *Job, refused []core.Bound) *core.Error {
	r := j.Request
	what := r.Method + " " + r.URL + " is not sent"
	if !s.opts.Confirm.Person {
		return core.SecretError(core.KindPolicy, r.Source, what, refused)
	}
	c := confirmation(r, j.Ref, core.ReasonSecret)
	c.Secret = &refused[0]
	e := core.SecretError(core.KindConfirm, r.Source, what+" without a confirmation", refused)
	if strings.Contains(j.Ref, ",") {
		// --confirm=<ref> would split the ref, and --confirm alone does not do.
		c.Flag = ""
		e.Msg += "; a request in a file whose name holds a comma cannot be named by --confirm=<ref>: bind the secret, or send it from vegtam tui"
	} else {
		e.Msg += "; or " + c.Flag + " sends it this once"
	}
	e.Confirm = c
	return e
}
