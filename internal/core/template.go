package core

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Ref is one {{...}} placeholder: a variable such as {{host}}, or a
// dynamic variable such as {{$env TOKEN}}.
type Ref struct {
	Func string // "" for a variable; otherwise the dynamic variable, "$" included
	Name string // the variable name, or the argument of the dynamic variable
}

// String returns the placeholder in canonical form, braces included.
func (r Ref) String() string {
	switch {
	case r.Func == "":
		return "{{" + r.Name + "}}"
	case r.Name == "":
		return "{{" + r.Func + "}}"
	}
	return "{{" + r.Func + " " + r.Name + "}}"
}

// Piece is a run of literal text or one placeholder.
type Piece struct {
	Text string
	Ref  *Ref
}

var (
	varName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	funcName = regexp.MustCompile(`^\$[A-Za-z][A-Za-z0-9_.]*$`)
)

// IsVarName reports whether s may name a variable, as in {{s}}.
func IsVarName(s string) bool { return varName.MatchString(s) }

// ParseTemplate splits s into literal text and placeholders. Whitespace
// inside the braces is ignored. A "{{" without a matching "}}" and a
// malformed placeholder are errors.
func ParseTemplate(s string) ([]Piece, error) {
	var pieces []Piece
	for s != "" {
		i := strings.Index(s, "{{")
		if i < 0 {
			return append(pieces, Piece{Text: s}), nil
		}
		if i > 0 {
			pieces = append(pieces, Piece{Text: s[:i]})
		}
		s = s[i:]
		j := strings.Index(s, "}}")
		if j < 0 {
			return nil, fmt.Errorf("unclosed placeholder %q", clip(s))
		}
		ref, err := parseRef(s[2:j])
		if err != nil {
			return nil, fmt.Errorf("invalid placeholder %q", s[:j+2])
		}
		pieces = append(pieces, Piece{Ref: ref})
		s = s[j+2:]
	}
	return pieces, nil
}

func parseRef(s string) (*Ref, error) {
	f := strings.Fields(s)
	switch {
	case len(f) == 1 && varName.MatchString(f[0]):
		return &Ref{Name: f[0]}, nil
	case len(f) == 1 && funcName.MatchString(f[0]):
		return &Ref{Func: f[0]}, nil
	case len(f) == 2 && funcName.MatchString(f[0]):
		return &Ref{Func: f[0], Name: f[1]}, nil
	}
	return nil, errors.New("malformed placeholder")
}

// clip shortens s for an error message.
func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
