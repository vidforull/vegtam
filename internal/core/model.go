package core

import (
	"fmt"
	"slices"
	"strconv"
)

// Collection is the set of .http files a command works on.
type Collection struct {
	Files []*File
}

// File is one parsed .http file.
type File struct {
	Path     string
	Requests []*Request
}

// Find returns the request named ref or, when ref is a number, the
// ref-th request of the file, counting from 1.
func (f *File) Find(ref string) (*Request, bool) {
	if n, err := strconv.Atoi(ref); err == nil {
		if n < 1 || n > len(f.Requests) {
			return nil, false
		}
		return f.Requests[n-1], true
	}
	for _, r := range f.Requests {
		if r.Name == ref {
			return r, true
		}
	}
	return nil, false
}

// Request is one request as written in a .http file. URL, header values
// and Body keep their {{...}} placeholders; package env resolves them.
type Request struct {
	Name       string // from "# @name"; empty when the request has none
	Method     string
	URL        string
	Version    string // HTTP version written after the URL, if any
	Headers    []Header
	Body       string // inline body
	BodyFile   string // path from a "< path" body, as written
	Directives []Directive
	Source     Source // the request line
}

// Header is one "Name: value" line.
type Header struct {
	Name  string
	Value string
}

// Directive is an "# @assert", "# @capture", "# @tag" or "# @no-log"
// comment, kept as written for the stages that act on it.
type Directive struct {
	Kind  string // "assert", "capture", "tag" or NoLog
	Value string // "" for NoLog
	Line  int
}

// NoLog is the kind of the "# @no-log" directive, which JetBrains, kulala
// and httpyac know too: the history of runs does not keep the request.
const NoLog = "no-log"

// NoLog reports whether r has an "# @no-log" directive.
func (r *Request) NoLog() bool {
	return slices.ContainsFunc(r.Directives, func(d Directive) bool { return d.Kind == NoLog })
}

// Source locates a line in a .http file.
type Source struct {
	File string
	Line int
}

func (s Source) String() string {
	if s.Line == 0 {
		return s.File
	}
	return fmt.Sprintf("%s:%d", s.File, s.Line)
}
