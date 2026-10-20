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
	Version    string // HTTP11, HTTP2 or HTTP2PriorKnowledge, if written after the URL
	Headers    []Header
	Body       string // inline body
	BodyFile   string // path from a "< path" body, as written
	Directives []Directive
	Source     Source    // the request line
	Warnings   []Warning // of the parser: the directives of other clients it ignored
}

// Header is one "Name: value" line.
type Header struct {
	Name  string
	Value string
}

// Directive is an "# @assert", "# @capture", "# @tag", "# @no-log",
// "# @no-cookie-jar" or time limit comment, kept as written for the stages
// that act on it.
type Directive struct {
	Kind  string // "assert", "capture", "tag", NoLog, NoCookieJar, Timeout, ConnectionTimeout or MaxTime
	Value string // "" for NoLog and NoCookieJar
	Line  int
}

// The HTTP versions a request line or a flag may ask for.
const (
	HTTP11              = "HTTP/1.1"
	HTTP2               = "HTTP/2" // over TLS, as ALPN agrees on it
	HTTP2PriorKnowledge = "HTTP/2 (Prior Knowledge)"
)

// NoLog is the kind of the "# @no-log" directive, which JetBrains, kulala
// and httpyac know too: the history of runs does not keep the request.
const NoLog = "no-log"

// NoLog reports whether r has an "# @no-log" directive.
func (r *Request) NoLog() bool {
	return slices.ContainsFunc(r.Directives, func(d Directive) bool { return d.Kind == NoLog })
}

// NoCookieJar is the kind of the "# @no-cookie-jar" directive, which
// JetBrains, REST Client, httpyac and kulala know too: the cookie jar of
// the run is neither read nor written for the request. JetBrains only
// does not write it.
const NoCookieJar = "no-cookie-jar"

// NoCookieJar reports whether r has an "# @no-cookie-jar" directive.
func (r *Request) NoCookieJar() bool {
	return slices.ContainsFunc(r.Directives, func(d Directive) bool { return d.Kind == NoCookieJar })
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
