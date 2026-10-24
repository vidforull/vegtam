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
	Name       string      `json:"name,omitempty"` // from "# @name"; empty when the request has none
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Version    string      `json:"version,omitempty"` // HTTP11, HTTP2 or HTTP2PriorKnowledge, if written after the URL
	Headers    []Header    `json:"headers,omitempty"`
	Body       string      `json:"body,omitempty"`      // inline body
	BodyFile   string      `json:"body_file,omitempty"` // path from a "< path" body, as written
	Directives []Directive `json:"directives,omitempty"`
	Source     Source      `json:"source"`             // the request line
	Warnings   []Warning   `json:"warnings,omitempty"` // of the parser: the directives of other clients it ignored
}

// Header is one "Name: value" line.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Directive is an "# @assert", "# @capture", "# @tag", "# @no-log",
// "# @no-cookie-jar", "# @note" or time limit comment, kept as written for
// the stages that act on it.
type Directive struct {
	Kind  string `json:"kind"`            // "assert", "capture", "tag", NoLog, NoCookieJar, Note, Timeout, ConnectionTimeout or MaxTime
	Value string `json:"value,omitempty"` // "" for NoLog and NoCookieJar, and may be for Note
	Line  int    `json:"line,omitempty"`
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

// Note is the kind of the "# @note" directive, as httpyac has it: the
// request is not sent without a confirmation, and the text after the
// directive, which may be empty, says why.
const Note = "note"

// Note returns the text of the "# @note" directive of r, and whether it
// has one.
func (r *Request) Note() (string, bool) {
	i := slices.IndexFunc(r.Directives, func(d Directive) bool { return d.Kind == Note })
	if i < 0 {
		return "", false
	}
	return r.Directives[i].Value, true
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
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
}

func (s Source) String() string {
	if s.Line == 0 {
		return s.File
	}
	return fmt.Sprintf("%s:%d", s.File, s.Line)
}
