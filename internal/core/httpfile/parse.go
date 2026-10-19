// Package httpfile parses the subset of the .http format that vegtam
// supports; docs/FORMAT.md describes it. Anything outside the subset is an
// error with a file and line, never silently ignored.
package httpfile

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/vidforull/vegtam/internal/core"
)

var methods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
}

// IsMethod reports whether m is a method the parser accepts.
func IsMethod(m string) bool { return methods[m] }

var versions = map[string]bool{"HTTP/1.1": true, "HTTP/2": true, "HTTP/2.0": true}

// directives are the comment directives kept in Request.Directives.
var directives = map[string]bool{"assert": true, "capture": true, "tag": true}

var (
	nameRE     = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	bodyFileRE = regexp.MustCompile(`^<\s+(\S.*)$`)
	handlerRE  = regexp.MustCompile(`^(>|>>|>>!|<>)\s`)
)

type state int

const (
	between state = iota // before a request line: blank lines, comments, directives
	headers              // after the request line, up to the first blank line
	body                 // after that blank line, up to ### or the end of the file
)

type parser struct {
	file   *core.File
	names  map[string]int // request name -> line it was given on
	state  state
	req    *core.Request // the request being read; nil between requests
	at     int           // line where req started
	body   []string
	bodyAt int // line of body[0]
}

// Parse parses src, the contents of the .http file at path. The path ends
// up in each request's Source and in errors.
func Parse(path string, src []byte) (*core.File, error) {
	text := strings.TrimPrefix(string(src), "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	p := &parser{file: &core.File{Path: path}, names: map[string]int{}}
	for i, line := range strings.Split(text, "\n") {
		if err := p.line(i+1, line); err != nil {
			return nil, err
		}
	}
	if err := p.flush(); err != nil {
		return nil, err
	}
	return p.file, nil
}

func (p *parser) errorf(line int, format string, args ...any) error {
	return core.Errorf(core.KindParse, core.Source{File: p.file.Path, Line: line}, format, args...)
}

func (p *parser) line(n int, s string) error {
	if strings.HasPrefix(s, "###") {
		return p.flush()
	}
	t := strings.TrimSpace(s)
	switch p.state {
	case between:
		switch {
		case t == "":
			return nil
		case isComment(t):
			return p.comment(n, t)
		}
		return p.requestLine(n, t)
	case headers:
		switch {
		case t == "":
			p.state = body
			return nil
		case isComment(t):
			return p.comment(n, t)
		}
		return p.header(n, s)
	}
	if len(p.body) == 0 {
		p.bodyAt = n
	}
	p.body = append(p.body, s)
	return nil
}

func isComment(t string) bool { return strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") }

// directive returns the "@kind value" text of a comment, if it is one.
func directive(t string) (string, bool) {
	if c, ok := strings.CutPrefix(t, "//"); ok {
		t = c
	} else {
		t = strings.TrimPrefix(t, "#")
	}
	return strings.CutPrefix(strings.TrimSpace(t), "@")
}

// cur returns the request being read, starting one at line n if needed.
func (p *parser) cur(n int) *core.Request {
	if p.req == nil {
		p.req, p.at = &core.Request{}, n
	}
	return p.req
}

func (p *parser) comment(n int, t string) error {
	d, ok := directive(t)
	if !ok {
		return nil
	}
	kind, value := splitWord(d)
	switch {
	case kind == "name":
		return p.setName(n, value)
	case !directives[kind]:
		return p.errorf(n, "unknown directive @%s (supported: @name, @assert, @capture, @tag)", kind)
	case value == "":
		return p.errorf(n, "@%s needs a value", kind)
	}
	r := p.cur(n)
	r.Directives = append(r.Directives, core.Directive{Kind: kind, Value: value, Line: n})
	return nil
}

func (p *parser) setName(n int, name string) error {
	switch {
	case !nameRE.MatchString(name):
		return p.errorf(n, "invalid request name %q: use letters, digits, '.', '_' and '-'", name)
	case isNumber(name):
		return p.errorf(n, "request name %q is a number; numbers refer to requests by position", name)
	case p.req != nil && p.req.Name != "":
		return p.errorf(n, "request already named %q", p.req.Name)
	}
	if first, dup := p.names[name]; dup {
		return p.errorf(n, "duplicate request name %q (first on line %d)", name, first)
	}
	p.names[name] = n
	p.cur(n).Name = name
	return nil
}

func (p *parser) requestLine(n int, t string) error {
	method, rest := splitWord(t)
	switch {
	case strings.HasPrefix(t, "@"):
		return p.errorf(n, "file variables (%q) are not supported; use an environment file", clip(t))
	case !methods[method]:
		return p.errorf(n, "expected a request line \"METHOD URL\", got %q", clip(t))
	case rest == "":
		return p.errorf(n, "%s needs a URL", method)
	}
	r := p.cur(n)
	r.Method, r.Source = method, core.Source{File: p.file.Path, Line: n}
	if i := strings.LastIndexAny(rest, " \t"); i >= 0 && strings.HasPrefix(rest[i+1:], "HTTP/") {
		if r.Version = rest[i+1:]; !versions[r.Version] {
			return p.errorf(n, "unsupported HTTP version %q (supported: HTTP/1.1, HTTP/2)", r.Version)
		}
		rest = strings.TrimSpace(rest[:i])
	}
	if _, err := core.ParseTemplate(rest); err != nil {
		return p.errorf(n, "URL: %v", err)
	}
	r.URL = rest
	p.state = headers
	return nil
}

func (p *parser) header(n int, s string) error {
	name, value, ok := strings.Cut(s, ":")
	if !ok || !isToken(name) {
		return p.errorf(n, "expected a header \"Name: value\", got %q (a blank line must separate the body)", clip(s))
	}
	value = strings.TrimSpace(value)
	if _, err := core.ParseTemplate(value); err != nil {
		return p.errorf(n, "header %s: %v", name, err)
	}
	p.req.Headers = append(p.req.Headers, core.Header{Name: name, Value: value})
	return nil
}

// flush ends the request being read, if any.
func (p *parser) flush() error {
	r, lines, at := p.req, p.body, p.bodyAt
	p.req, p.body, p.state = nil, nil, between
	if r == nil {
		return nil
	}
	if r.Method == "" {
		return p.errorf(p.at, "directive is not followed by a request line")
	}
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines, at = lines[1:], at+1
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > 0 {
		if m := bodyFileRE.FindStringSubmatch(lines[0]); m != nil {
			if len(lines) > 1 {
				return p.errorf(at+1, "a body file (< path) must be the whole body")
			}
			r.BodyFile = strings.TrimSpace(m[1])
		} else if err := p.checkBody(lines, at); err != nil {
			return err
		} else {
			r.Body = strings.Join(lines, "\n")
		}
	}
	p.file.Requests = append(p.file.Requests, r)
	return nil
}

// checkBody rejects body lines that are likely meant as something else.
func (p *parser) checkBody(lines []string, at int) error {
	for i, l := range lines {
		n, t := at+i, strings.TrimSpace(l)
		method, rest := splitWord(t)
		_, isDirective := directive(t)
		switch {
		case strings.HasPrefix(l, "<@"):
			return p.errorf(n, "body files with variables (<@) are not supported yet")
		case bodyFileRE.MatchString(l):
			return p.errorf(n, "a body file (< path) inside a body, as in multipart, is not supported yet")
		case handlerRE.MatchString(l):
			return p.errorf(n, "response handlers and redirects (%q) are not supported", clip(t))
		case isComment(t) && isDirective,
			methods[method] && (strings.Contains(rest, "://") || strings.HasPrefix(rest, "{{")):
			return p.errorf(n, "%q looks like the start of another request; separate requests with ###", clip(t))
		}
		if _, err := core.ParseTemplate(l); err != nil {
			return p.errorf(n, "body: %v", err)
		}
	}
	return nil
}

// isNumber reports whether name would be taken for a position, as
// core.File.Find reads it.
func isNumber(name string) bool {
	_, err := strconv.Atoi(name)
	return err == nil
}

// splitWord splits s at its first run of spaces or tabs.
func splitWord(s string) (word, rest string) {
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i:])
}

// isToken reports whether s is a valid header name (an RFC 9110 token).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
