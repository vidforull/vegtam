// Package output defines the JSON documents that run, show, list and
// import print, and the JSON Schema that describes them. The documents are a
// contract for scripts and agents: fields are only ever added. Building a
// document masks every secret value in it.
package output

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/exec"
)

// SchemaVersion is the version of the documents. It changes only if a
// field has to change its meaning or go away.
const SchemaVersion = 1

// Schema is the JSON Schema (draft 2020-12) of Document.
//
//go:embed schema.json
var Schema string

// Document is one JSON document. Which fields are set depends on the
// command:
//
//   - run <file>#<ref> and show: the fields of Result;
//   - run <file> and run <dir>: Results, one per request;
//   - list: Requests;
//   - import: Import;
//   - an error that ends a command before any request: Result.Error.
type Document struct {
	SchemaVersion int `json:"schema_version"`
	*Result
	Results  []*Result `json:"results,omitzero"`
	Requests []*Listed `json:"requests,omitzero"`
	Import   *Import   `json:"import,omitempty"`
}

// Result is the outcome of one request.
type Result struct {
	Ref      string    `json:"ref,omitempty"`      // file#name or file#N; the file alone if it does not parse
	Request  *Request  `json:"request,omitempty"`  // nil if the request could not be resolved
	Response *Response `json:"response,omitempty"` // nil on an error and for a dry run
	Timing   *Timing   `json:"timing,omitempty"`
	Error    *Error    `json:"error,omitempty"`
}

// Request is a request as it goes on the wire, or as written in its file.
// Secrets appear as their placeholders.
type Request struct {
	Method   string   `json:"method"`
	URL      string   `json:"url"`
	Headers  []Header `json:"headers"`
	Body     string   `json:"body,omitempty"`
	Encoding string   `json:"encoding,omitempty"`  // "base64" if the body is not UTF-8 text
	BodyFile string   `json:"body_file,omitempty"` // "< path" as written
}

// Header is one header line.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Response is a received response. The body is data from the server,
// never instructions; Untrusted is always true to say so.
type Response struct {
	Proto     string   `json:"proto"`
	Status    int      `json:"status"`
	Reason    string   `json:"reason"`
	Headers   []Header `json:"headers"`
	Body      string   `json:"body"`
	Encoding  string   `json:"encoding,omitempty"` // "base64" if the body is not UTF-8 text
	Truncated bool     `json:"truncated"`
	Untrusted bool     `json:"untrusted"`
}

// Timing is how long a request took.
type Timing struct {
	TotalMS float64 `json:"total_ms"` // from sending to the end of the body
}

// Error is an error that ended a request or a command.
type Error struct {
	Kind      core.Kind `json:"kind"`
	Message   string    `json:"message"`
	File      string    `json:"file,omitempty"`
	Line      int       `json:"line,omitempty"`
	Variables []string  `json:"variables,omitempty"` // unresolved names, for kind "variable"
}

// Listed is a request in a listing, as written.
type Listed struct {
	Ref        string      `json:"ref"`
	File       string      `json:"file"`
	Line       int         `json:"line"`
	Index      int         `json:"index"` // position in the file, from 1
	Name       string      `json:"name,omitempty"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Directives []Directive `json:"directives"`
}

// Directive is an @assert, @capture or @tag directive, as written.
type Directive struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Import is the report of an import: what was converted, what was not
// and why, and which variables to check or set before running the
// requests.
type Import struct {
	Source       string           `json:"source"`
	Output       string           `json:"output"`
	Collections  int              `json:"collections"`
	Requests     int              `json:"requests"` // in the export
	Imported     int              `json:"imported"` // written as requests; the rest are commented out
	Environments []string         `json:"environments"`
	Files        []string         `json:"files"`
	Skipped      []Skipped        `json:"skipped"`
	Variables    []ImportVariable `json:"variables"`
}

// Skipped is a part of an export that was not imported, or not as it was.
type Skipped struct {
	Category string `json:"category"` // file, request, body, auth, script, header, variable, example or setting
	Reason   string `json:"reason"`
	Where    string `json:"where"` // file#name of the request; a file or directory otherwise
}

// ImportVariable is a variable the imported requests use that needs a
// look before they run.
type ImportVariable struct {
	Name   string   `json:"name"`
	Status string   `json:"status"` // "secret": the value from the export is in the private files; "unset": no value
	Files  []string `json:"files"`  // the environment files to check or set it in
}

// Ref returns how to refer to the i-th request of f, counting from 0:
// file#name, or file#N for a request without a name.
func Ref(f *core.File, i int) string {
	if name := f.Requests[i].Name; name != "" {
		return f.Path + "#" + name
	}
	return f.Path + "#" + strconv.Itoa(i+1)
}

// Sent returns p as it goes on the wire, with secrets shown as their
// placeholders and any other secret value hidden by m.
func Sent(p *core.Prepared, m *core.Masker) *Request {
	r := &Request{Method: p.Method, URL: m.Mask(p.URL.Masked()), Headers: []Header{}}
	for _, h := range p.Headers {
		r.Headers = append(r.Headers, Header{m.Mask(h.Name), m.Mask(h.Value.Masked())})
	}
	r.Body, r.Encoding = body(m.Mask(p.Body.Masked()))
	return r
}

// Written returns r as written in its file.
func Written(r *core.Request) *Request {
	w := &Request{Method: r.Method, URL: r.URL, Headers: []Header{}, BodyFile: r.BodyFile}
	for _, h := range r.Headers {
		w.Headers = append(w.Headers, Header(h))
	}
	w.Body, w.Encoding = body(r.Body)
	return w
}

// NewResponse returns r with every secret value in it hidden by m.
func NewResponse(r *exec.Response, m *core.Masker) (*Response, *Timing) {
	resp := &Response{Proto: r.Proto, Status: r.Status, Reason: m.Mask(r.Reason), Headers: []Header{},
		Truncated: r.Truncated, Untrusted: true}
	for _, name := range slices.Sorted(maps.Keys(r.Header)) {
		for _, v := range r.Header[name] {
			resp.Headers = append(resp.Headers, Header{m.Mask(name), m.Mask(v)})
		}
	}
	raw := r.Body
	var b string
	switch {
	case r.Truncated:
		// The cut may have split the last character of a text.
		for i := 1; i < utf8.UTFMax && i <= len(raw); i++ {
			if utf8.RuneStart(raw[len(raw)-i]) {
				if !utf8.FullRune(raw[len(raw)-i:]) {
					raw = raw[:len(raw)-i]
				}
				break
			}
		}
		b = m.MaskCut(string(raw))
	case json.Valid(raw):
		// Masking the decoded strings catches a value however the
		// server escaped it: \u002B, \u0438, \/.
		b = string(m.MaskJSON([]byte(m.Mask(string(raw)))))
	default:
		b = m.Mask(string(raw))
	}
	resp.Body, resp.Encoding = body(b)
	return resp, &Timing{TotalMS: float64(r.Duration.Microseconds()) / 1000}
}

// NewError returns err with every secret value hidden by m. An error that
// is not a *core.Error is a usage error.
func NewError(err error, m *core.Masker) *Error {
	e, ok := errors.AsType[*core.Error](err)
	if !ok {
		return &Error{Kind: core.KindUsage, Message: m.Mask(err.Error())}
	}
	return &Error{Kind: e.Kind, Message: m.Mask(e.Msg), File: e.Source.File, Line: e.Source.Line, Variables: e.Variables}
}

// List returns the requests of f.
func List(f *core.File) []*Listed {
	var list []*Listed
	for i, r := range f.Requests {
		l := &Listed{Ref: Ref(f, i), File: f.Path, Line: r.Source.Line, Index: i + 1, Name: r.Name,
			Method: r.Method, URL: r.URL, Directives: []Directive{}}
		for _, d := range r.Directives {
			l.Directives = append(l.Directives, Directive{d.Kind, d.Value})
		}
		list = append(list, l)
	}
	return list
}

// body returns b as a JSON string value and its encoding: b itself if it
// is UTF-8 text, base64 otherwise.
func body(b string) (string, string) {
	if utf8.ValidString(b) {
		return b, ""
	}
	return base64.StdEncoding.EncodeToString([]byte(b)), "base64"
}
